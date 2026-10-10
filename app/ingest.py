"""Upload validation + ingestion orchestration. Never claims success for content it could not parse."""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone

from .config import Settings
from .parsers import ParseOptions, parse_text, SUPPORTED_FORMATS
from .storage import Store, now_iso

ALLOWED_EXT = {".log", ".txt", ".json", ".jsonl", ".ndjson", ".xml", ".out", ".syslog", ""}


class IngestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def safe_name(name: str | None) -> str:
    base = os.path.basename((name or "upload").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._\- ]", "_", base)[:120]
    return base or "upload"


def decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if b"\x00" in data[:4096]:
        raise IngestError(415, "File looks binary (NUL bytes). Binary .evtx is not supported — export the log to XML or JSON.")
    return data.decode("utf-8", errors="replace")


def ingest_bytes(store: Store, settings: Settings, data: bytes, filename: str | None, dataset_id: str | None,
                 dataset_name: str | None, default_year: int | None, actor: str) -> dict:
    name = safe_name(filename)
    ext = os.path.splitext(name)[1].lower()
    if ext == ".evtx":
        raise IngestError(415, "Binary .evtx files are not supported. Export the log as XML or JSON first.")
    if ext not in ALLOWED_EXT:
        raise IngestError(415, f"File type '{ext}' is not supported. Allowed: .log .txt .json .jsonl .ndjson .xml")
    if not data:
        raise IngestError(400, "The uploaded file is empty.")
    if len(data) > settings.max_upload_bytes:
        raise IngestError(413, f"File exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB upload limit.")
    text = decode(data)
    sha = hashlib.sha256(data).hexdigest()
    year = default_year or datetime.now(timezone.utc).year
    if not 1990 <= year <= 2100:
        raise IngestError(400, "default_year out of range")
    ingested_at = now_iso()
    res = parse_text(text, ParseOptions(source_key=sha, filename=name, default_year=year,
                                        max_events=settings.max_events_per_upload, max_line_bytes=settings.max_line_bytes,
                                        max_raw_chars=settings.max_raw_chars, ingested_at=ingested_at))
    if res.format == "unsupported" or not res.events:
        # nothing usable: do not create or modify a dataset
        summary = _summary(res, 0, 0, name, sha)
        summary["status"] = "FAILED"
        summary["message"] = res.note or "No records could be parsed; nothing was ingested."
        return {"dataset_id": None, "summary": summary}
    if dataset_id:
        if not store.get_dataset(dataset_id):
            raise IngestError(404, "Dataset not found")
    else:
        dataset_id = "ds-" + uuid.uuid4().hex[:10]
        store.create_dataset(dataset_id, (dataset_name or name)[:120], "FILE_UPLOAD")
    inserted, dups = store.insert_events(dataset_id, res.events)
    summary = _summary(res, inserted, dups, name, sha)
    store.add_upload(dataset_id, name, sha, len(data), res.format, summary)
    store.audit(actor, "ingest", dataset_id, {"file": name, "sha256": sha, "accepted": summary["accepted"],
                                              "rejected": summary["rejected"], "unsupported": summary["unsupported"]})
    return {"dataset_id": dataset_id, "summary": summary}


def _summary(res, inserted: int, dups: int, name: str, sha: str) -> dict:
    n_rej, n_uns = len(res.rejected), len(res.unsupported)
    accepted = len(res.events)
    unclassified = sum(1 for e in res.events if e.get("action") == "unclassified")
    no_ts = sum(1 for e in res.events if e.get("timestamp") is None)
    if accepted and not n_rej and not n_uns and not res.truncated:
        status = "SUCCESS"
    elif accepted:
        status = "PARTIAL"
    else:
        status = "FAILED"
    return {
        "status": status, "filename": name, "sha256": sha, "detected_format": res.format,
        "format_description": SUPPORTED_FORMATS.get(res.format),
        "records_total": res.records_total, "accepted": accepted, "new_events_stored": inserted,
        "duplicates_skipped": dups, "rejected": n_rej, "unsupported": n_uns,
        "accepted_but_unclassified": unclassified, "accepted_without_timestamp": no_ts,
        "truncated": res.truncated,
        "action_breakdown": dict(Counter(e.get("action") for e in res.events).most_common(15)),
        "rejected_samples": res.rejected[:20], "unsupported_samples": res.unsupported[:20],
        "caveats": _caveats(res),
    }


def _caveats(res) -> list[str]:
    c = []
    if any(any(n.startswith("timestamp_year_assumed") for n in e["notes"]) for e in res.events[:200]):
        c.append("Syslog lines carry no year; the year was assumed from the 'default_year' setting. Verify it.")
    if any("timestamp_timezone_assumed_utc" in e["notes"] for e in res.events[:200]):
        c.append("Some timestamps had no timezone and were assumed to be UTC.")
    if res.truncated:
        c.append("The file exceeded the per-upload event cap; later records were NOT ingested.")
    return c
