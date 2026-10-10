from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import syslog as sl
from .common import event_id
from .jsonlogs import is_wazuh, normalize_record
from .windows import parse_windows_xml_doc

SUPPORTED_FORMATS = {
    "syslog": "Linux syslog / auth.log / secure (RFC3164, ISO-timestamp rsyslog, RFC5424)",
    "jsonl": "JSON Lines / NDJSON (generic, ECS-style aliases, Wazuh alerts, Windows JSON)",
    "json": "JSON array/object (generic, Wazuh alert export, Elasticsearch/OpenSearch hits)",
    "windows_xml": "Windows Event Log XML export (Security channel event IDs 4624/4625/4648/4672/4688/4697/4698/4720/4728/4732/4756/7045/1102 classified)",
}


@dataclass
class ParseOptions:
    source_key: str                       # content hash; used for stable event ids
    filename: str = "upload"
    default_year: int = field(default_factory=lambda: datetime.now(timezone.utc).year)
    max_events: int = 200_000
    max_line_bytes: int = 64 * 1024
    max_raw_chars: int = 8192
    ingested_at: str = ""


@dataclass
class ParseResult:
    format: str
    records_total: int = 0
    events: list = field(default_factory=list)
    rejected: list = field(default_factory=list)       # malformed records
    unsupported: list = field(default_factory=list)    # well-formed but not normalizable
    truncated: bool = False
    note: str | None = None

    def reject(self, where, reason, excerpt=""):
        self.rejected.append({"position": where, "reason": reason, "excerpt": str(excerpt)[:200]})

    def unsupp(self, where, reason, excerpt=""):
        self.unsupported.append({"position": where, "reason": reason, "excerpt": str(excerpt)[:200]})


def detect_format(text: str) -> str | None:
    t = text.lstrip("\ufeff").lstrip()
    if not t:
        return None
    if t.startswith("<?xml") or re.match(r"<Events?[\s>]", t):
        return "windows_xml"
    if t[0] in "[{":
        try:
            json.loads(t)
            return "json"
        except ValueError:
            pass
        lines = [l for l in t.splitlines() if l.strip()][:50]
        ok = 0
        for l in lines:
            try:
                if isinstance(json.loads(l), dict):
                    ok += 1
            except ValueError:
                pass
        if lines and ok / len(lines) >= 0.5:
            return "jsonl"
        return None
    lines = [l for l in t.splitlines() if l.strip()][:50]
    hits = sum(1 for l in lines if sl.match_line(l)[1] is not None)
    if lines and hits / len(lines) >= 0.5:
        return "syslog"
    return None


def _finish(e: dict, opts: ParseOptions, pos, raw: str):
    e["event_id"] = e.get("event_id") or event_id(opts.source_key, pos)
    e["raw"] = raw[:opts.max_raw_chars]
    e["source_file"] = opts.filename
    e["line_no"] = pos if isinstance(pos, int) else None
    e["ingested_at"] = opts.ingested_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    if e["extra"].get("indexer_id"):
        e["event_id"] = event_id("wazuh-indexer", e["extra"]["indexer_id"])
    return e


def parse_text(text: str, opts: ParseOptions, fmt: str | None = None) -> ParseResult:
    text = text.lstrip("\ufeff")
    fmt = fmt or detect_format(text)
    if fmt is None:
        return ParseResult(format="unsupported", note="Could not recognise the content as any supported log format. "
                           "Nothing was ingested.")
    res = ParseResult(format=fmt)
    if fmt == "syslog":
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            res.records_total += 1
            if len(line.encode("utf-8", "ignore")) > opts.max_line_bytes:
                res.reject(n, "line exceeds maximum length", line[:100]); continue
            e = sl.parse_line(line, opts.default_year)
            if e is None:
                res.reject(n, "line does not match any supported syslog layout", line); continue
            if len(res.events) >= opts.max_events:
                res.truncated = True; break
            res.events.append(_finish(e, opts, n, line))
    elif fmt in ("jsonl", "json"):
        records: list[tuple[object, object, str]] = []
        if fmt == "jsonl":
            for n, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                if len(line.encode("utf-8", "ignore")) > opts.max_line_bytes:
                    res.records_total += 1; res.reject(n, "line exceeds maximum length", line[:100]); continue
                try:
                    records.append((n, json.loads(line), line))
                except ValueError as exc:
                    res.records_total += 1; res.reject(n, f"invalid JSON: {exc}", line)
        else:
            doc = json.loads(text)
            items = doc
            if isinstance(doc, dict):
                if isinstance(doc.get("hits"), dict) and isinstance(doc["hits"].get("hits"), list):
                    items = doc["hits"]["hits"]
                else:
                    items = next((doc[k] for k in ("events", "alerts", "records", "logs", "data") if isinstance(doc.get(k), list)), [doc])
            for i, it in enumerate(items, 1):
                records.append((i, it, json.dumps(it, default=str)))
        for pos, rec, raw in records:
            res.records_total += 1
            if not isinstance(rec, dict):
                res.reject(pos, "record is not a JSON object", raw); continue
            try:
                e, why = normalize_record(rec)
            except Exception as exc:  # noqa: BLE001
                res.reject(pos, f"normalisation error: {type(exc).__name__}", raw); continue
            if e is None:
                res.unsupp(pos, why or "unsupported record", raw); continue
            if len(res.events) >= opts.max_events:
                res.truncated = True; break
            res.events.append(_finish(e, opts, pos, raw))
    elif fmt == "windows_xml":
        try:
            for pos, item, eid in parse_windows_xml_doc(text):
                res.records_total += 1
                if isinstance(item, Exception):
                    res.reject(pos, f"invalid event: {item}"); continue
                if len(res.events) >= opts.max_events:
                    res.truncated = True; break
                res.events.append(_finish(item, opts, pos, f"Windows Event {eid} (record {pos})"))
        except Exception as exc:  # noqa: BLE001 - whole-document failure
            res.reject(0, f"XML could not be parsed: {exc}")
            res.records_total = max(res.records_total, 1)
    return res
