"""Rule-based analysis pipeline: events -> findings -> cases -> investigation records (no AI involved here)."""
from __future__ import annotations

import hashlib

from .config import Settings
from .correlation import correlate
from .detection import DetectionConfig, run_detections
from .ioc import extract_iocs
from .storage import Store, now_iso

MAX_TIMELINE = 400


def rec_id(inv_id: str, action: str) -> str:
    return "REC-" + hashlib.sha256(f"{inv_id}|{action}".encode()).hexdigest()[:10]


def build_timeline(findings: list[dict], events: dict[str, dict]) -> tuple[list[dict], bool]:
    stage_of = {}
    for f in findings:
        for eid in f["evidence_ids"]:
            stage_of.setdefault(eid, (f["stage"], f["finding_id"]))
    rows = []
    for eid, (stage, fid) in stage_of.items():
        e = events.get(eid)
        if e:
            rows.append({"timestamp": e.get("timestamp"), "event_id": eid, "stage": stage or "context", "finding_id": fid,
                         "host": e.get("host"), "user": e.get("username"), "src_ip": e.get("src_ip"),
                         "action": e.get("action"), "summary": (e.get("message") or "")[:300]})
    rows.sort(key=lambda r: (r["timestamp"] is None, r["timestamp"] or "", r["event_id"]))
    return rows[:MAX_TIMELINE], len(rows) > MAX_TIMELINE


def analyze_dataset(store: Store, settings: Settings, dataset_id: str, actor: str = "system") -> list[dict]:
    ds = store.get_dataset(dataset_id)
    if not ds:
        raise KeyError(dataset_id)
    cfg = DetectionConfig.load(settings.detection_config)
    events = store.all_events(dataset_id)
    by_id = {e["event_id"]: e for e in events}
    findings = run_detections(events, cfg)
    cases = correlate(findings, cfg)
    fmap = {f["finding_id"]: f for f in findings}
    out = []
    keep_ids = set()
    for c in cases:
        fs = [fmap[i] for i in c["finding_ids"]]
        inv_id = f"INV-{dataset_id[3:]}-{c['case_key'][:6]}".upper()
        keep_ids.add(inv_id)
        timeline, tl_trunc = build_timeline(fs, by_id)
        ev_ids = sorted({i for f in fs for i in f["evidence_ids"]})
        iocs = extract_iocs([by_id[i] for i in ev_ids if i in by_id])
        mitre = {}
        for f in fs:
            for m in f["mitre"]:
                d = mitre.setdefault(m["technique_id"], {**m, "evidence_ids": [], "finding_ids": [], "bases": []})
                d["evidence_ids"] = sorted(set(d["evidence_ids"]) | set(m["evidence_ids"]))[:200]
                d["finding_ids"].append(f["finding_id"]); d["bases"].append(m["basis"])
                if m["status"] == "OBSERVED":
                    d["status"] = "OBSERVED"
        recs, seen = [], set()
        for f in fs:
            for r in f["recommended_steps"]:
                if r["action"] in seen:
                    continue
                seen.add(r["action"])
                recs.append({**r, "recommendation_id": rec_id(inv_id, r["action"]), "origin": "RULE",
                             "finding_ids": [f["finding_id"]]})
        prev = store.get_investigation(inv_id)
        inv = {
            "id": inv_id, "dataset_id": dataset_id, "title": c["title"], "case": c, "findings": fs,
            "severity": c["severity"], "severity_basis": c["severity_basis"], "timeline": timeline,
            "timeline_truncated": tl_trunc, "iocs": iocs, "mitre": list(mitre.values()), "recommendations": recs,
            "source": {"kind": ds["source_kind"], "dataset_name": ds["name"], "uploads": [
                {k: u[k] for k in ("filename", "sha256", "detected_format", "ingested_at")} | {"summary": u["summary"]}
                for u in ds["uploads"]], "live_telemetry": False if ds["source_kind"] == "FILE_UPLOAD" else None},
            "scope": {"dataset_events": ds["event_count"], "evidence_events": len(ev_ids),
                      "window": [c["first_seen"], c["last_seen"]]},
            "detection_config": cfg.as_dict(),
            "analysis_mode": "RULE_BASED",
            "agent": prev["agent"] if prev and prev.get("agent") and prev["case"]["finding_ids"] == c["finding_ids"]
            else {"status": "NOT_RUN"},
            "status": "OPEN",
        }
        store.save_investigation(inv)
        out.append(inv)
    for old in store.list_investigations(dataset_id):   # drop stale cases no longer produced by current data
        if old["id"] not in keep_ids:
            store.conn.execute("DELETE FROM investigations WHERE id=?", (old["id"],))
            store.conn.commit()
    store.audit(actor, "analyze", dataset_id, {"findings": len(findings), "cases": len(cases)})
    return out
