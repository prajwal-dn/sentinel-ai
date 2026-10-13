"""Generic JSON/JSONL events (ECS-ish field aliases), Wazuh alert JSON, and Windows JSON exports."""
from __future__ import annotations

from typing import Any

from .common import OUTCOME_MAP, apply, blank_event, classify_message, parse_any_ts, to_port, valid_ip
from .windows import build_windows_event

ALIASES = {
    "timestamp": ["timestamp", "@timestamp", "time", "ts", "datetime", "eventTime", "event_time", "date"],
    "host": ["host.name", "hostname", "host", "agent.name", "computer", "device", "node"],
    "username": ["user.name", "username", "user", "account", "data.dstuser", "data.srcuser", "actor"],
    "src_ip": ["source.ip", "src_ip", "srcip", "source_ip", "client_ip", "data.srcip", "remote_ip", "ip"],
    "dst_ip": ["destination.ip", "dst_ip", "dstip", "dest_ip", "destination_ip", "data.dstip"],
    "src_port": ["source.port", "src_port", "srcport", "source_port"],
    "dst_port": ["destination.port", "dst_port", "dstport", "dest_port", "destination_port"],
    "process": ["process.name", "process", "program", "program_name", "exe", "image"],
    "command": ["process.command_line", "command_line", "commandline", "command", "cmd"],
    "file_path": ["file.path", "file_path", "path", "target_path"],
    "message": ["message", "msg", "log", "full_log", "event.original", "text"],
    "outcome": ["event.outcome", "outcome", "result", "status"],
    "action": ["event.action", "action"],
    "category": ["event.category", "category", "type"],
}
CAT_MAP = {"authentication": "auth", "auth": "auth", "process": "process", "network": "network", "file": "file",
           "iam": "account", "account": "account", "host": "system", "intrusion_detection": "detection"}


def dig(rec: dict, path: str) -> Any:
    if path in rec:
        return rec[path]
    cur: Any = rec
    for part in path.split("."):
        if isinstance(cur, dict):
            lk = {k.lower(): k for k in cur}
            if part.lower() not in lk:
                return None
            cur = cur[lk[part.lower()]]
        else:
            return None
    return cur


def pick(rec: dict, field: str) -> Any:
    for a in ALIASES[field]:
        v = dig(rec, a)
        if v not in (None, "", [], {}):
            return v
    return None


def is_wazuh(rec: dict) -> bool:
    return isinstance(rec.get("rule"), dict) and "id" in rec["rule"] and ("agent" in rec or "full_log" in rec or "decoder" in rec)


def windows_json_id(rec: dict) -> int | None:
    for p in ("EventID", "winlog.event_id", "Event.System.EventID", "data.win.system.eventID"):
        v = dig(rec, p)
        if isinstance(v, dict):
            v = v.get("#text") or v.get("Value")
        try:
            if v is not None:
                return int(str(v).strip())
        except ValueError:
            continue
    return None


def _scalar(v: Any) -> Any:
    return v[0] if isinstance(v, list) and v else v


def normalize_record(rec: dict) -> tuple[dict | None, str | None]:
    """Returns (event, None) | (None, reason_unsupported)."""
    if "_source" in rec and isinstance(rec["_source"], dict):
        idx_id = rec.get("_id")
        rec = dict(rec["_source"])
        rec.setdefault("_indexer_id", idx_id)
    # Windows (Wazuh win.* or exported JSON)
    eid = windows_json_id(rec)
    if eid is not None:
        data = (dig(rec, "data.win.eventdata") or dig(rec, "winlog.event_data") or dig(rec, "EventData")
                or dig(rec, "Event.EventData") or {})
        if not isinstance(data, dict):
            data = {}
        if not data:
            data = {k: v for k, v in rec.items() if not isinstance(v, (dict, list))}
        ts = pick(rec, "timestamp") or dig(rec, "TimeCreated") or dig(rec, "data.win.system.systemTime")
        comp = (dig(rec, "Computer") or dig(rec, "winlog.computer_name") or dig(rec, "data.win.system.computer")
                or pick(rec, "host"))
        e = build_windows_event(eid, data, ts, comp)
        if is_wazuh(rec):
            _wazuh_meta(e, rec)
        return e, None
    e = blank_event()
    ts_val = pick(rec, "timestamp")
    parsed = parse_any_ts(ts_val)
    msg = pick(rec, "message")
    wazuh = is_wazuh(rec)
    if wazuh:
        msg = msg or dig(rec, "rule.description")
    if parsed is None and msg is None:
        return None, "no recognizable timestamp or message field"
    if parsed:
        e["timestamp"] = parsed[0]
        if parsed[1]:
            e["notes"].append("timestamp_timezone_assumed_utc")
    else:
        e["notes"].append("no_timestamp" if ts_val is None else "unparsable_timestamp")
    e["source_type"] = "wazuh_alert" if wazuh else "json"
    e["host"] = _scalar(pick(rec, "host")) or (dig(rec, "predecoder.hostname") if wazuh else None)
    e["username"] = _scalar(pick(rec, "username"))
    e["src_ip"] = valid_ip(str(_scalar(pick(rec, "src_ip")))) if pick(rec, "src_ip") else None
    e["dst_ip"] = valid_ip(str(_scalar(pick(rec, "dst_ip")))) if pick(rec, "dst_ip") else None
    e["src_port"], e["dst_port"] = to_port(pick(rec, "src_port")), to_port(pick(rec, "dst_port"))
    e["process"] = _scalar(pick(rec, "process")) if not isinstance(pick(rec, "process"), dict) else None
    e["command"], e["file_path"] = pick(rec, "command"), pick(rec, "file_path")
    e["message"] = str(msg)[:4000] if msg is not None else None
    for f in ("username", "host", "process", "command", "file_path"):
        if e[f] is not None and not isinstance(e[f], str):
            e[f] = str(e[f])
    cat = _scalar(pick(rec, "category"))
    if isinstance(cat, str):
        e["category"] = CAT_MAP.get(cat.lower())
    act = pick(rec, "action")
    e["action"] = str(act) if act is not None and not isinstance(act, (dict, list)) else None
    oc = pick(rec, "outcome")
    if isinstance(oc, str):
        e["outcome"] = OUTCOME_MAP.get(oc.lower())
    prog = (dig(rec, "predecoder.program_name") if wazuh else None) or e["process"]
    cls = classify_message(e["message"] or "", prog)
    if cls.get("action") == "unclassified" and (e["category"] or e["action"]):
        cls = {k: v for k, v in cls.items() if k not in ("category", "action", "outcome")}
    apply(e, cls)
    if e["process"] is None and prog:
        e["process"] = prog
    e["outcome"] = e["outcome"] or "unknown"
    e["category"] = e["category"] or "unknown"
    e["action"] = e["action"] or "unclassified"
    if wazuh:
        _wazuh_meta(e, rec)
    return e, None


def _wazuh_meta(e: dict, rec: dict):
    e["source_type"] = "wazuh_alert"
    e["host"] = e["host"] or dig(rec, "agent.name")
    e["extra"].update({
        "wazuh_rule_id": str(dig(rec, "rule.id")), "wazuh_rule_level": dig(rec, "rule.level"),
        "wazuh_rule_description": dig(rec, "rule.description"), "wazuh_rule_groups": dig(rec, "rule.groups"),
        "vendor_mitre_ids": dig(rec, "rule.mitre.id"), "wazuh_agent_id": dig(rec, "agent.id"),
        "wazuh_location": rec.get("location")})
    if rec.get("_indexer_id"):
        e["extra"]["indexer_id"] = rec["_indexer_id"]
    if e.get("src_ip") is None:
        e["src_ip"] = valid_ip(str(dig(rec, "data.srcip"))) if dig(rec, "data.srcip") else None
