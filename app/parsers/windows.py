"""Windows Security event normalisation (XML export, JSON export, Winlogbeat-style, Wazuh win.* data)."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from .common import blank_event, parse_any_ts, to_port, valid_ip

SUPPORTED_IDS = {4624, 4625, 4648, 4672, 4688, 4697, 7045, 4698, 4720, 4728, 4732, 4756, 1102}


def _clean(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return None if s in {"", "-", "::", "0.0.0.0"} else s


def windows_fields(event_id: int, data: dict[str, Any]) -> dict:
    d = {str(k).lower(): v for k, v in data.items()}
    g = lambda *ks: next((_clean(d.get(k.lower())) for k in ks if _clean(d.get(k.lower()))), None)  # noqa: E731
    f: dict[str, Any] = {"extra": {"windows_event_id": event_id}}
    if event_id in (4624, 4625, 4648):
        ok = event_id != 4625
        f.update(category="auth", outcome="success" if ok else "failure", username=g("TargetUserName"),
                 src_ip=valid_ip(g("IpAddress")), src_port=to_port(g("IpPort")),
                 action={4624: "windows_logon_success", 4625: "windows_logon_failed", 4648: "windows_explicit_cred_logon"}[event_id])
        f["extra"].update(logon_type=g("LogonType"), target_domain=g("TargetDomainName"),
                          workstation=g("WorkstationName"), status=g("Status"), sub_status=g("SubStatus"))
    elif event_id == 4672:
        f.update(category="privilege", action="special_privileges_assigned", outcome="success", username=g("SubjectUserName"))
    elif event_id == 4688:
        f.update(category="process", action="process_created", outcome="success", username=g("SubjectUserName"),
                 process=g("NewProcessName"), command=g("CommandLine"))
        f["extra"]["parent_process"] = g("ParentProcessName")
    elif event_id in (4697, 7045):
        f.update(category="persistence", action="service_installed", outcome="success", username=g("SubjectUserName"),
                 process=g("ServiceName"), file_path=g("ServiceFileName", "ImagePath"))
    elif event_id == 4698:
        f.update(category="persistence", action="scheduled_task_created", outcome="success",
                 username=g("SubjectUserName"), process=g("TaskName"))
    elif event_id == 4720:
        f.update(category="account", action="account_created", outcome="success", username=g("SubjectUserName"),
                 target_user=g("TargetUserName"))
    elif event_id in (4728, 4732, 4756):
        f.update(category="account", action="group_member_added", outcome="success", username=g("SubjectUserName"),
                 target_user=g("MemberName", "MemberSid"))
        f["extra"]["group"] = g("TargetUserName")
    elif event_id == 1102:
        f.update(category="defense", action="audit_log_cleared", outcome="success", username=g("SubjectUserName"))
    else:
        f.update(category="system", action="unclassified", outcome="unknown")
    return f


def build_windows_event(event_id: int, data: dict, ts_value: Any, computer: str | None) -> dict:
    e = blank_event()
    e["source_type"] = "windows_security"
    e["host"] = computer
    parsed = parse_any_ts(ts_value)
    if parsed:
        e["timestamp"] = parsed[0]
        if parsed[1]:
            e["notes"].append("timestamp_timezone_assumed_utc")
    else:
        e["notes"].append("no_timestamp")
    f = windows_fields(event_id, data)
    e["extra"].update(f.pop("extra"))
    e.update({k: v for k, v in f.items() if v is not None})
    e["message"] = f"Windows event {event_id}: {e['action']}" + (f" user={e['username']}" if e["username"] else "")
    return e


def parse_windows_xml_doc(text: str):
    """Yields (index, event_dict) or (index, Exception). Rejects DTD/entities outright (untrusted XML)."""
    low = text[:4096].lower()
    if "<!doctype" in low or "<!entity" in text.lower():
        raise ValueError("XML containing DOCTYPE/ENTITY declarations is refused (untrusted input)")
    # Wrap multiple root-level <Event> fragments, which is how exports are commonly saved
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text.strip())
    if not re.match(r"<Events?[\s>]", body):
        raise ValueError("not a Windows event XML export")
    if body.startswith("<Event ") or body.startswith("<Event>"):
        body = f"<Events>{body}</Events>"
    root = ET.fromstring(body)
    strip = lambda t: t.rsplit("}", 1)[-1]  # noqa: E731
    nodes = [root] if strip(root.tag) == "Event" else [c for c in root if strip(c.tag) == "Event"]
    for i, ev in enumerate(nodes, 1):
        try:
            system, data = {}, {}
            for ch in ev:
                t = strip(ch.tag)
                if t == "System":
                    for s in ch:
                        st = strip(s.tag)
                        system[st] = s.attrib.get("SystemTime") if st == "TimeCreated" else (s.text or "").strip()
                elif t in ("EventData", "UserData"):
                    for dd in ch.iter():
                        if strip(dd.tag) == "Data" and "Name" in dd.attrib:
                            data[dd.attrib["Name"]] = (dd.text or "").strip()
            eid = int(system.get("EventID") or 0)
            if not eid:
                raise ValueError("missing EventID")
            yield i, build_windows_event(eid, data, system.get("TimeCreated"), system.get("Computer")), eid
        except Exception as exc:  # noqa: BLE001 - reported to the caller as a rejected record
            yield i, exc, None
