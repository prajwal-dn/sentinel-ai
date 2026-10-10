from __future__ import annotations

import re
from datetime import datetime, timezone

from .common import apply, blank_event, classify_message, parse_iso, parse_syslog_ts

PRI = re.compile(r"^<\d{1,3}>(?!1 )")
R3164 = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:? ?(?P<msg>.*)$")
RISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (?P<host>\S+) (?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:? ?(?P<msg>.*)$")
R5424 = re.compile(r"^<\d{1,3}>1 (?P<ts>\S+) (?P<host>\S+) (?P<proc>\S+) (?P<pid>\S+) \S+ (?:-|\[.*?\]) ?(?P<msg>.*)$")


def match_line(line: str):
    s = line.rstrip("\r\n")
    m = R5424.match(s)
    if m:
        return "5424", m
    s = PRI.sub("", s)
    for kind, rx in (("3164", R3164), ("iso", RISO)):
        m = rx.match(s)
        if m:
            return kind, m
    return None, None


def parse_line(line: str, default_year: int, source_type: str = "syslog") -> dict | None:
    kind, m = match_line(line)
    if not m:
        return None
    e = blank_event()
    e["source_type"] = source_type
    e["host"] = m["host"] if m["host"] != "-" else None
    proc = m["proc"] if m["proc"] != "-" else None
    e["process"] = proc
    e["message"] = m["msg"]
    if kind == "3164":
        ts = parse_syslog_ts(m["ts"], default_year)
        if ts is None:
            return None
        e["timestamp"] = ts
        e["notes"].append(f"timestamp_year_assumed_{default_year}")
    else:
        parsed = parse_iso(m["ts"].replace(",", "."))
        if parsed is None:
            return None
        e["timestamp"] = parsed[0]
        if parsed[1]:
            e["notes"].append("timestamp_timezone_assumed_utc")
    if m["pid"] and m["pid"] != "-":
        e["extra"]["pid"] = m["pid"]
    apply(e, classify_message(e["message"], proc))
    return e
