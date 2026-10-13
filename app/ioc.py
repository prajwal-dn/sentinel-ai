"""Local IOC extraction. Values come only from fields/text of cited evidence events; enrichment is a separate, optional step."""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

R_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
R_URL = re.compile(r"\bhttps?://[^\s'\"<>]{3,300}", re.I)
R_HASH = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
R_PATH = re.compile(r"(?:/(?:home|root|etc|tmp|var|usr|opt)/[^\s'\"]+|[A-Za-z]:\\[^\s'\"]+)")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
NOT_ENRICHED = {"status": "PROVIDER_NOT_CONFIGURED", "detail": "No threat-intelligence provider has been run for this indicator."}


def ip_scope(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_unspecified:
        return "loopback"
    if any(a in n for n in DOC_NETS):
        return "documentation"      # reserved example ranges; never sent to external providers
    if a.is_private or a.is_link_local:
        return "internal"
    return "external"


def hash_type(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}[len(h)]


def extract_iocs(events: list[dict]) -> list[dict]:
    acc: dict[tuple[str, str], dict] = {}

    def add(kind, value, ev, role):
        k = (kind, value)
        d = acc.setdefault(k, {"type": kind, "value": value, "evidence_ids": [], "roles": set(), "hosts": set()})
        if ev["event_id"] not in d["evidence_ids"] and len(d["evidence_ids"]) < 50:
            d["evidence_ids"].append(ev["event_id"])
        d["roles"].add(role)
        if ev.get("host"):
            d["hosts"].add(ev["host"])

    for e in events:
        if e.get("src_ip"):
            add("ip", e["src_ip"], e, f"source of {e.get('action')}")
        if e.get("dst_ip"):
            add("ip", e["dst_ip"], e, f"destination of {e.get('action')}" + (f" on port {e['dst_port']}" if e.get("dst_port") else ""))
        for u in (e.get("username"), e.get("target_user")):
            if u:
                add("account", u, e, f"account in {e.get('action')}")
        if e.get("file_path"):
            add("file_path", e["file_path"], e, f"path in {e.get('action')}")
        text = " ".join(str(x) for x in (e.get("message"), e.get("command")) if x)
        for m in R_URL.findall(text):
            add("url", m.rstrip(".,);"), e, "URL in event text")
        for m in R_HASH.findall(text):
            add(hash_type(m), m.lower(), e, "hash in event text")
        for m in R_IP.findall(text):
            try:
                ipaddress.ip_address(m)
            except ValueError:
                continue
            add("ip", m, e, "mentioned in event text")
        for m in R_PATH.findall(text):
            add("file_path", m.rstrip(".,);"), e, "path in event text")
    out = []
    for d in acc.values():
        d["roles"] = sorted(d["roles"]); d["hosts"] = sorted(d["hosts"])
        d["source"] = "LOCAL_EXTRACTION"
        d["enrichment"] = dict(NOT_ENRICHED)
        if d["type"] == "ip":
            d["scope"] = ip_scope(d["value"])
        out.append(d)
    out.sort(key=lambda d: (d["type"] != "ip", d["type"], d["value"]))
    return out
