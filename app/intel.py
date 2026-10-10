"""Optional, user-triggered threat-intelligence enrichment. Disabled unless a provider key is configured."""
from __future__ import annotations

import ipaddress

import httpx

from .config import Settings
from .storage import now_iso

MAX_LOOKUPS = 25


def intel_status(s: Settings) -> dict:
    if not s.abuseipdb_key:
        return {"configured": False, "provider": None, "status": "PROVIDER_NOT_CONFIGURED",
                "message": "No threat-intelligence provider configured (set SENTINEL_ABUSEIPDB_KEY). No external lookups are made."}
    return {"configured": True, "provider": "abuseipdb", "status": "CONFIGURED",
            "message": "AbuseIPDB configured. Lookups run only when an analyst requests enrichment, for external IPs."}


def _lookup_abuseipdb(ip: str, key: str, transport) -> dict:
    try:
        with httpx.Client(timeout=10, transport=transport) as c:
            r = c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                      headers={"Key": key, "Accept": "application/json"})
    except httpx.TimeoutException:
        return {"status": "PROVIDER_UNAVAILABLE", "detail": "timeout"}
    except httpx.HTTPError as exc:
        return {"status": "PROVIDER_UNAVAILABLE", "detail": type(exc).__name__}
    if r.status_code >= 500:
        return {"status": "PROVIDER_UNAVAILABLE", "detail": f"HTTP {r.status_code}"}
    if r.status_code != 200:
        return {"status": "LOOKUP_FAILED", "detail": f"HTTP {r.status_code}"}
    try:
        d = r.json()["data"]
        total = int(d.get("totalReports", 0))
    except (ValueError, KeyError, TypeError):
        return {"status": "LOOKUP_FAILED", "detail": "unexpected response"}
    base = {"abuse_confidence_score": d.get("abuseConfidenceScore"), "total_reports": total,
            "country_code": d.get("countryCode"), "isp": d.get("isp")}
    return {"status": "MATCH" if total > 0 else "NO_MATCH", **base}


def enrich(inv: dict, s: Settings, transport=None) -> dict:
    n = 0
    for i in inv["iocs"]:
        if i["type"] != "ip":
            continue
        if not s.abuseipdb_key:
            i["enrichment"] = {"status": "PROVIDER_NOT_CONFIGURED", "detail": "No provider configured."}
            continue
        if i.get("scope") != "external":
            i["enrichment"] = {"status": "NOT_APPLICABLE", "detail": f"{i.get('scope')} address; not sent to external providers."}
            continue
        if n >= MAX_LOOKUPS:
            i["enrichment"] = {"status": "NOT_LOOKED_UP", "detail": f"Lookup cap of {MAX_LOOKUPS} reached."}
            continue
        n += 1
        i["enrichment"] = {**_lookup_abuseipdb(i["value"], s.abuseipdb_key, transport), "provider": "abuseipdb", "checked_at": now_iso()}
    return inv
