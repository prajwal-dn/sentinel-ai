"""Correlates findings into cases using explicit, recorded reasons."""
from __future__ import annotations

import hashlib

from .detection import DetectionConfig, SEV_ORDER, T, sev_max

POST_ACCESS_RULES = {"account.created", "persistence.ssh_authorized_keys", "network.suspicious_port",
                     "persistence.service_installed", "persistence.scheduled_task", "defense.audit_log_cleared",
                     "account.group_member_added"}


def correlate(findings: list[dict], cfg: DetectionConfig) -> list[dict]:
    n = len(findings)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    reasons: list[tuple[int, int, str]] = []
    for i in range(n):
        for j in range(i + 1, n):
            a, b = findings[i], findings[j]
            why = _link(a, b, cfg)
            if why:
                parent[find(i)] = find(j)
                reasons.append((i, j, why))
    comps: dict[int, list[int]] = {}
    for i in range(n):
        comps.setdefault(find(i), []).append(i)
    cases = []
    for idxs in comps.values():
        fs = [findings[i] for i in idxs]
        fids = sorted(f["finding_id"] for f in fs)
        key = hashlib.sha256("|".join(fids).encode()).hexdigest()[:10]
        rs = [{"findings": [findings[i]["finding_id"], findings[j]["finding_id"]], "reason": w}
              for i, j, w in reasons if i in idxs]
        rules = {f["rule_id"] for f in fs}
        base = sev_max(*[f["severity"] for f in fs])
        basis = [f"Highest finding severity is '{base}'."]
        sev = base
        chain = "auth.success_after_failures" in rules and bool(rules & POST_ACCESS_RULES) and bool(rs)
        if chain:
            sev = "critical"
            basis.append("Escalated to 'critical': a successful login after repeated failures is linked to later "
                         "post-access activity (persistence / unusual connection / evasion) on the same host.")
        ts = sorted(f["first_seen"] for f in fs if f["first_seen"])
        te = sorted(f["last_seen"] for f in fs if f["last_seen"])
        hosts = sorted({h for f in fs for h in f["entities"]["hosts"]})
        cases.append({
            "case_key": key, "finding_ids": fids, "severity": sev, "severity_basis": basis, "attack_chain": chain,
            "title": _title(fs, rules, chain, hosts), "first_seen": ts[0] if ts else None, "last_seen": te[-1] if te else None,
            "hosts": hosts, "users": sorted({u for f in fs for u in f["entities"]["users"]}),
            "ips": sorted({i for f in fs for i in f["entities"]["ips"]}), "correlation_links": rs,
        })
    cases.sort(key=lambda c: (-SEV_ORDER.index(c["severity"]), c["first_seen"] or ""))
    return cases


def _title(fs, rules, chain, hosts) -> str:
    h = ", ".join(hosts[:2]) or "unknown host"
    if chain:
        return f"Suspected account compromise on {h}: failed logins, successful access, then post-access activity"
    if "auth.success_after_failures" in rules:
        return f"Suspicious successful login on {h} after repeated failures"
    if rules & {"auth.bruteforce", "auth.spray"}:
        return f"Repeated failed authentication against {h}"
    return max(fs, key=lambda f: SEV_ORDER.index(f["severity"]))["title"]


def _link(a, b, cfg) -> str | None:
    ea, eb = a["entities"], b["entities"]
    sip = set(ea["ips"]) & set(eb["ips"])
    if sip:
        return f"Share IP address {sorted(sip)[0]}"
    # post-access linkage: access finding + later activity on same host by the logged-in account
    for x, y in ((a, b), (b, a)):
        if x["rule_id"] == "auth.success_after_failures" and y["rule_id"] in POST_ACCESS_RULES | {"priv.sensitive_sudo"}:
            st = x["stats"]
            common_host = set(x["entities"]["hosts"]) & set(y["entities"]["hosts"])
            if not common_host or not y["first_seen"]:
                continue
            dt = (T(y["first_seen"]) - T(st["success_time"])).total_seconds()
            if 0 <= dt <= cfg.correlation_window_seconds and (st["success_user"] in y["entities"]["users"]
                                                               or not y["entities"]["users"]
                                                               or y["rule_id"] == "network.suspicious_port"):
                who = f"account '{st['success_user']}'" if st["success_user"] in y["entities"]["users"] else "the same host (no account attributed on that event)"
                return (f"Activity on {sorted(common_host)[0]} attributed to {who} began {int(dt)}s after the suspicious login "
                        f"(window {cfg.correlation_window_seconds}s)")
    if set(ea["hosts"]) & set(eb["hosts"]) and set(ea["users"]) & set(eb["users"]) and a["first_seen"] and b["first_seen"]:
        if abs((T(a["first_seen"]) - T(b["first_seen"])).total_seconds()) <= cfg.correlation_window_seconds:
            return f"Same host and account '{sorted(set(ea['users']) & set(eb['users']))[0]}' within window"
    return None
