"""Transparent, configurable detection rules. Every finding cites the event IDs it was built from."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Callable

from .mitre import technique

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
LOGIN_FAIL = {"ssh_login_failed", "windows_logon_failed"}
LOGIN_OK = {"ssh_login_success", "windows_logon_success"}
MAX_EVIDENCE = 500


@dataclass
class DetectionConfig:
    fail_threshold: int = 5
    fail_window_seconds: int = 300        # max gap between consecutive failures in one cluster
    success_window_seconds: int = 900     # success counted if within this long after the last failure
    spray_min_users: int = 5
    spray_max_per_user: int = 3
    suspicious_ports: tuple = (4444, 5555, 1337, 31337, 6666, 6667, 9001, 12345)
    sensitive_sudo_regex: str = (r"\b(useradd|adduser|usermod|passwd|visudo|crontab|nc|ncat|netcat)\b|chmod\s+(u\+s|[0-7]?[4-7][0-7]{3})"
                                 r"|/bin/(ba)?sh\b|(curl|wget)[^|]*\|\s*(ba)?sh")
    privileged_groups: tuple = ("administrators", "domain admins", "enterprise admins", "sudo", "wheel", "root")
    vendor_level_threshold: int = 12
    correlation_window_seconds: int = 1800

    @classmethod
    def load(cls, path: str | None) -> "DetectionConfig":
        cfg = cls()
        if path:
            with open(path, encoding="utf-8") as fh:
                for k, v in json.load(fh).items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, tuple(v) if isinstance(getattr(cfg, k), tuple) else v)
        return cfg

    def as_dict(self) -> dict:
        return asdict(self)


def T(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def sev_max(*s: str) -> str:
    return max(s, key=SEV_ORDER.index)


def make_finding(rule_id, title, description, severity, severity_basis, strength, events, mitre, explanation,
                 uncertainty, recs, extra_entities=None, stats=None, stage="") -> dict:
    ids = [e["event_id"] for e in events]
    fid = "FND-" + hashlib.sha256((rule_id + "|" + "|".join(sorted(ids))).encode()).hexdigest()[:10]
    ts = sorted(e["timestamp"] for e in events if e.get("timestamp"))
    ent = {"hosts": sorted({e["host"] for e in events if e.get("host")}),
           "users": sorted({u for e in events for u in (e.get("username"), e.get("target_user")) if u}),
           "ips": sorted({i for e in events for i in (e.get("src_ip"), e.get("dst_ip")) if i})}
    if extra_entities:
        for k, v in extra_entities.items():
            ent[k] = v
    return {"finding_id": fid, "rule_id": rule_id, "title": title, "description": description,
            "severity": severity, "severity_basis": severity_basis, "evidence_strength": strength,
            "detection_method": "RULE", "origin": "RULE", "stage": stage,
            "evidence_ids": ids[:MAX_EVIDENCE], "evidence_total": len(ids), "evidence_truncated": len(ids) > MAX_EVIDENCE,
            "first_seen": ts[0] if ts else None, "last_seen": ts[-1] if ts else None, "entities": ent,
            "mitre": mitre, "explanation": explanation, "uncertainty": uncertainty,
            "recommended_steps": recs, "stats": stats or {}}


def rec(action, rationale, disruptive=False, approval=None):
    return {"action": action, "rationale": rationale, "disruptive": disruptive,
            "requires_approval": disruptive if approval is None else approval}


# ------------------------------------------------------------------ rules
def _clusters(events, key, window):
    groups = defaultdict(list)
    for e in events:
        if e.get("timestamp"):
            groups[key(e)].append(e)
    for k, evs in groups.items():
        evs.sort(key=lambda e: e["timestamp"])
        cur = [evs[0]]
        for e in evs[1:]:
            if (T(e["timestamp"]) - T(cur[-1]["timestamp"])).total_seconds() <= window:
                cur.append(e)
            else:
                yield k, cur
                cur = [e]
        yield k, cur


def rule_auth_failures(events, cfg: DetectionConfig):
    """Returns (findings, clusters) — clusters feed the success-after-failure rule."""
    fails = [e for e in events if e.get("action") in LOGIN_FAIL]
    key = lambda e: (e.get("src_ip"), e.get("host"), None if e.get("src_ip") else e.get("username"))  # noqa: E731
    out, clusters = [], []
    for k, cl in _clusters(fails, key, cfg.fail_window_seconds):
        if len(cl) < cfg.fail_threshold:
            continue
        users = [e.get("username") for e in cl if e.get("username")]
        distinct, per_user = len(set(users)), defaultdict(int)
        for u in users:
            per_user[u] += 1
        max_per = max(per_user.values()) if per_user else 0
        span = (T(cl[-1]["timestamp"]) - T(cl[0]["timestamp"])).total_seconds()
        src = k[0] or "an unknown source"
        host = k[1] or "unknown host"
        spray = distinct >= cfg.spray_min_users and max_per <= cfg.spray_max_per_user
        if spray:
            rid, title, tid = "auth.spray", f"Password-spraying pattern against {host} from {src}", "T1110.003"
        else:
            rid, title = "auth.bruteforce", f"Repeated failed logins against {host} from {src}"
            tid = "T1110.001" if (distinct == 1 or max_per >= 5) and distinct <= 3 else "T1110"
        sev = "high" if (len(cl) >= 50 or distinct >= 10) else "medium"
        basis = (f"Base severity 'medium' for {len(cl)} failures >= threshold {cfg.fail_threshold}; "
                 "raised to 'high' only at >=50 failures or >=10 distinct accounts.")
        f = make_finding(
            rid, title,
            f"{len(cl)} failed authentication attempts against {host} from {src} over {int(span)}s, targeting "
            f"{distinct} account(s) (most-attempted account: {max_per} tries).",
            sev, basis, "moderate" if len(cl) < 20 else "strong", cl,
            [technique(tid, "SUSPECTED", f"{len(cl)} failed logins from one source within gaps <= {cfg.fail_window_seconds}s; "
                       "intent is inferred from the pattern.", [e["event_id"] for e in cl])],
            "Rule: failed-login events clustered by (source, host); cluster size >= threshold.",
            "Failures alone do not prove malicious intent (misconfigured clients, expired credentials and password "
            "managers can also cause bursts). The source may also be shared (NAT/proxy).",
            [rec("Review the source address's history and confirm whether it is an expected client or scanner.",
                 "Distinguishes misconfiguration from hostile activity."),
             rec(f"Consider rate-limiting or blocking {src} after validating business impact.",
                 "Reduces further guessing attempts; may affect legitimate users behind the same address.",
                 disruptive=True)] if k[0] else
            [rec("Review the targeted account for lockout and unusual sign-in sources.", "Confirms account exposure.")],
            stats={"failures": len(cl), "distinct_users": distinct, "max_attempts_per_user": max_per,
                   "duration_seconds": int(span), "source_ip": k[0]}, stage="credential_access")
        out.append(f)
        clusters.append({"key": k, "events": cl, "finding": f, "users": set(users)})
    return out, clusters


def rule_success_after_failures(events, cfg, clusters):
    out = []
    oks = [e for e in events if e.get("action") in LOGIN_OK and e.get("timestamp")]
    for c in clusters:
        src, host = c["key"][0], c["key"][1]
        if not src:
            continue
        t0, t1 = T(c["events"][0]["timestamp"]), T(c["events"][-1]["timestamp"])
        hits = [e for e in oks if e.get("src_ip") == src and e.get("host") == host
                and 0 <= (T(e["timestamp"]) - t1).total_seconds() <= cfg.success_window_seconds]
        if not hits:
            continue
        hits.sort(key=lambda e: e["timestamp"])
        first = hits[0]
        same_user = first.get("username") in c["users"]
        evid = c["events"] + hits[:5]
        f = make_finding(
            "auth.success_after_failures", f"Successful login to {host} from {src} after repeated failures",
            f"After {len(c['events'])} failed attempts, {src} authenticated successfully to {host} as "
            f"'{first.get('username')}' at {first['timestamp']}"
            + (" — the same account had failed earlier." if same_user else " — an account not seen among the failures."),
            "high", "Fixed at 'high': a successful login from a source that just failed >= threshold times. "
            "May be raised to 'critical' by correlation if post-access activity follows.",
            "strong" if same_user else "moderate", evid,
            [technique("T1078", "SUSPECTED", "Login succeeded from a source with preceding repeated failures; whether the "
                       "credentials were guessed or legitimately held cannot be confirmed from logs.", [e["event_id"] for e in evid])],
            "Rule: successful login with same source and host within "
            f"{cfg.success_window_seconds}s after the last failure in a qualifying cluster.",
            "A legitimate user may have mistyped their password several times before succeeding.",
            [rec(f"Review session activity of '{first.get('username')}' on {host} since {first['timestamp']}.",
                 "Establishes whether the login was followed by suspicious behaviour."),
             rec(f"Consider disabling or resetting credentials for '{first.get('username')}'.",
                 "Limits attacker access if the account is compromised; interrupts a legitimate user if not.",
                 disruptive=True)],
            stats={"failures": len(c["events"]), "successful_logins": len(hits), "same_account_failed_first": same_user,
                   "success_user": first.get("username"), "success_time": first["timestamp"], "source_ip": src},
            stage="initial_access")
        out.append(f)
    return out


USERADD = re.compile(r"\b(useradd|adduser)\b(?P<args>.*)")


def _useradd_target(cmd: str) -> str | None:
    m = USERADD.search(cmd or "")
    if not m:
        return None
    toks = [t for t in m["args"].split() if not t.startswith("-")]
    return toks[-1] if toks else None


def rule_account_created(events, cfg):
    groups = defaultdict(list)
    for e in events:
        if e.get("action") == "account_created":
            groups[(e.get("host"), e.get("target_user"))].append(e)
        elif e.get("action") == "sudo_command" and USERADD.search(e.get("command") or ""):
            groups[(e.get("host"), _useradd_target(e["command"]))].append(e)
    out = []
    for (host, tgt), evs in groups.items():
        evs.sort(key=lambda e: e.get("timestamp") or "")
        actors = sorted({e["username"] for e in evs if e.get("username")})
        out.append(make_finding(
            "account.created", f"New local account '{tgt or 'unknown'}' created on {host or 'unknown host'}",
            f"Account creation for '{tgt or 'unknown'}' on {host or 'unknown host'}"
            + (f" performed by {', '.join(actors)}" if actors else "") + ".",
            "medium", "Base severity 'medium': account creation is a common persistence step but is routine administration too.",
            "moderate", evs, [technique("T1136.001", "OBSERVED", "An account creation (useradd/adduser or Windows 4720) appears in the logs.",
                                        [e["event_id"] for e in evs])],
            "Rule: account-creation events or sudo useradd/adduser commands.",
            "Cannot tell from the log whether the creation was an authorised change.",
            [rec(f"Verify '{tgt}' against change tickets; confirm who requested it.", "Separates authorised administration from persistence.")],
            extra_entities={"accounts_created": [tgt] if tgt else []}, stage="persistence"))
    return out


def rule_authorized_keys(events, cfg):
    evs = [e for e in events if e.get("action") == "authorized_keys_modified"
           or (e.get("category") == "file" and "authorized_keys" in ((e.get("file_path") or "") + (e.get("message") or "")))]
    by_host = defaultdict(list)
    for e in evs:
        by_host[(e.get("host"), e.get("file_path"))].append(e)
    return [make_finding(
        "persistence.ssh_authorized_keys", f"SSH authorized_keys modified on {h or 'unknown host'}",
        f"File activity on {p or 'an authorized_keys file'} on {h or 'unknown host'} ({len(v)} event(s)).",
        "medium", "Base severity 'medium': SSH key changes grant durable access but are also routine.", "moderate", v,
        [technique("T1098.004", "OBSERVED", "authorized_keys file activity appears in the logs.", [e["event_id"] for e in v])],
        "Rule: file events referencing authorized_keys.", "Key contents are not logged, so the added key's origin is unknown.",
        [rec("Inspect the authorized_keys file and compare entries to approved keys.", "Identifies unauthorised access keys.")],
        stage="persistence") for (h, p), v in by_host.items()]


def rule_sensitive_sudo(events, cfg):
    rx = re.compile(cfg.sensitive_sudo_regex)
    evs = [e for e in events if e.get("action") == "sudo_command" and rx.search(e.get("command") or "")
           and not USERADD.search(e.get("command") or "")]
    by = defaultdict(list)
    for e in evs:
        by[(e.get("host"), e.get("username"))].append(e)
    return [make_finding(
        "priv.sensitive_sudo", f"Sensitive commands run via sudo by '{u}' on {h or 'unknown host'}",
        f"{len(v)} sudo invocation(s) matching sensitive-command patterns.", "low",
        "Fixed at 'low': sudo use is normal; this is context for correlation, not an alert on its own.",
        "weak", v, [], "Rule: sudo COMMAND matching configurable sensitive patterns.",
        "Routine administration produces the same events. No ATT&CK technique is assigned because sudo use alone is not abuse.",
        [rec("Confirm the commands were expected for this user.", "Provides context for the surrounding events.")],
        stage="privilege_escalation") for (h, u), v in by.items()]


def _is_loopbackish(ip: str) -> bool:
    import ipaddress
    a = ipaddress.ip_address(ip)
    return a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local


def rule_suspicious_port(events, cfg):
    by = defaultdict(list)
    for e in events:
        if e.get("category") == "network" and e.get("dst_ip") and e.get("dst_port") in cfg.suspicious_ports \
                and not _is_loopbackish(e["dst_ip"]):
            by[(e.get("host"), e["dst_ip"], e["dst_port"])].append(e)
    out = []
    for (h, ip, port), v in by.items():
        explicit = any(e.get("action") == "outbound_connection" or e["extra"].get("direction") == "outbound" for e in v)
        out.append(make_finding(
            "network.suspicious_port", f"Connection from {h or 'unknown host'} to {ip}:{port}",
            f"{len(v)} network event(s) to {ip} on TCP/UDP port {port}, a port on the configured watch-list.",
            "medium", "Base severity 'medium': watch-list ports are used by common backdoors/tools but also by legitimate software.",
            "weak" if not explicit else "moderate", v,
            [technique("T1571", "SUSPECTED", f"Destination port {port} is on the configured non-standard/suspicious port list.",
                       [e["event_id"] for e in v])],
            "Rule: network events whose destination port is in 'suspicious_ports'.",
            "Port lists are heuristic. No payload, process or reputation data was inspected; "
            + ("" if explicit else "the log does not state the connection direction."),
            [rec(f"Identify the process on {h or 'the host'} that opened the connection and the owner of {ip}.",
                 "Determines whether the traffic is benign tooling or command-and-control.")],
            stats={"connections": len(v), "bytes_seen": None}, stage="command_and_control"))
    return out


def rule_windows_persistence_and_evasion(events, cfg):
    out = []
    for e in events:
        a = e.get("action")
        if a == "audit_log_cleared":
            out.append(make_finding("defense.audit_log_cleared", f"Windows audit log cleared on {e.get('host') or 'unknown host'}",
                f"Security log cleared by '{e.get('username')}'.", "high",
                "Fixed at 'high': clearing the security log removes investigative evidence.", "strong", [e],
                [technique("T1070.001", "OBSERVED", "Windows event 1102 (audit log cleared) is present.", [e["event_id"]])],
                "Rule: Windows event 1102.", "May be authorised maintenance.",
                [rec("Confirm with the account owner/change records; preserve any remaining logs and forward logs off-host.", "Evidence preservation.")],
                stage="defense_evasion"))
        elif a == "service_installed":
            out.append(make_finding("persistence.service_installed", f"Service installed on {e.get('host') or 'unknown host'}: {e.get('process')}",
                f"Service '{e.get('process')}' installed (binary: {e.get('file_path')}).", "medium",
                "Base severity 'medium': new services are a persistence mechanism but are routine for software installs.", "weak", [e],
                [technique("T1543.003", "OBSERVED", "Windows service installation event present.", [e["event_id"]])],
                "Rule: Windows events 4697/7045.", "Legitimate installers create services too.",
                [rec("Verify the service binary's signature and origin.", "Identifies unauthorised persistence.")], stage="persistence"))
        elif a == "scheduled_task_created":
            out.append(make_finding("persistence.scheduled_task", f"Scheduled task created on {e.get('host') or 'unknown host'}: {e.get('process')}",
                f"Scheduled task '{e.get('process')}' created by '{e.get('username')}'.", "medium",
                "Base severity 'medium': scheduled tasks are a common persistence mechanism and common administration.", "weak", [e],
                [technique("T1053.005", "OBSERVED", "Windows event 4698 (scheduled task created) present.", [e["event_id"]])],
                "Rule: Windows event 4698.", "Task contents are not captured in this log.",
                [rec("Review the task's action and trigger.", "Determines whether it runs attacker code.")], stage="persistence"))
        elif a == "group_member_added":
            grp = (e["extra"].get("group") or "")
            sev = "high" if grp.lower() in cfg.privileged_groups else "low"
            out.append(make_finding("account.group_member_added", f"Member added to group '{grp}' on {e.get('host') or 'unknown host'}",
                f"'{e.get('target_user')}' added to '{grp}' by '{e.get('username')}'.", sev,
                f"'high' only when the group is on the privileged-group list; otherwise 'low'.", "moderate", [e],
                [technique("T1098", "SUSPECTED", "Group membership change (possible privilege change).", [e["event_id"]])],
                "Rule: Windows events 4728/4732/4756.", "Often routine administration.",
                [rec("Verify the change against approvals.", "Detects unauthorised privilege grants.")], stage="privilege_escalation"))
    return out


def rule_vendor_alert(events, cfg):
    by = defaultdict(list)
    for e in events:
        lvl = e["extra"].get("wazuh_rule_level")
        if isinstance(lvl, (int, float)) and lvl >= cfg.vendor_level_threshold:
            by[(e.get("host"), e["extra"].get("wazuh_rule_id"))].append(e)
    return [make_finding("vendor.high_level_alert", f"SIEM-raised alert on {h or 'unknown host'}: {v[0]['extra'].get('wazuh_rule_description')}",
        f"Wazuh rule {rid} (level {v[0]['extra'].get('wazuh_rule_level')}) fired {len(v)} time(s). This is the SIEM's assertion, not an independent Sentinel detection.",
        "high", f"'high' because the source SIEM rated it level >= {cfg.vendor_level_threshold}.", "moderate", v, [],
        "Rule: forwards high-level vendor alerts as findings for triage.",
        "Vendor ATT&CK labels (" + str(v[0]['extra'].get('vendor_mitre_ids')) + ") are vendor-asserted and are not adopted as Sentinel mappings.",
        [rec("Triage the alert in the originating SIEM.", "Vendor context may include data not exported here.")],
        stage="") for (h, rid), v in by.items()]


def run_detections(events: list[dict], cfg: DetectionConfig) -> list[dict]:
    fails, clusters = rule_auth_failures(events, cfg)
    findings = fails + rule_success_after_failures(events, cfg, clusters)
    for fn in (rule_account_created, rule_authorized_keys, rule_sensitive_sudo, rule_suspicious_port,
               rule_windows_persistence_and_evasion, rule_vendor_alert):
        findings += fn(events, cfg)
    seen, uniq = set(), []
    for f in findings:
        if f["finding_id"] not in seen:
            seen.add(f["finding_id"]); uniq.append(f)
    uniq.sort(key=lambda f: (f["first_seen"] or "", f["finding_id"]))
    return uniq
