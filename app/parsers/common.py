from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(value: str) -> tuple[str, bool] | None:
    """Returns (normalized UTC ts, tz_assumed). None if unparsable."""
    v = value.strip()
    if not v:
        return None
    v = re.sub(r"Z$", "+00:00", v)
    v = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v)
    v = re.sub(r"^(\d{4}-\d{2}-\d{2}) (\d)", r"\1T\2", v)
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    assumed = dt.tzinfo is None
    if assumed:
        dt = dt.replace(tzinfo=timezone.utc)
    return fmt_ts(dt), assumed


def parse_any_ts(value: Any) -> tuple[str, bool] | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        x = float(value)
        if x > 1e11:
            x /= 1000.0
        if x < 946684800 or x > 4102444800:  # sanity: 2000..2100
            return None
        return fmt_ts(datetime.fromtimestamp(x, tz=timezone.utc)), False
    if isinstance(value, str):
        if re.fullmatch(r"\d{10,13}(\.\d+)?", value.strip()):
            return parse_any_ts(float(value))
        return parse_iso(value)
    return None


def parse_syslog_ts(text: str, year: int, now: datetime | None = None) -> str | None:
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})$", text.strip())
    if not m or m.group(1) not in MONTHS:
        return None
    try:
        dt = datetime(year, MONTHS[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)),
                      int(m.group(5)), tzinfo=timezone.utc)
    except ValueError:
        return None
    ref = now or datetime.now(timezone.utc)
    if dt > ref + timedelta(days=1):  # a Dec log read in Jan with default year -> previous year
        try:
            dt = dt.replace(year=year - 1)
        except ValueError:
            return None
    return fmt_ts(dt)


def valid_ip(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip().strip("[]")
    if s.startswith("::ffff:"):
        s = s[7:]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def to_port(v: Any) -> int | None:
    try:
        p = int(v)
        return p if 0 < p < 65536 else None
    except (TypeError, ValueError):
        return None


def event_id(source_key: str, position: Any) -> str:
    return "evt-" + hashlib.sha256(f"{source_key}:{position}".encode()).hexdigest()[:12]


BASE_FIELDS = ("timestamp", "host", "source_type", "username", "target_user", "src_ip", "dst_ip", "src_port",
               "dst_port", "process", "command", "file_path", "category", "action", "outcome", "message")


def blank_event() -> dict:
    e: dict[str, Any] = {k: None for k in BASE_FIELDS}
    e["notes"] = []
    e["extra"] = {}
    return e


# ---------------------------------------------------------------- message classification
IP = r"[0-9A-Fa-f:.]+"
R_FAILED = re.compile(rf"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>{IP}) port (?P<port>\d+)")
R_ACCEPTED = re.compile(rf"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>{IP}) port (?P<port>\d+)")
R_INVALID = re.compile(rf"Invalid user (?P<user>\S*) from (?P<ip>{IP})(?: port (?P<port>\d+))?")
R_PREAUTH = re.compile(rf"Connection closed by (?:authenticating|invalid) user (?P<user>\S+) (?P<ip>{IP}) port (?P<port>\d+)")
R_MAXAUTH = re.compile(rf"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>{IP}) port (?P<port>\d+)")
R_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:.*?; )?TTY=[^;]*; PWD=(?P<pwd>[^;]*) ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
R_SUDO_FAIL = re.compile(r"(?:authentication failure|incorrect password attempts)")
R_PAM_USER = re.compile(r"\buser=(?P<user>\S+)")
R_USERADD = re.compile(r"new user: name=(?P<name>[^,\s]+)")
R_USERDEL = re.compile(r"delete user '(?P<name>[^']+)'")
R_PASSWD = re.compile(r"password changed for (?P<name>\S+)")
R_SU = re.compile(r"(?P<ok>Successful|FAILED) su for (?P<target>\S+) by (?P<user>\S+)")
R_AUTHKEYS = re.compile(r"authorized_keys", re.I)
R_OUTBOUND = re.compile(r"(?i)outbound\s+(?P<proto>tcp|udp)\s+connection\s+to\s+(?P<ip>[0-9a-fA-F:.]+):(?P<port>\d+)")


def classify_message(msg: str, process: str | None = None) -> dict:
    """Derive category/action/outcome and entities from a free-text message. Unrecognised -> category 'system'/'unclassified'."""
    out: dict[str, Any] = {}
    if not msg:
        return out
    m = R_FAILED.search(msg)
    if m:
        return {"category": "auth", "action": "ssh_login_failed", "outcome": "failure", "username": m["user"],
                "src_ip": valid_ip(m["ip"]), "src_port": to_port(m["port"]), "dst_port": 22,
                "extra": {"auth_method": m["method"], "invalid_user": bool(m["invalid"])}}
    m = R_ACCEPTED.search(msg)
    if m:
        return {"category": "auth", "action": "ssh_login_success", "outcome": "success", "username": m["user"],
                "src_ip": valid_ip(m["ip"]), "src_port": to_port(m["port"]), "dst_port": 22,
                "extra": {"auth_method": m["method"]}}
    m = R_MAXAUTH.search(msg)
    if m:
        return {"category": "auth", "action": "ssh_max_auth_exceeded", "outcome": "unknown", "username": m["user"],
                "src_ip": valid_ip(m["ip"]), "src_port": to_port(m["port"])}
    m = R_INVALID.search(msg)
    if m:
        return {"category": "auth", "action": "ssh_invalid_user", "outcome": "unknown", "username": m["user"] or None,
                "src_ip": valid_ip(m["ip"]), "src_port": to_port(m["port"])}
    m = R_PREAUTH.search(msg)
    if m:
        return {"category": "auth", "action": "ssh_preauth_close", "outcome": "unknown", "username": m["user"],
                "src_ip": valid_ip(m["ip"]), "src_port": to_port(m["port"])}
    m = R_SUDO.match(msg)
    if m:
        return {"category": "process", "action": "sudo_command", "outcome": "success", "username": m["user"],
                "target_user": m["target"], "command": m["cmd"].strip()[:1000]}
    if process and process.startswith("sudo") and R_SUDO_FAIL.search(msg):
        u = R_PAM_USER.search(msg)
        return {"category": "auth", "action": "sudo_auth_failed", "outcome": "failure", "username": u["user"] if u else None}
    m = R_SU.search(msg)
    if m:
        ok = m["ok"] == "Successful"
        return {"category": "auth", "action": "su_success" if ok else "su_failed",
                "outcome": "success" if ok else "failure", "username": m["user"], "target_user": m["target"]}
    m = R_USERADD.search(msg)
    if m and (process or "").startswith(("useradd", "adduser")):
        return {"category": "account", "action": "account_created", "outcome": "success", "target_user": m["name"]}
    m = R_USERDEL.search(msg)
    if m and (process or "").startswith(("userdel", "deluser")):
        return {"category": "account", "action": "account_deleted", "outcome": "success", "target_user": m["name"]}
    m = R_PASSWD.search(msg)
    if m and (process or "").startswith(("passwd", "chpasswd", "usermod")):
        return {"category": "account", "action": "password_changed", "outcome": "success", "target_user": m["name"]}
    m = R_OUTBOUND.search(msg)
    if m:
        return {"category": "network", "action": "outbound_connection", "outcome": "unknown",
                "dst_ip": valid_ip(m["ip"]), "dst_port": to_port(m["port"]), "extra": {"protocol": m["proto"].lower()}}
    if R_AUTHKEYS.search(msg):
        p = re.search(r"(/[^\s'\"]*authorized_keys\S*)", msg)
        return {"category": "file", "action": "authorized_keys_modified", "outcome": "unknown",
                "file_path": p.group(1) if p else None}
    return {"category": "system", "action": "unclassified", "outcome": "unknown"}


def apply(event: dict, fields: dict, overwrite: bool = False):
    for k, v in fields.items():
        if k == "extra":
            event["extra"].update(v)
        elif v is not None and (overwrite or event.get(k) is None):
            event[k] = v


OUTCOME_MAP = {"success": "success", "succeeded": "success", "accepted": "success", "allow": "success",
               "allowed": "success", "ok": "success", "failure": "failure", "failed": "failure", "fail": "failure",
               "denied": "failure", "error": "failure", "deny": "failure", "unknown": "unknown"}
