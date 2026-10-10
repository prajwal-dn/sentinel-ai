"""SQLite persistence. All queries are parameterised; column names never come from user input."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS datasets(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, source_kind TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS uploads(
  id INTEGER PRIMARY KEY AUTOINCREMENT, dataset_id TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, detected_format TEXT, ingested_at TEXT NOT NULL, summary TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  dataset_id TEXT NOT NULL, event_id TEXT NOT NULL, ts TEXT, host TEXT, source_type TEXT, username TEXT,
  src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, process TEXT, category TEXT, action TEXT,
  outcome TEXT, message TEXT, source_file TEXT, line_no INTEGER, ingested_at TEXT NOT NULL, data TEXT NOT NULL,
  PRIMARY KEY(dataset_id, event_id));
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(dataset_id, ts);
CREATE INDEX IF NOT EXISTS ix_ev_src ON events(dataset_id, src_ip);
CREATE TABLE IF NOT EXISTS investigations(
  id TEXT PRIMARY KEY, dataset_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS decisions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, recommendation_id TEXT NOT NULL,
  decision TEXT NOT NULL, actor TEXT NOT NULL, note TEXT, decided_at TEXT NOT NULL,
  execution_status TEXT NOT NULL, execution_detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS connector_state(
  connector TEXT PRIMARY KEY, data TEXT NOT NULL);
"""

EVENT_COLS = ["ts", "host", "source_type", "username", "src_ip", "dst_ip", "src_port", "dst_port",
              "process", "category", "action", "outcome", "message", "source_file", "line_no"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            d = os.path.dirname(os.path.abspath(path))
            os.makedirs(d, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # -- generic helpers
    def _all(self, sql: str, args: Iterable = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, tuple(args)).fetchall()

    def _one(self, sql: str, args: Iterable = ()):
        with self._lock:
            return self.conn.execute(sql, tuple(args)).fetchone()

    def _exec(self, sql: str, args: Iterable = ()):
        with self._lock:
            cur = self.conn.execute(sql, tuple(args))
            self.conn.commit()
            return cur

    # -- datasets
    def create_dataset(self, ds_id: str, name: str, source_kind: str) -> dict:
        self._exec("INSERT INTO datasets VALUES(?,?,?,?)", (ds_id, name, source_kind, now_iso()))
        return self.get_dataset(ds_id)

    def get_dataset(self, ds_id: str) -> dict | None:
        r = self._one("SELECT * FROM datasets WHERE id=?", (ds_id,))
        if not r:
            return None
        d = dict(r)
        d["event_count"] = self._one("SELECT COUNT(*) c FROM events WHERE dataset_id=?", (ds_id,))["c"]
        rng = self._one("SELECT MIN(ts) a, MAX(ts) b FROM events WHERE dataset_id=? AND ts IS NOT NULL", (ds_id,))
        d["first_event"], d["last_event"] = rng["a"], rng["b"]
        d["uploads"] = [dict(u, summary=json.loads(u["summary"])) for u in
                        self._all("SELECT * FROM uploads WHERE dataset_id=? ORDER BY id", (ds_id,))]
        return d

    def list_datasets(self) -> list[dict]:
        return [self.get_dataset(r["id"]) for r in self._all("SELECT id FROM datasets ORDER BY created_at DESC")]

    def delete_dataset(self, ds_id: str) -> bool:
        if not self.get_dataset(ds_id):
            return False
        inv_ids = [r["id"] for r in self._all("SELECT id FROM investigations WHERE dataset_id=?", (ds_id,))]
        with self._lock:
            for i in inv_ids:
                self.conn.execute("DELETE FROM decisions WHERE investigation_id=?", (i,))
            self.conn.execute("DELETE FROM investigations WHERE dataset_id=?", (ds_id,))
            self.conn.execute("DELETE FROM events WHERE dataset_id=?", (ds_id,))
            self.conn.execute("DELETE FROM uploads WHERE dataset_id=?", (ds_id,))
            self.conn.execute("DELETE FROM datasets WHERE id=?", (ds_id,))
            self.conn.commit()
        return True

    def add_upload(self, ds_id, filename, sha, size, fmt, summary: dict):
        self._exec("INSERT INTO uploads(dataset_id,filename,sha256,size_bytes,detected_format,ingested_at,summary) "
                   "VALUES(?,?,?,?,?,?,?)", (ds_id, filename, sha, size, fmt, now_iso(), json.dumps(summary)))

    # -- events
    def insert_events(self, ds_id: str, events: list[dict]) -> tuple[int, int]:
        """Returns (inserted, duplicates)."""
        ins = 0
        with self._lock:
            for e in events:
                vals = [e.get("timestamp") if c == "ts" else e.get(c) for c in EVENT_COLS]
                cur = self.conn.execute(
                    f"INSERT OR IGNORE INTO events(dataset_id,event_id,{','.join(EVENT_COLS)},ingested_at,data) "
                    f"VALUES(?,?,{','.join('?' * len(EVENT_COLS))},?,?)",
                    [ds_id, e["event_id"], *vals, e["ingested_at"], json.dumps(e, default=str)])
                ins += cur.rowcount
            self.conn.commit()
        return ins, len(events) - ins

    @staticmethod
    def _ev(row) -> dict:
        return json.loads(row["data"])

    def get_events(self, ds_id: str, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        out = []
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            q = ",".join("?" * len(chunk))
            out += [self._ev(r) for r in self._all(
                f"SELECT data FROM events WHERE dataset_id=? AND event_id IN ({q})", [ds_id, *chunk])]
        return out

    def all_events(self, ds_id: str) -> list[dict]:
        return [self._ev(r) for r in self._all(
            "SELECT data FROM events WHERE dataset_id=? ORDER BY ts IS NULL, ts, line_no", (ds_id,))]

    FILTERS = {"host": "host", "username": "username", "src_ip": "src_ip", "dst_ip": "dst_ip",
               "category": "category", "action": "action", "outcome": "outcome", "source_file": "source_file"}

    def search_events(self, ds_id: str, filters: dict, text: str | None = None, start: str | None = None,
                      end: str | None = None, limit: int = 100, offset: int = 0) -> tuple[int, list[dict]]:
        where, args = ["dataset_id=?"], [ds_id]
        for k, col in self.FILTERS.items():
            if filters.get(k):
                where.append(f"{col}=?")
                args.append(filters[k])
        if text:
            where.append("(message LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\')")
            like = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like, like, like]
        if start:
            where.append("ts>=?"); args.append(start)
        if end:
            where.append("ts<=?"); args.append(end)
        w = " AND ".join(where)
        total = self._one(f"SELECT COUNT(*) c FROM events WHERE {w}", args)["c"]
        rows = self._all(f"SELECT data FROM events WHERE {w} ORDER BY ts IS NULL, ts, line_no LIMIT ? OFFSET ?",
                         [*args, max(1, min(limit, 1000)), max(0, offset)])
        return total, [self._ev(r) for r in rows]

    def count_by(self, ds_id: str, column: str, filters: dict) -> list[dict]:
        if column not in self.FILTERS:
            raise ValueError("unsupported group_by column")
        where, args = ["dataset_id=?"], [ds_id]
        for k, col in self.FILTERS.items():
            if filters.get(k):
                where.append(f"{col}=?"); args.append(filters[k])
        rows = self._all(f"SELECT {column} v, COUNT(*) n FROM events WHERE {' AND '.join(where)} "
                         f"GROUP BY {column} ORDER BY n DESC LIMIT 50", args)
        return [{"value": r["v"], "count": r["n"]} for r in rows]

    # -- investigations
    def save_investigation(self, inv: dict):
        now = now_iso()
        with self._lock:
            ex = self.conn.execute("SELECT created_at FROM investigations WHERE id=?", (inv["id"],)).fetchone()
            self.conn.execute("INSERT OR REPLACE INTO investigations VALUES(?,?,?,?,?)",
                              (inv["id"], inv["dataset_id"], ex["created_at"] if ex else now, now,
                               json.dumps(inv, default=str)))
            self.conn.commit()

    def get_investigation(self, inv_id: str) -> dict | None:
        r = self._one("SELECT data, created_at, updated_at FROM investigations WHERE id=?", (inv_id,))
        if not r:
            return None
        d = json.loads(r["data"]); d["created_at"], d["updated_at"] = r["created_at"], r["updated_at"]
        return d

    def list_investigations(self, ds_id: str | None = None) -> list[dict]:
        rows = self._all("SELECT data, created_at, updated_at FROM investigations "
                         + ("WHERE dataset_id=? " if ds_id else "") + "ORDER BY updated_at DESC",
                         [ds_id] if ds_id else [])
        out = []
        for r in rows:
            d = json.loads(r["data"]); d["created_at"], d["updated_at"] = r["created_at"], r["updated_at"]
            out.append(d)
        return out

    # -- decisions / audit
    def add_decision(self, inv_id, rec_id, decision, actor, note, exec_status, exec_detail) -> dict:
        cur = self._exec("INSERT INTO decisions(investigation_id,recommendation_id,decision,actor,note,decided_at,"
                         "execution_status,execution_detail) VALUES(?,?,?,?,?,?,?,?)",
                         (inv_id, rec_id, decision, actor, note, now_iso(), exec_status, exec_detail))
        return dict(self._one("SELECT * FROM decisions WHERE id=?", (cur.lastrowid,)))

    def decisions(self, inv_id: str) -> list[dict]:
        return [dict(r) for r in self._all("SELECT * FROM decisions WHERE investigation_id=? ORDER BY id", (inv_id,))]

    def audit(self, actor: str, action: str, target: str | None = None, detail: Any = None):
        self._exec("INSERT INTO audit_log(ts,actor,action,target,detail) VALUES(?,?,?,?,?)",
                   (now_iso(), actor, action, target, json.dumps(detail, default=str) if detail is not None else None))

    def audit_log(self, limit: int = 200) -> list[dict]:
        return [dict(r) for r in self._all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    # -- connector state
    def get_connector_state(self, name: str) -> dict:
        r = self._one("SELECT data FROM connector_state WHERE connector=?", (name,))
        return json.loads(r["data"]) if r else {}

    def set_connector_state(self, name: str, data: dict):
        self._exec("INSERT OR REPLACE INTO connector_state VALUES(?,?)", (name, json.dumps(data, default=str)))
