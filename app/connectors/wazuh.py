"""Wazuh connector via the Wazuh *indexer* (OpenSearch) alerts index — where alerts are actually stored.

Credentials come from environment variables only and are never stored in the database or returned by the API.
Pagination: sort by timestamp + search_after. Incremental: watermark with overlap; duplicates removed by indexer _id.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx

from ..config import Settings
from ..parsers import ParseOptions, parse_text
from ..storage import Store, now_iso

DATASET_ID = "ds-wazuh"
PAGE = 500
OVERLAP = timedelta(seconds=120)
CONNECTOR = "wazuh"


class ConnectorError(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind, self.detail = kind, detail


class WazuhConnector:
    def __init__(self, settings: Settings, store: Store, transport: httpx.BaseTransport | None = None, sleep=time.sleep):
        self.s, self.store, self.transport, self._sleep = settings, store, transport, sleep

    # ---- configuration
    def missing_config(self) -> list[str]:
        miss = []
        if not self.s.wazuh_url:
            miss.append("SENTINEL_WAZUH_INDEXER_URL")
        if not self.s.wazuh_user:
            miss.append("SENTINEL_WAZUH_USER")
        if not self.s.wazuh_password:
            miss.append("SENTINEL_WAZUH_PASSWORD")
        if self.s.wazuh_url and urlparse(self.s.wazuh_url).scheme not in ("http", "https"):
            miss.append("SENTINEL_WAZUH_INDEXER_URL (must be http(s))")
        return miss

    def _client(self) -> httpx.Client:
        verify: bool | str = self.s.wazuh_ca_bundle or self.s.wazuh_verify_tls
        return httpx.Client(base_url=self.s.wazuh_url.rstrip("/"), auth=(self.s.wazuh_user, self.s.wazuh_password),
                            timeout=15, verify=verify, transport=self.transport)

    def _request(self, c: httpx.Client, method: str, path: str, **kw) -> httpx.Response:
        last: Exception | None = None
        for attempt in range(3):
            try:
                r = c.request(method, path, **kw)
            except httpx.TimeoutException as exc:
                last = ConnectorError("TIMEOUT", "request timed out")
            except httpx.ConnectError as exc:
                msg = str(exc).lower()
                last = ConnectorError("TLS_ERROR" if "ssl" in msg or "certificate" in msg else "UNREACHABLE",
                                      "TLS/certificate problem" if "ssl" in msg or "certificate" in msg else "cannot connect")
            except httpx.HTTPError as exc:
                last = ConnectorError("UNREACHABLE", type(exc).__name__)
            else:
                if r.status_code in (401, 403):
                    raise ConnectorError("AUTH_FAILED" if r.status_code == 401 else "PERMISSION_DENIED",
                                         f"HTTP {r.status_code} from indexer")
                if r.status_code >= 500 or r.status_code == 429:
                    last = ConnectorError("SERVER_ERROR", f"HTTP {r.status_code}")
                elif r.status_code >= 400:
                    raise ConnectorError("REQUEST_REJECTED", f"HTTP {r.status_code}")
                else:
                    return r
            if attempt < 2:
                self._sleep(0.5 * (attempt + 1))
        raise last  # type: ignore[misc]

    # ---- operations
    def test(self) -> dict:
        miss = self.missing_config()
        if miss:
            return {"ok": False, "kind": "NOT_CONFIGURED", "detail": "Missing: " + ", ".join(miss)}
        try:
            with self._client() as c:
                r = self._request(c, "GET", "/")
                info = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        except ConnectorError as e:
            self._record(error=e)
            return {"ok": False, "kind": e.kind, "detail": e.detail}
        return {"ok": True, "kind": "OK", "detail": f"Indexer reachable (cluster: {info.get('cluster_name', 'unknown')})."}

    def poll(self) -> dict:
        miss = self.missing_config()
        if miss:
            return {"ok": False, "kind": "NOT_CONFIGURED", "detail": "Missing: " + ", ".join(miss), "new_events": 0}
        st = self.store.get_connector_state(CONNECTOR)
        wm = st.get("watermark")
        since = (datetime.fromisoformat(wm.replace("Z", "+00:00")) - OVERLAP) if wm else \
            datetime.now(timezone.utc) - timedelta(hours=1)
        hits_all: list[dict] = []
        try:
            with self._client() as c:
                search_after = None
                while len(hits_all) < self.s.wazuh_max_per_poll:
                    body = {"size": PAGE, "sort": [{"timestamp": "asc"}],
                            "query": {"range": {"timestamp": {"gte": since.strftime("%Y-%m-%dT%H:%M:%S.000Z")}}}}
                    if search_after:
                        body["search_after"] = search_after
                    r = self._request(c, "POST", f"/{self.s.wazuh_index}/_search", params={"ignore_unavailable": "true"}, json=body)
                    try:
                        hits = r.json()["hits"]["hits"]
                    except (ValueError, KeyError, TypeError):
                        raise ConnectorError("BAD_RESPONSE", "indexer response was not a search result")
                    hits_all += hits
                    if len(hits) < PAGE:
                        break
                    search_after = hits[-1].get("sort")
                    if not search_after:
                        break
        except ConnectorError as e:
            self._record(error=e)
            return {"ok": False, "kind": e.kind, "detail": e.detail, "new_events": 0}
        if not self.store.get_dataset(DATASET_ID):
            self.store.create_dataset(DATASET_ID, "Wazuh live alerts", "CONNECTOR:wazuh")
        res = parse_text(json.dumps({"hits": {"hits": hits_all}}), ParseOptions(
            source_key="wazuh", filename="wazuh-indexer", max_events=self.s.wazuh_max_per_poll + PAGE, ingested_at=now_iso()), fmt="json")
        ins, dups = self.store.insert_events(DATASET_ID, res.events)
        newest = max((e["timestamp"] for e in res.events if e.get("timestamp")), default=None)
        new_wm = max([x for x in (newest, wm) if x], default=None)
        self._record(success=True, watermark=new_wm, newest=newest, inserted=ins, received=len(hits_all),
                     rejected=len(res.rejected), unsupported=len(res.unsupported), capped=len(hits_all) >= self.s.wazuh_max_per_poll)
        self.store.audit("connector:wazuh", "poll", DATASET_ID, {"received": len(hits_all), "new": ins, "duplicates": dups})
        return {"ok": True, "kind": "OK", "detail": "poll complete", "received": len(hits_all), "new_events": ins,
                "duplicates": dups, "rejected": len(res.rejected), "unsupported": len(res.unsupported)}

    # ---- state / status
    def _record(self, error: ConnectorError | None = None, success: bool = False, watermark=None, newest=None,
                inserted=0, received=0, rejected=0, unsupported=0, capped=False):
        st = self.store.get_connector_state(CONNECTOR)
        st["last_attempt"] = now_iso()
        if error:
            st.update(last_error={"kind": error.kind, "detail": error.detail, "at": now_iso()})
        if success:
            st["last_success"] = now_iso()
            st["last_error"] = None
            if watermark:
                st["watermark"] = watermark
            if newest:
                st["newest_event_ts"] = max(newest, st.get("newest_event_ts") or "")
            st["events_stored_total"] = st.get("events_stored_total", 0) + inserted
            st["last_poll"] = {"received": received, "new": inserted, "rejected": rejected, "unsupported": unsupported,
                               "capped": capped}
        self.store.set_connector_state(CONNECTOR, st)

    def status(self) -> dict:
        miss = self.missing_config()
        base = {"id": "wazuh", "name": "Wazuh (indexer alerts)", "dataset_id": DATASET_ID if self.store.get_dataset(DATASET_ID) else None,
                "poll_interval_seconds": self.s.wazuh_poll_seconds or None, "live_window_seconds": self.s.wazuh_live_window}
        if miss:
            return {**base, "status": "NOT_CONFIGURED", "live": False, "last_success": None, "last_event": None, "last_error": None,
                    "message": "Wazuh is not configured. Missing: " + ", ".join(miss) + ". File uploads are not live telemetry."}
        st = self.store.get_connector_state(CONNECTOR)
        warn = [] if self.s.wazuh_verify_tls else ["TLS verification is disabled"]
        common = {**base, "last_success": st.get("last_success"), "last_event": st.get("newest_event_ts"),
                  "last_error": st.get("last_error"), "last_poll": st.get("last_poll"), "warnings": warn,
                  "events_stored_total": st.get("events_stored_total", 0)}
        if not st.get("last_attempt"):
            return {**common, "status": "CONFIGURED_NOT_POLLED", "live": False,
                    "message": "Configured but never polled. Run a connection test or poll."}
        age = lambda ts: (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds() if ts else None  # noqa: E731
        if st.get("last_error"):
            return {**common, "status": "ERROR", "live": False,
                    "message": f"Last attempt failed: {st['last_error']['kind']} — {st['last_error']['detail']}"}
        s_age, e_age, w = age(st.get("last_success")), age(st.get("newest_event_ts")), self.s.wazuh_live_window
        if s_age is not None and s_age <= w and e_age is not None and e_age <= w:
            return {**common, "status": "LIVE", "live": True, "message": "Connected; recent alerts are being received."}
        if s_age is not None and s_age <= w:
            return {**common, "status": "CONNECTED_NO_RECENT_EVENTS", "live": False,
                    "message": "Connected, but no alert newer than the live window was received. Not labelled live."}
        return {**common, "status": "STALE", "live": False, "message": "Last successful poll is older than the live window."}
