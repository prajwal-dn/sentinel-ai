import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app.connectors import WazuhConnector
from app.main import create_app
from app.storage import Store


def hit(i, ts, level=5):
    return {"_id": f"doc{i}", "sort": [ts], "_source": {"timestamp": ts, "rule": {"id": "5710", "level": level, "description": "ssh fail"},
            "agent": {"id": "001", "name": "web-01"}, "data": {"srcip": "203.0.113.7"},
            "full_log": f"Feb 18 08:41:02 web-01 sshd[1]: Failed password for root from 203.0.113.7 port {4000 + i} ssh2"}}


def ts_ago(sec):
    return (datetime.now(timezone.utc) - timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


@pytest.fixture
def wsettings(settings):
    settings.wazuh_url, settings.wazuh_user, settings.wazuh_password = "https://indexer.example:9200", "svc", "pw-secret"
    return settings


def conn(wsettings, store, handler):
    return WazuhConnector(wsettings, store, transport=httpx.MockTransport(handler), sleep=lambda s: None)


def test_not_configured_is_explicit_and_never_live(settings, store):
    c = WazuhConnector(settings, store)
    st = c.status()
    assert st["status"] == "NOT_CONFIGURED" and st["live"] is False and "SENTINEL_WAZUH_INDEXER_URL" in st["message"]
    assert c.poll()["kind"] == "NOT_CONFIGURED" and c.test()["ok"] is False


def test_auth_failure_is_visible_and_not_retried_forever(wsettings, store):
    calls = []
    c = conn(wsettings, store, lambda r: (calls.append(1), httpx.Response(401))[1])
    r = c.poll()
    assert r["ok"] is False and r["kind"] == "AUTH_FAILED" and len(calls) == 1
    st = c.status()
    assert st["status"] == "ERROR" and st["live"] is False and "pw-secret" not in json.dumps(st)


def test_unreachable_retries_then_reports(wsettings, store):
    n = []
    def h(r):
        n.append(1); raise httpx.ConnectError("refused")
    c = conn(wsettings, store, h)
    assert c.poll()["kind"] == "UNREACHABLE" and len(n) == 3
    assert c.status()["status"] == "ERROR"


def test_server_error_then_recovery_within_retries(wsettings, store):
    seq = [httpx.Response(503), httpx.Response(200, json={"hits": {"hits": [hit(1, ts_ago(5))]}})]
    c = conn(wsettings, store, lambda r: seq.pop(0))
    assert c.poll()["ok"] is True


def test_poll_ingests_dedupes_and_reports_live_only_when_recent(wsettings, store):
    payload = {"hits": {"hits": [hit(1, ts_ago(30)), hit(2, ts_ago(20))]}}
    seen = []
    def h(r):
        seen.append(json.loads(r.content) if r.content else None)
        return httpx.Response(200, json=payload)
    c = conn(wsettings, store, h)
    r1 = c.poll()
    assert r1["ok"] and r1["new_events"] == 2
    r2 = c.poll()                                       # overlap re-delivers the same docs
    assert r2["new_events"] == 0 and r2["duplicates"] == 2
    assert store.get_dataset("ds-wazuh")["event_count"] == 2
    assert "range" in json.dumps(seen[1]) and seen[1]["sort"] == [{"timestamp": "asc"}]
    st = c.status()
    assert st["status"] == "LIVE" and st["live"] is True and st["last_success"] and st["last_event"]
    assert store.get_dataset("ds-wazuh")["source_kind"] == "CONNECTOR:wazuh"


def test_old_events_mean_connected_but_not_live(wsettings, store):
    c = conn(wsettings, store, lambda r: httpx.Response(200, json={"hits": {"hits": [hit(1, ts_ago(86400))]}}))
    c.poll()
    st = c.status()
    assert st["status"] == "CONNECTED_NO_RECENT_EVENTS" and st["live"] is False


def test_pagination(wsettings, store):
    pages = [{"hits": {"hits": [hit(i, ts_ago(100 - i % 50)) for i in range(500)]}}, {"hits": {"hits": [hit(900, ts_ago(5))]}}]
    bodies = []
    def h(r):
        bodies.append(json.loads(r.content)); return httpx.Response(200, json=pages.pop(0))
    c = conn(wsettings, store, h)
    assert c.poll()["new_events"] == 501 and "search_after" in bodies[1]


def test_bad_response_shape(wsettings, store):
    c = conn(wsettings, store, lambda r: httpx.Response(200, json={"oops": 1}))
    assert c.poll()["kind"] == "BAD_RESPONSE"


def test_api_surface_and_file_upload_never_labelled_live(wsettings, store):
    from conftest import attack_log, upload
    app = create_app(wsettings, store, http_transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    cl = TestClient(app)
    assert cl.get("/api/connectors").json()["connectors"][0]["status"] == "CONFIGURED_NOT_POLLED"
    assert cl.post("/api/connectors/wazuh/test").json()["kind"] == "AUTH_FAILED"
    assert cl.get("/api/connectors").json()["connectors"][0]["live"] is False
    ds = upload(cl, attack_log(), default_year="2025").json()["dataset_id"]
    assert cl.get(f"/api/datasets/{ds}").json()["source_kind"] == "FILE_UPLOAD"
    iid = cl.post(f"/api/datasets/{ds}/analyze").json()["investigations"][0]["id"]
    assert cl.get(f"/api/investigations/{iid}").json()["source"]["live_telemetry"] is False
