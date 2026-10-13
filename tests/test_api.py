import os
from conftest import upload, attack_log


def test_health_and_empty_state(client):
    assert client.get("/api/health").json()["status"] == "ok"
    st = client.get("/api/status").json()
    assert st["counts"] == {"datasets": 0, "events": 0, "investigations": 0}
    assert st["llm"]["status"] == "NOT_CONFIGURED" and st["connectors"][0]["status"] == "NOT_CONFIGURED"
    assert client.get("/api/investigations").json()["investigations"] == []
    assert client.get("/api/mitre").json()["groups"] == []
    assert client.get("/api/incidents").status_code == 404                # demo endpoints are gone
    assert client.post("/api/demo/reset").status_code in (404, 405)


def test_analyze_empty_or_unknown_dataset(client):
    assert client.post("/api/datasets/ds-none/analyze").status_code == 404


def test_api_token_required_when_configured(make_client):
    c = make_client(api_token="s3cret-token")
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/status").status_code == 401
    assert c.get("/api/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/status", headers={"Authorization": "Bearer s3cret-token"}).status_code == 200
    assert c.post("/api/ingest", files={"file": ("a.log", b"x")}).status_code == 401


def test_security_headers_and_unknown_api_404(client):
    r = client.get("/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and "default-src 'self'" in r.headers["content-security-policy"]
    assert "https://fonts.googleapis.com" in r.headers["content-security-policy"]
    assert "https://fonts.gstatic.com" in r.headers["content-security-policy"]
    assert client.get("/api/nope").status_code == 404
    assert client.get("/api/../../etc/passwd").status_code in (404, 200)    # SPA fallback, never a file read
    assert "root:" not in client.get("/assets/..%2f..%2fetc/passwd").text


def test_landing_page_and_app_routes(client):
    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "Enter Command Center" in r_root.text
    assert "sentinel-particles.mp4" in r_root.text

    r_home = client.get("/assets/home.html")
    assert r_home.status_code == 200
    assert "Enter Command Center" in r_home.text

    r_app = client.get("/app")
    assert r_app.status_code == 200
    assert 'id="soc"' in r_app.text
    assert "/assets/app.js" in r_app.text

    r_app_deep = client.get("/app/overview")
    assert r_app_deep.status_code == 200
    assert 'id="soc"' in r_app_deep.text

    assert client.get("/assets/home.css").status_code == 200
    assert client.get("/assets/home.js").status_code == 200
    assert client.get("/assets/sentinel-particles-poster.jpg").status_code == 200


def test_report_generated_from_real_results(analyzed):
    client, ds, iid = analyzed
    r = client.get(f"/api/investigations/{iid}/report")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    t = r.text
    assert iid in t and "203.0.113.50" in t and "NO — analysis of uploaded file" in t
    assert "INC-2025-0218-001" not in t and "SIMULATED" not in t
    assert "No AI investigation has been completed" in t
    for sec in ("Incident summary", "Investigation scope", "Source and ingestion", "Findings", "Attack timeline",
                "Indicators of compromise", "MITRE ATT&CK mapping", "Investigation steps", "Alternative explanations", "Recommended actions"):
        assert sec in t


def test_report_neutralises_markdown_injection(client):
    log = "\n".join(f"Feb 18 08:41:{s:02d} h sshd[1]: Failed password for <script>x</script>|`evil` from 203.0.113.9 port 4{s} ssh2" for s in range(1, 8))
    ds = upload(client, log, default_year="2025").json()["dataset_id"]
    iid = client.post(f"/api/datasets/{ds}/analyze").json()["investigations"][0]["id"]
    t = client.get(f"/api/investigations/{iid}/report").text
    assert "<script>" not in t


def test_approval_is_a_record_not_an_execution(analyzed):
    client, ds, iid = analyzed
    inv = client.get(f"/api/investigations/{iid}").json()
    rec = next(r for r in inv["recommendations"] if r["disruptive"])
    r = client.post(f"/api/investigations/{iid}/recommendations/{rec['recommendation_id']}/decision",
                    json={"decision": "APPROVED", "note": "ok"}, headers={"X-Analyst": "prajwal"})
    d = r.json()
    assert r.status_code == 200 and d["decision"] == "APPROVED" and d["actor"] == "prajwal"
    assert d["execution_status"] == "NOT_EXECUTED" and "recorded only" in d["execution_detail"]
    after = client.get(f"/api/investigations/{iid}").json()
    assert after["status"] == "DECISIONS_RECORDED"
    assert next(x for x in after["recommendations"] if x["recommendation_id"] == rec["recommendation_id"])["latest_decision"]["decision"] == "APPROVED"
    assert "APPROVED" in client.get(f"/api/investigations/{iid}/report").text
    assert any(a["action"] == "decision" for a in client.get("/api/audit").json()["entries"])


def test_decision_validation(analyzed):
    client, ds, iid = analyzed
    rid = client.get(f"/api/investigations/{iid}").json()["recommendations"][0]["recommendation_id"]
    assert client.post(f"/api/investigations/{iid}/recommendations/{rid}/decision", json={"decision": "EXECUTE"}).status_code == 422
    assert client.post(f"/api/investigations/{iid}/recommendations/REC-nope/decision", json={"decision": "REJECTED"}).status_code == 404
    assert client.post("/api/investigations/INV-nope/recommendations/x/decision", json={"decision": "REJECTED"}).status_code == 404


def test_delete_dataset_removes_everything(analyzed):
    client, ds, iid = analyzed
    assert client.delete(f"/api/datasets/{ds}").status_code == 200
    assert client.get(f"/api/datasets/{ds}").status_code == 404
    assert client.get(f"/api/investigations/{iid}").status_code == 404
    assert client.get("/api/status").json()["counts"]["events"] == 0
    assert any(a["action"] == "delete_dataset" for a in client.get("/api/audit").json()["entries"])


def test_mitre_endpoint_aggregates_real_results(analyzed):
    client, ds, iid = analyzed
    g = client.get("/api/mitre").json()["groups"]
    tactics = {x["tactic"] for x in g}
    assert {"Credential Access", "Initial Access", "Persistence", "Command and Control"} <= tactics


def test_persistence_across_restart(tmp_path, settings):
    from app.main import create_app
    from app.storage import Store
    from fastapi.testclient import TestClient
    p = str(tmp_path / "s.db")
    c1 = TestClient(create_app(settings, Store(p)))
    ds = upload(c1, attack_log(), default_year="2025").json()["dataset_id"]
    c2 = TestClient(create_app(settings, Store(p)))
    assert c2.get(f"/api/datasets/{ds}").json()["event_count"] == 11
