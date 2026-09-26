from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
INCIDENT = "INC-2025-0218-001"

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["source_mode"] == "DEMO"

def test_demo_end_to_end():
    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200
    events = client.get("/api/events").json()
    assert events["count"] == 11
    assert all(e["source_mode"] == "DEMO" for e in events["events"])
    incidents = client.get("/api/incidents").json()
    assert incidents["count"] == 1
    incident = client.get(f"/api/incidents/{INCIDENT}").json()
    assert incident["severity"] == "CRITICAL"
    assert incident["confidence"] == 0.98
    assert len(incident["mitre_techniques"]) == 5
    assert len(incident["attack_timeline"]) == 11
    assert incident["threat_intelligence"]["status"] == "UNAVAILABLE"
    assert len(incident["agent_trace"]) == 6
    assert incident["report_id"] in incident["generated_markdown_report"]

def test_mitre_is_grouped_and_evidence_based():
    data = client.get("/api/mitre").json()
    assert len(data["groups"]) == 4
    for group in data["groups"]:
        for tech in group["techniques"]:
            assert tech["tactic"] == group["tactic"]
            assert tech["reason/evidence_basis"]
            assert tech["observed_count"] > 0

def test_connector_is_truthful():
    c = client.get("/api/connectors").json()["connectors"][0]
    assert c == {"id": "wazuh", "name": "Wazuh", "status": "NOT_CONNECTED", "configuration_state": "NOT_CONFIGURED", "last_event": "UNAVAILABLE", "message": "No SIEM connection is configured. Demo events are local and simulated."}

def test_report_download():
    r = client.get(f"/api/incidents/{INCIDENT}/report")
    assert r.status_code == 200
    assert "# Sentinel AI Incident Report" in r.text
    assert "SIMULATED DATA" in r.text
    assert "attachment" in r.headers["content-disposition"]

def test_approval_records_but_does_not_execute():
    r = client.post(f"/api/incidents/{INCIDENT}/approve")
    assert r.status_code == 200
    assert r.json()["decision"]["execution"] == "NOT_EXECUTED"
    r = client.post(f"/api/incidents/{INCIDENT}/reject")
    assert r.status_code == 200
    assert r.json()["decision"]["execution"] == "NOT_EXECUTED"

def test_unknown_incident_404():
    assert client.get("/api/incidents/nope").status_code == 404
