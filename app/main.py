from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .detector import analyze, demo_events

ROOT = Path(__file__).resolve().parent.parent
app = FastAPI(title="Sentinel AI", version="1.0.0", description="Deterministic SOC incident investigation demo")

state = {"events": demo_events(), "incident": None}
state["incident"] = analyze(state["events"])

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "sentinel-ai", "version": "1.0.0", "source_mode": "DEMO", "safety": "HUMAN_APPROVAL_REQUIRED"}

@app.get("/api/events")
def events():
    return {"source_mode": "DEMO", "demo_notice": "Simulated demonstration data; not live telemetry.", "count": len(state["events"]), "events": state["events"]}

@app.get("/api/incidents")
def incidents():
    i = state["incident"]
    return {"source_mode": "DEMO", "count": 1, "incidents": [{k: deepcopy(i[k]) for k in ("id", "timestamp", "attack_type", "severity", "severity_score", "confidence", "source_mode", "status", "affected_assets", "report_id")}]}

@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str):
    if incident_id != state["incident"]["id"]:
        raise HTTPException(404, "Incident not found")
    return state["incident"]

@app.get("/api/incidents/{incident_id}/report", response_class=PlainTextResponse)
def report(incident_id: str):
    if incident_id != state["incident"]["id"]:
        raise HTTPException(404, "Incident not found")
    i = state["incident"]
    return PlainTextResponse(i["generated_markdown_report"], media_type="text/markdown", headers={"Content-Disposition": f"attachment; filename={i['report_id']}.md", "X-Report-ID": i["report_id"]})

@app.get("/api/mitre")
def mitre():
    techniques = state["incident"]["mitre_techniques"]
    grouped = []
    for tactic in dict.fromkeys(t["tactic"] for t in techniques):
        grouped.append({"tactic": tactic, "techniques": [t for t in techniques if t["tactic"] == tactic]})
    return {"source_mode": "DEMO", "framework": "MITRE ATT&CK Enterprise", "groups": grouped}

@app.get("/api/connectors")
def connectors():
    return {"connectors": [{"id": "wazuh", "name": "Wazuh", "status": "NOT_CONNECTED", "configuration_state": "NOT_CONFIGURED", "last_event": "UNAVAILABLE", "message": "No SIEM connection is configured. Demo events are local and simulated."}]}

@app.post("/api/demo/reset")
def reset_demo():
    state["events"] = demo_events()
    state["incident"] = analyze(state["events"])
    return {"status": "RESET", "source_mode": "DEMO", "incident_id": state["incident"]["id"], "message": "Demo events reloaded and deterministic investigation completed."}

@app.post("/api/incidents/{incident_id}/approve")
def approve(incident_id: str):
    if incident_id != state["incident"]["id"]:
        raise HTTPException(404, "Incident not found")
    state["incident"]["status"] = "APPROVED_FOR_MANUAL_RESPONSE"
    state["incident"]["decision"] = {"decision": "APPROVED", "scope": "RECOMMENDATIONS_ONLY", "execution": "NOT_EXECUTED", "note": "Approval recorded. Sentinel AI does not execute response actions."}
    return {"incident_id": incident_id, "status": state["incident"]["status"], "decision": state["incident"]["decision"]}

@app.post("/api/incidents/{incident_id}/reject")
def reject(incident_id: str):
    if incident_id != state["incident"]["id"]:
        raise HTTPException(404, "Incident not found")
    state["incident"]["status"] = "RESPONSE_REJECTED"
    state["incident"]["decision"] = {"decision": "REJECTED", "execution": "NOT_EXECUTED", "note": "Recommendations rejected; no actions were executed."}
    return {"incident_id": incident_id, "status": state["incident"]["status"], "decision": state["incident"]["decision"]}

app.mount("/assets", StaticFiles(directory=ROOT / "static"), name="assets")

@app.get("/{full_path:path}")
def spa(full_path: str):
    return FileResponse(ROOT / "static" / "index.html")
