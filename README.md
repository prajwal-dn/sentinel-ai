# Sentinel AI

An evidence-grounded cybersecurity incident response/SOC demo. Sentinel AI deterministically correlates simulated SSH brute-force events with a successful login and suspicious post-authentication activity, then generates an explainable incident, MITRE ATT&CK mapping, timeline, IOCs, recommendations, agent trace, and downloadable report.

> **Demo safety:** Included events are simulated and clearly labelled. No SIEM is connected. The app never executes response actions; approvals are records for human-led response only.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
bash run.sh
```

Open <http://localhost:8000>. Click **Run Demo Investigation**.

## Tests

```bash
.venv/bin/pytest -q
```

## API

- `GET /api/health`
- `GET /api/events`
- `GET /api/incidents`
- `GET /api/incidents/{id}`
- `GET /api/incidents/{id}/report`
- `GET /api/mitre`
- `GET /api/connectors`
- `POST /api/demo/reset`
- `POST /api/incidents/{id}/approve`
- `POST /api/incidents/{id}/reject`

## Architecture

A small FastAPI service serves both the JSON API and a dependency-light HTML/CSS/JavaScript frontend. The deterministic correlation engine in `app/detector.py` cites event IDs for every finding and explicitly marks uncertainty. External threat intelligence is `LOCAL / UNAVAILABLE` until a real provider is configured.
