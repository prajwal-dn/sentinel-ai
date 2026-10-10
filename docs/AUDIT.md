# Sentinel AI — Phase 1 Audit (baseline commit cf3ae04)

## 1. Architecture (before)
- `app/main.py` (81 lines): FastAPI; in-memory `state` dict loaded at import time from `demo_events()`.
- `app/detector.py` (99 lines): `demo_events()` returns 11 hardcoded SSH/host events (all labelled `source_mode: DEMO`);
  `analyze()` returns a hardcoded incident `INC-2025-0218-001` (severity 96, confidence 0.98, five MITRE rows,
  IOCs, trace and recommendations are literal strings/numbers) and `build_report()` templates it into Markdown.
- `static/` single-page UI: landing page with "Run Demo Investigation", nine nav views all bound to the one demo incident.
- `tests/test_api.py`: 7 tests, all asserting demo constants (11 events, CRITICAL, 0.98, 5 techniques, 6 trace stages).
- Deps: fastapi, uvicorn, httpx (unused), pytest. No DB, no LLM, no parser, no upload endpoint.

## 2. Classification of capabilities
| Capability | Status |
|---|---|
| HTTP API + static serving | Real |
| Approve/reject recording (`NOT_EXECUTED`) | Real, but single-incident, in-memory, no actor/audit trail |
| Truthful Wazuh status ("NOT_CONNECTED") | Real, but a constant — no connector exists |
| Brute-force threshold (>=5 failures) | Rule-based, only over demo data; the rest of the incident is hardcoded |
| Severity 96 / confidence 0.98 / MITRE confidences | **Simulated** — literals |
| IOC list, timeline stages, recommendations, findings | **Simulated** — literals referencing fixed `evt-0xx` IDs |
| "Agent trace" (6 stages) | **Simulated** — static strings; no LLM, no tools, no iteration |
| Report | Template over simulated incident |
| Log ingestion / parsing / persistence | **Missing** |
| LLM provider / agent loop / tools | **Missing** |
| Threat intel, live connector | **Missing** |

## 3. Security weaknesses found
- No authentication on any endpoint; server binds `0.0.0.0` by default (`run.sh`).
- State-changing endpoints (`/approve`, `/reject`, `/demo/reset`) unauthenticated, no actor recorded, no audit log.
- `x()` HTML escaper in `app.js` does not escape quotes (attribute injection risk); several interpolations (`v.finding`, `i.attack_type`, `c.message`) are unescaped.
- Catch-all SPA route returns index for any path (fine) but no security headers / CSP.
- Approval of a *whole incident* with no per-action granularity.
- Nothing yet to validate uploads, untrusted XML, prompt injection, or outbound URLs (features did not exist).

## 4. Recommended sequence (followed in this work)
1. Storage + schema → 2. parsers/ingestion → 3. detection/correlation → 4. LLM agent with scoped tools →
5. MITRE/IOC/report → 6. upload-first UI → 7. Wazuh connector → 8. hardening, tests, docs.
