# 🛡️ Sentinel AI

**AI-assisted security log investigation. Evidence in, traceable findings out. Humans stay in control.**

Sentinel AI ingests real security logs, detects suspicious patterns with transparent rules, correlates them into cases,
and (optionally) lets an LLM-driven agent investigate each case using a small set of read-only tools. Every finding
cites the source events it came from. It never executes response actions.

> **File uploads are not live telemetry.** The UI says so everywhere. "LIVE" appears only when the Wazuh connector is
> actually receiving recent alerts.

## Investigation workflow

**Observe -> Analyze -> Correlate -> Map -> Assess -> Recommend -> Report**

Sentinel AI correlates security events into cases, extracts indicators of compromise (IOCs), reconstructs timelines, maps observed behavior to MITRE ATT&CK, assesses severity and confidence, and generates investigation reports. Findings should be checked against cited events. AI recommendations do not execute response actions; humans remain in control.

## What is real, what is optional

| Capability | Status |
|---|---|
| Upload + parse syslog/auth.log, JSON, JSONL, Wazuh alert JSON, Windows XML/JSON | Implemented, tested |
| Normalised event store (SQLite), stable event IDs, ingestion summary with rejected/unsupported counts | Implemented, tested |
| Rule detections (brute force, spray, success-after-failures, account creation, authorized_keys, suspicious ports, Windows log clear/service/task/group, SIEM high-level alerts) | Implemented, tested |
| Correlation into cases with recorded reasons; severity escalation rules | Implemented, tested |
| MITRE ATT&CK mapping with `OBSERVED` / `SUSPECTED` status and cited basis | Implemented, tested |
| Local IOC extraction; threat-intel enrichment | Extraction implemented; enrichment **off** unless `SENTINEL_ABUSEIPDB_KEY` is set |
| LLM investigation agent (bounded, tool-using, validated) | Implemented and tested with a scripted model; **needs your LLM credentials** and has not been run against a real model by the authors of this change |
| Markdown reports from stored results | Implemented, tested |
| Per-recommendation approve/reject records with audit log | Implemented, tested. **No executors exist**: approval ≠ execution |
| Wazuh connector (indexer API) | Implemented and tested against mocked responses only; **not yet verified against a real Wazuh deployment** |

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
bash run.sh                    # http://127.0.0.1:8000  (binds to localhost by default)
```

1. Open the app → **Ingest logs** → upload a log file (add the correct *year* for syslog files, which carry none).
2. Read the ingestion result (accepted / rejected / unsupported, caveats), then press **Analyze**.
3. Open a case: findings, timeline, correlation reasoning, IOCs, MITRE mappings, recommendations. Click any event ID to see the original record.
4. (Optional) **Run AI investigation** if an LLM is configured. Download the **report**.

## Configuration (environment variables)

| Variable | Purpose | Default |
|---|---|---|
| `SENTINEL_DB_PATH` | SQLite file | `data/sentinel.db` |
| `SENTINEL_API_TOKEN` | If set, every `/api/*` call except `/api/health` needs `Authorization: Bearer <token>`. **Set this before binding to anything but localhost.** | unset (auth disabled, reported in UI) |
| `SENTINEL_MAX_UPLOAD_MB`, `SENTINEL_MAX_EVENTS_PER_UPLOAD` | upload limits | 25, 200000 |
| `SENTINEL_LLM_PROVIDER` | `anthropic`, `openai` (any OpenAI-compatible endpoint), or `none` | `none` |
| `SENTINEL_LLM_MODEL` | model identifier (required; no default is assumed) | – |
| `SENTINEL_LLM_API_KEY` | provider key | – |
| `SENTINEL_LLM_BASE_URL` | OpenAI-compatible base URL (https, or http for localhost) | OpenAI |
| `SENTINEL_LLM_TIMEOUT`, `SENTINEL_AGENT_MAX_STEPS`, `SENTINEL_AGENT_DEADLINE` | per-call timeout (s), max agent steps, total deadline (s) | 60, 8, 240 |
| `SENTINEL_WAZUH_INDEXER_URL`, `SENTINEL_WAZUH_USER`, `SENTINEL_WAZUH_PASSWORD` | Wazuh **indexer** (OpenSearch) access, read-only account recommended | unset |
| `SENTINEL_WAZUH_VERIFY_TLS`, `SENTINEL_WAZUH_CA_BUNDLE`, `SENTINEL_WAZUH_INDEX` | TLS verification (default on), CA file, index pattern | true, –, `wazuh-alerts-*` |
| `SENTINEL_WAZUH_POLL_SECONDS` | background polling interval (0 = manual polling only) | 0 |
| `SENTINEL_WAZUH_LIVE_WINDOW_SECONDS` | how recent the last poll *and* newest alert must be to show LIVE | 900 |
| `SENTINEL_ABUSEIPDB_KEY` | enables optional, analyst-triggered IP enrichment | unset |
| `SENTINEL_DETECTION_CONFIG` | JSON file overriding detection thresholds (see `GET /api/config/detection`) | built-in |

Credentials are read only from the environment, never stored in the database, never returned by the API.

## Supported log formats

`syslog` (RFC3164 incl. `/var/log/auth.log`, `/var/log/secure`; ISO-timestamp rsyslog; RFC5424) · `jsonl`/`json` (generic with ECS-style
field aliases, Wazuh alert exports and indexer hits, Windows JSON) · `windows_xml` (Event Log XML export; DOCTYPE/ENTITY refused).
Classified Windows IDs: 4624, 4625, 4648, 4672, 4688, 4697/7045, 4698, 4720, 4728/4732/4756, 1102. Other IDs are stored as *unclassified*.
Binary `.evtx` is **not** supported — export to XML/JSON.

## How the agent works (and its limits)

The model must answer each turn with one JSON object: call one of six approved read-only tools
(`get_case_overview`, `get_events`, `search_events`, `count_events`, `get_context`, `lookup_indicator`) or give a final result.
Tool output is scoped to the case's dataset, size-capped, and wrapped as untrusted data. Hard limits: step cap, total deadline,
per-call timeout, ≤2 invalid replies. The final result is schema-validated; evidence IDs not present in the dataset are removed,
`SUPPORTED` claims without valid evidence are downgraded, MITRE claims without evidence are dropped, disruptive recommendations
are forced to require approval. If the provider fails or times out, the case keeps its rule-based findings and the run is shown as failed.

**Severity vs confidence:** *severity* is assigned by rules (basis shown per finding/case). *Confidence* is only produced by the agent
(LOW/MEDIUM/HIGH with a rationale) and is displayed separately.

## API (all under `/api`)

`GET health` · `GET status` · `POST ingest` (multipart `file`, optional `dataset_id`, `dataset_name`, `default_year`) · `GET datasets` ·
`GET|DELETE datasets/{id}` · `GET datasets/{id}/events[?host&username&src_ip&action&text&start&end&limit&offset]` · `GET datasets/{id}/events/{event_id}` ·
`POST datasets/{id}/analyze` · `GET investigations` · `GET investigations/{id}` · `POST investigations/{id}/agent` · `POST investigations/{id}/enrich` ·
`GET investigations/{id}/report` · `POST investigations/{id}/recommendations/{rec_id}/decision` · `GET mitre` · `GET connectors` ·
`POST connectors/wazuh/test|poll` · `GET audit` · `GET config/detection`. Interactive docs at `/docs`.

## Security notes

Uploads are size/type/format validated, never written to disk or executed; XML with DTDs/entities is refused; all SQL is parameterised;
the UI escapes every dynamic value and runs under a strict CSP (no inline scripts/styles); reports neutralise log-derived markdown/HTML;
the only outbound requests are to the configured LLM endpoint, the configured Wazuh indexer, and (on explicit request) AbuseIPDB —
there are no user-supplied URLs. Prompt injection inside logs is mitigated by tool scoping, read-only tools, untrusted-data wrapping and
output validation, **not eliminated**: always review AI output against the cited events. Audit log records ingestion, analysis, agent runs,
decisions and deletions. Delete a dataset to remove its events, cases and decisions. Not production-ready: single-process SQLite, one shared
bearer token (no per-user accounts or roles), no TLS termination, no encryption at rest.

## Known limitations

- Syslog has no year/timezone: the year is user-supplied and zone is assumed UTC (flagged in the ingestion result).
- Detection coverage is limited to the rules listed; it cannot detect what the logs do not record (e.g. no process telemetry → no execution findings).
- Port watch-list and sudo patterns are heuristics. Correlation by IP/host/account/time can merge unrelated activity on busy hosts; reasons are shown so analysts can judge.
- Wazuh polling uses a timestamp watermark with overlap; events sharing an identical timestamp across a page boundary are re-checked on the next poll (deduplicated by indexer `_id`). Alerts are read from the indexer, not the manager API.
- AI agent is synchronous per request (up to the deadline). Only Anthropic and OpenAI-compatible HTTP APIs are implemented.

## Tests

```bash
.venv/bin/python -m pytest -q                         # 70+ tests, all offline (LLM, Wazuh, AbuseIPDB mocked)
JSDOM_PATH=/path/to/node_modules/jsdom .venv/bin/python -m pytest tests/test_frontend.py   # + browser-level UI run
```
Synthetic logs exist only under `tests/`. To verify real integrations, set the env vars above and use *Test connection* (Wazuh) or
*Run AI investigation* (LLM) from the UI; these are intentionally not part of the automated suite.
