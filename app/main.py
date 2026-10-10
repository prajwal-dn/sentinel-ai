"""Sentinel AI API. Create with `create_app()`; uvicorn uses the factory: `uvicorn app.main:create_app --factory`."""
from __future__ import annotations

import asyncio
import re
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .agent import merge_agent_recommendations, run_agent
from .analysis import analyze_dataset
from .config import Settings, get_settings
from .connectors import WazuhConnector
from .detection import DetectionConfig
from .ingest import IngestError, ingest_bytes
from .intel import enrich, intel_status
from .llm import build_provider, llm_status
from .parsers import SUPPORTED_FORMATS
from .reports import build_report
from .storage import Store

ROOT = Path(__file__).resolve().parent.parent
ID_RX = re.compile(r"^[A-Za-z0-9._\-]{1,80}$")


class AgentRequest(BaseModel):
    objective: str | None = Field(default=None, max_length=500)


class DecisionRequest(BaseModel):
    decision: str = Field(pattern="^(APPROVED|REJECTED)$")
    note: str | None = Field(default=None, max_length=1000)


def create_app(settings: Settings | None = None, store: Store | None = None, provider_factory: Callable | None = None,
               http_transport=None) -> FastAPI:
    settings = settings or get_settings()
    store = store or Store(settings.db_path)
    provider_factory = provider_factory or (lambda s: build_provider(s))
    wazuh = WazuhConnector(settings, store, transport=http_transport)
    stop = threading.Event()

    def poll_loop():
        while not stop.wait(settings.wazuh_poll_seconds):
            try:
                wazuh.poll()
            except Exception:  # noqa: BLE001 - never let the poller thread die
                pass

    @asynccontextmanager
    async def lifespan(app):
        if settings.wazuh_poll_seconds > 0 and not wazuh.missing_config():
            threading.Thread(target=poll_loop, daemon=True, name="wazuh-poller").start()
        yield
        stop.set()

    app = FastAPI(title="Sentinel AI", version=__version__, lifespan=lifespan,
                  description="AI-assisted security log investigation. File uploads are NOT live telemetry.")
    app.state.settings, app.state.store, app.state.wazuh = settings, store, wazuh

    # ---------------------------------------------------------------- security middleware
    @app.middleware("http")
    async def guard(request: Request, call_next):
        p = request.url.path
        if p.startswith("/api/") and p != "/api/health" and settings.api_token:
            auth = request.headers.get("authorization", "")
            ok = auth.lower().startswith("bearer ") and secrets.compare_digest(auth[7:].strip(), settings.api_token)
            if not ok:
                return JSONResponse({"detail": "Authentication required"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
        resp = await call_next(request)
        resp.headers.update({
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                       "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        if p.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def actor(request: Request) -> str:
        who = re.sub(r"[^A-Za-z0-9._@ \-]", "", request.headers.get("x-analyst", ""))[:40]
        return who or ("api-token-user" if settings.api_token else "local-analyst")

    def need_ds(ds_id: str) -> dict:
        if not ID_RX.match(ds_id) or not (ds := store.get_dataset(ds_id)):
            raise HTTPException(404, "Dataset not found")
        return ds

    def need_inv(inv_id: str) -> dict:
        if not ID_RX.match(inv_id) or not (inv := store.get_investigation(inv_id)):
            raise HTTPException(404, "Investigation not found")
        return inv

    def view(inv: dict) -> dict:
        decs = store.decisions(inv["id"])
        latest = {d["recommendation_id"]: d for d in decs}
        out = dict(inv)
        out["recommendations"] = [{**r, "latest_decision": latest.get(r["recommendation_id"])} for r in inv["recommendations"]]
        out["decisions"] = decs
        out["status"] = "DECISIONS_RECORDED" if decs else "OPEN"
        return out

    # ---------------------------------------------------------------- status
    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "sentinel-ai", "version": __version__,
                "auth": "ENABLED" if settings.api_token else "DISABLED",
                "response_actions": "HUMAN_APPROVAL_REQUIRED_NO_EXECUTORS_CONFIGURED"}

    @app.get("/api/status")
    def status():
        datasets = store.list_datasets()
        invs = store.list_investigations()
        return {"version": __version__, "auth": "ENABLED" if settings.api_token else "DISABLED",
                "llm": llm_status(settings), "threat_intel": intel_status(settings), "connectors": [wazuh.status()],
                "supported_formats": SUPPORTED_FORMATS,
                "limits": {"max_upload_mb": settings.max_upload_bytes // (1024 * 1024),
                           "max_events_per_upload": settings.max_events_per_upload},
                "counts": {"datasets": len(datasets), "events": sum(d["event_count"] for d in datasets),
                           "investigations": len(invs)},
                "agent": {"max_steps": settings.agent_max_steps, "deadline_seconds": settings.agent_deadline}}

    @app.get("/api/connectors")
    def connectors():
        return {"connectors": [wazuh.status()]}

    @app.post("/api/connectors/wazuh/test")
    def wazuh_test(request: Request):
        r = wazuh.test()
        store.audit(actor(request), "connector_test", "wazuh", {"ok": r["ok"], "kind": r["kind"]})
        return r

    @app.post("/api/connectors/wazuh/poll")
    def wazuh_poll(request: Request):
        r = wazuh.poll()
        store.audit(actor(request), "connector_poll", "wazuh", {"ok": r["ok"], "kind": r["kind"]})
        return r

    @app.get("/api/config/detection")
    def detection_cfg():
        return DetectionConfig.load(settings.detection_config).as_dict()

    @app.get("/api/audit")
    def audit(limit: int = 200):
        return {"entries": store.audit_log(max(1, min(limit, 1000)))}

    # ---------------------------------------------------------------- ingestion
    @app.post("/api/ingest")
    async def ingest(request: Request, file: UploadFile = File(...), dataset_id: str | None = Form(None),
                     dataset_name: str | None = Form(None), default_year: int | None = Form(None)):
        chunks, size = [], 0
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.max_upload_bytes:
                raise HTTPException(413, f"File exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB upload limit.")
            chunks.append(chunk)
        if dataset_id and not ID_RX.match(dataset_id):
            raise HTTPException(404, "Dataset not found")
        try:
            res = await asyncio.to_thread(ingest_bytes, store, settings, b"".join(chunks), file.filename, dataset_id,
                                          dataset_name, default_year, actor(request))
        except IngestError as e:
            raise HTTPException(e.status, e.message)
        code = 200 if res["summary"]["status"] in ("SUCCESS", "PARTIAL") else 422
        return JSONResponse(res, status_code=code)

    @app.get("/api/datasets")
    def datasets():
        return {"datasets": store.list_datasets()}

    @app.get("/api/datasets/{ds_id}")
    def dataset(ds_id: str):
        return need_ds(ds_id)

    @app.delete("/api/datasets/{ds_id}")
    def delete_dataset(ds_id: str, request: Request):
        need_ds(ds_id)
        store.delete_dataset(ds_id)
        store.audit(actor(request), "delete_dataset", ds_id)
        return {"deleted": ds_id}

    @app.get("/api/datasets/{ds_id}/events")
    def events(ds_id: str, host: str | None = None, username: str | None = None, src_ip: str | None = None,
               dst_ip: str | None = None, category: str | None = None, action: str | None = None,
               outcome: str | None = None, text: str | None = None, start: str | None = None, end: str | None = None,
               limit: int = 100, offset: int = 0):
        need_ds(ds_id)
        total, evs = store.search_events(ds_id, {"host": host, "username": username, "src_ip": src_ip, "dst_ip": dst_ip,
                                                 "category": category, "action": action, "outcome": outcome},
                                         text, start, end, limit, offset)
        return {"dataset_id": ds_id, "total": total, "count": len(evs), "events": evs}

    @app.get("/api/datasets/{ds_id}/events/{event_id}")
    def event(ds_id: str, event_id: str):
        need_ds(ds_id)
        got = store.get_events(ds_id, [event_id])
        if not got:
            raise HTTPException(404, "Event not found")
        return got[0]

    # ---------------------------------------------------------------- investigations
    @app.post("/api/datasets/{ds_id}/analyze")
    def analyze(ds_id: str, request: Request):
        ds = need_ds(ds_id)
        if ds["event_count"] == 0:
            raise HTTPException(422, "Dataset has no events; nothing to investigate.")
        invs = analyze_dataset(store, settings, ds_id, actor(request))
        return {"dataset_id": ds_id, "investigations": [_brief(i) for i in invs], "count": len(invs),
                "message": "No suspicious patterns were detected by the configured rules." if not invs else
                           "Rule-based analysis complete. AI investigation has not been run."}

    @app.get("/api/investigations")
    def investigations(dataset_id: str | None = None):
        return {"investigations": [_brief(i) for i in store.list_investigations(dataset_id)]}

    @app.get("/api/investigations/{inv_id}")
    def investigation(inv_id: str):
        return view(need_inv(inv_id))

    @app.post("/api/investigations/{inv_id}/agent")
    def agent(inv_id: str, body: AgentRequest, request: Request):
        inv = need_inv(inv_id)
        provider = None
        try:
            provider = provider_factory(settings)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(503, f"LLM provider could not be initialised: {exc}")
        if provider is None:
            raise HTTPException(503, llm_status(settings)["message"])
        run = run_agent(store, settings, provider, inv, body.objective)
        inv["agent"] = run
        merge_agent_recommendations(inv, run)
        store.save_investigation(inv)
        store.audit(actor(request), "agent_run", inv_id, {"status": run["status"], "steps": run["steps_used"],
                                                          "provider": run["provider"], "model": run["model"]})
        return view(inv)

    @app.post("/api/investigations/{inv_id}/enrich")
    def enrich_ep(inv_id: str, request: Request):
        inv = need_inv(inv_id)
        enrich(inv, settings, http_transport)
        store.save_investigation(inv)
        store.audit(actor(request), "enrich", inv_id, {"provider": intel_status(settings)["provider"]})
        return view(inv)

    @app.get("/api/investigations/{inv_id}/report", response_class=PlainTextResponse)
    def report(inv_id: str):
        inv = need_inv(inv_id)
        md = build_report(view(inv), store.decisions(inv_id))
        return PlainTextResponse(md, media_type="text/markdown; charset=utf-8",
                                 headers={"Content-Disposition": f'attachment; filename="{inv_id}-report.md"'})

    @app.post("/api/investigations/{inv_id}/recommendations/{rec_id}/decision")
    def decide(inv_id: str, rec_id: str, body: DecisionRequest, request: Request):
        inv = need_inv(inv_id)
        if not any(r["recommendation_id"] == rec_id for r in inv["recommendations"]):
            raise HTTPException(404, "Recommendation not found")
        d = store.add_decision(inv_id, rec_id, body.decision, actor(request), body.note, "NOT_EXECUTED",
                               "No response integration is configured. The decision is recorded only; "
                               "any action must be carried out manually by an authorised person.")
        store.audit(actor(request), "decision", inv_id, {"recommendation": rec_id, "decision": body.decision})
        return d

    @app.get("/api/investigations/{inv_id}/decisions")
    def decisions(inv_id: str):
        need_inv(inv_id)
        return {"decisions": store.decisions(inv_id)}

    @app.get("/api/mitre")
    def mitre(dataset_id: str | None = None):
        rows = {}
        for inv in store.list_investigations(dataset_id):
            for m in inv["mitre"] + [dict(x, bases=[x["basis"]]) for x in inv.get("mitre_ai", [])]:
                k = (m["technique_id"], m.get("origin", "RULE"))
                d = rows.setdefault(k, {**m, "origin": m.get("origin", "RULE"), "investigations": []})
                d["investigations"].append(inv["id"])
        groups: dict[str, list] = {}
        for m in rows.values():
            groups.setdefault(m.get("tactic") or "Unmapped tactic", []).append(m)
        return {"framework": "MITRE ATT&CK Enterprise", "groups": [{"tactic": k, "techniques": v} for k, v in groups.items()]}

    # ---------------------------------------------------------------- static UI
    app.mount("/assets", StaticFiles(directory=ROOT / "static"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "Not found")
        return FileResponse(ROOT / "static" / "index.html")

    return app


def _brief(i: dict) -> dict:
    a = i.get("agent") or {}
    return {"id": i["id"], "dataset_id": i["dataset_id"], "title": i["title"], "severity": i["severity"],
            "findings": len(i["findings"]), "first_seen": i["case"]["first_seen"], "last_seen": i["case"]["last_seen"],
            "hosts": i["case"]["hosts"], "attack_chain": i["case"]["attack_chain"], "analysis_mode": i["analysis_mode"],
            "agent_status": a.get("status", "NOT_RUN"),
            "ai_assessment": (a.get("result") or {}).get("assessment"), "updated_at": i.get("updated_at")}
