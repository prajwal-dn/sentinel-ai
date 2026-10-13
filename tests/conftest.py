"""Synthetic fixtures live ONLY here (tests). The production app contains no sample data."""
import json
import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.storage import Store

SRC = "203.0.113.50"  # TEST-NET-3 documentation address


def ssh_fail(sec, user, ip=SRC, host="web-01", mm=41):
    return f"Feb 18 08:{mm:02d}:{sec:02d} {host} sshd[1]: Failed password for {user} from {ip} port {40000 + sec} ssh2"


def attack_log() -> str:
    L = [ssh_fail(2, "admin"), ssh_fail(10, "root"), ssh_fail(20, "deploy"), ssh_fail(30, "deploy"), ssh_fail(40, "deploy", ),
         ssh_fail(50, "deploy"), ssh_fail(5, "deploy", mm=42)]
    L += [f"Feb 18 08:42:31 web-01 sshd[2]: Accepted password for deploy from {SRC} port 50000 ssh2",
          "Feb 18 08:43:07 web-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m svc-x",
          "Feb 18 08:43:19 web-01 auditd[9]: Created /home/svc-x/.ssh/authorized_keys by uid=1002",
          "Feb 18 08:44:03 web-01 netflow[3]: Outbound TCP connection to 198.51.100.77:4444, 100 bytes"]
    return "\n".join(L) + "\n"


def benign_log() -> str:
    return "\n".join([
        "Feb 18 09:00:01 web-01 sshd[1]: Accepted publickey for alice from 10.0.0.5 port 50001 ssh2",
        "Feb 18 09:05:01 web-01 sshd[1]: Failed password for alice from 10.0.0.5 port 50002 ssh2",
        "Feb 18 09:05:09 web-01 sshd[1]: Accepted password for alice from 10.0.0.5 port 50003 ssh2"]) + "\n"


class ScriptedProvider:
    """Deterministic stand-in for an LLM: returns scripted replies (str) or raises scripted exceptions."""
    name, model = "scripted", "test-model"

    def __init__(self, script):
        self.script, self.calls = list(script), []

    def complete(self, system, messages, max_tokens=2000):
        self.calls.append(messages)
        item = self.script.pop(0) if self.script else json.dumps({"action": "tool", "tool": "get_case_overview", "arguments": {}, "rationale": "loop"})
        if isinstance(item, Exception):
            raise item
        return item if isinstance(item, str) else json.dumps(item)


@pytest.fixture
def settings():
    return Settings(db_path=":memory:", api_token=None, llm_provider="none", llm_model=None, llm_api_key=None,
                    wazuh_url=None, wazuh_user=None, wazuh_password=None, abuseipdb_key=None, detection_config=None,
                    agent_max_steps=6, wazuh_poll_seconds=0)


@pytest.fixture
def store():
    return Store(":memory:")


@pytest.fixture
def make_client(settings, store):
    def _mk(provider=None, **overrides):
        for k, v in overrides.items():
            setattr(settings, k, v)
        transport = overrides.pop("_t", None)
        app = create_app(settings, store, provider_factory=(lambda s: provider), http_transport=getattr(settings, "_transport", None))
        return TestClient(app)
    return _mk


@pytest.fixture
def client(make_client):
    return make_client()


def upload(client, text, name="auth.log", **data):
    return client.post("/api/ingest", files={"file": (name, text.encode() if isinstance(text, str) else text)}, data=data)


@pytest.fixture
def analyzed(client):
    r = upload(client, attack_log(), default_year="2025")
    assert r.status_code == 200, r.text
    ds = r.json()["dataset_id"]
    a = client.post(f"/api/datasets/{ds}/analyze").json()
    return client, ds, a["investigations"][0]["id"]
