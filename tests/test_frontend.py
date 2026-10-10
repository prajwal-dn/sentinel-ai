"""Frontend checks: static hygiene always; full jsdom run when node + jsdom are available (set JSDOM_PATH)."""
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


def test_no_demo_flow_or_inline_handlers():
    idx = (STATIC / "index.html").read_text(encoding="utf-8")
    js = (STATIC / "app.js").read_text()
    assert not re.search(r"demo", idx + js, re.I)
    assert not re.search(r"\son[a-z]+\s*=", idx), "inline handlers are blocked by CSP"
    assert "style=" not in idx
    assert "innerHTML" in js and "const esc" in js and "&quot;" in js   # escaper covers quotes


def test_js_syntax():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    subprocess.run([node, "--check", str(STATIC / "app.js")], check=True)


def test_ui_end_to_end(tmp_path):
    node, jsdom = shutil.which("node"), os.environ.get("JSDOM_PATH")
    if not node or not jsdom:
        pytest.skip("set JSDOM_PATH to a jsdom install to run the browser-level smoke test")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    env = {**os.environ, "SENTINEL_DB_PATH": str(tmp_path / "ui.db"), "SENTINEL_LLM_PROVIDER": "none", "PYTHONPATH": str(ROOT)}
    for k in ("SENTINEL_API_TOKEN", "SENTINEL_WAZUH_INDEXER_URL"):
        env.pop(k, None)
    srv = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:create_app", "--factory", "--port", str(port), "--log-level", "warning"], cwd=ROOT, env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); break
            except OSError:
                time.sleep(0.1)
        r = subprocess.run([node, str(ROOT / "tests/frontend/ui_smoke.cjs"), f"http://127.0.0.1:{port}"], capture_output=True, text=True, timeout=90)
        assert r.returncode == 0, r.stdout + r.stderr
    finally:
        srv.terminate(); srv.wait(5)
