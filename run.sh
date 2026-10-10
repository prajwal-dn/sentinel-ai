#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
# Binds to localhost by default. Set HOST=0.0.0.0 only together with SENTINEL_API_TOKEN and TLS in front.
exec .venv/bin/uvicorn app.main:create_app --factory --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
