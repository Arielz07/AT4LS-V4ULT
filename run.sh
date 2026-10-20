#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  echo "Creating local virtual environment…"
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -e .
fi

if ! .venv/bin/python -c "import fastapi, uvicorn, jinja2, multipart, cryptography" >/dev/null 2>&1; then
  echo "Installing project dependencies…"
  .venv/bin/pip install -e .
fi

HOST="${ATL4S_HOST:-127.0.0.1}"
PORT="${ATL4S_PORT:-8000}"

echo "ATL4S::V4UlT  http://${HOST}:${PORT}"
exec .venv/bin/python -m uvicorn atl4s.main:app --host "$HOST" --port "$PORT"
