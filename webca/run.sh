#!/usr/bin/env bash
# Start the SuperSimpleCA web UI in its virtualenv.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[*] Creating virtualenv..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi

if [ ! -f config.yaml ]; then
  echo "[!] No config.yaml yet. Run: ./.venv/bin/python setup.py"
  exit 1
fi

exec ./.venv/bin/python app.py
