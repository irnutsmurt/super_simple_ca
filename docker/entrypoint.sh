#!/usr/bin/env bash
# Container entrypoint for the SuperSimpleCA web UI.
#   - keeps all state (config, CA data, secrets) on the /data volume
#   - generates config.yaml from env vars on first run
#   - runs the app as the non-root "ssca" user
set -euo pipefail

DATA_DIR="${SSCA_CA_ROOT:-/data}"
CONFIG_PATH="${SUPERSIMPLECA_CONFIG:-$DATA_DIR/config.yaml}"
APP_DIR=/app/webca
RUN_USER=ssca

# 1. Ensure the volume and the instance dir exist. INSTANCE_DIR is hard-coded to
#    <app>/instance, so symlink it onto the volume to persist the Flask secret,
#    the managed TLS cert/key, and the persist-mode key across container restarts.
mkdir -p "$DATA_DIR" "$DATA_DIR/instance"
if [ ! -L "$APP_DIR/instance" ]; then
    rm -rf "$APP_DIR/instance"
fi
ln -sfn "$DATA_DIR/instance" "$APP_DIR/instance"

# 2. First run: write config.yaml from env if none exists yet.
if [ ! -f "$CONFIG_PATH" ]; then
    if [ -z "${SSCA_ADMIN_PASSWORD:-}" ]; then
        echo "[entrypoint] No config at $CONFIG_PATH and SSCA_ADMIN_PASSWORD is unset." >&2
        echo "[entrypoint] Set SSCA_ADMIN_PASSWORD (the web-UI admin password) on first run," >&2
        echo "[entrypoint] then you can remove it from the environment afterwards." >&2
        exit 1
    fi
    echo "[entrypoint] First run: writing $CONFIG_PATH"
    SSCA_CONFIG_PATH="$CONFIG_PATH" SSCA_DATA_DIR="$DATA_DIR" python - <<'PY'
import os, sys
sys.path.insert(0, "/app/webca")
from werkzeug.security import generate_password_hash
import config as c

cfg = dict(c.DEFAULTS)
cfg["ca_root"] = os.environ["SSCA_DATA_DIR"]
cfg["host"] = os.environ.get("SSCA_HOST", "0.0.0.0")
cfg["port"] = int(os.environ.get("SSCA_PORT", "8443"))

cfg["auth"] = dict(cfg["auth"])
cfg["auth"]["password_hash"] = generate_password_hash(os.environ["SSCA_ADMIN_PASSWORD"])

if os.environ.get("SSCA_SECURE_COOKIES", "").lower() in ("1", "true", "yes"):
    cfg["secure_cookies"] = True

sans = os.environ.get("SSCA_WEB_SANS", "").replace(",", " ").split()
if sans:
    cfg["web_tls"] = dict(cfg["web_tls"])
    cfg["web_tls"]["sans"] = sans

c.save_config(cfg, os.environ["SSCA_CONFIG_PATH"])
print("[entrypoint] config written to", os.environ["SSCA_CONFIG_PATH"])
PY
fi

# 3. Make the volume writable by the runtime user (mounts arrive as host-owned).
chown -R "$RUN_USER":"$RUN_USER" "$DATA_DIR" 2>/dev/null || true
chown -h "$RUN_USER":"$RUN_USER" "$APP_DIR/instance" 2>/dev/null || true

# 4. Drop privileges and run the app.
exec gosu "$RUN_USER" "$@"
