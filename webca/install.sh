#!/usr/bin/env bash
#
# install.sh — deploy the SuperSimpleCA web UI as a hardened systemd service.
#
# What it does:
#   1. Figures out its own directory (the webca app) and the CA data root.
#   2. Creates a dedicated system service account (no login, no shell).
#   3. Creates the Python virtualenv and installs dependencies.
#   4. Hands ownership of the CA tree to the service account and tightens perms.
#   5. Installs, enables (and optionally starts) the systemd unit.
#
# Usage:
#   sudo ./install.sh                 # install (interactive confirmation)
#   sudo ./install.sh -y              # install without the confirmation prompt
#   sudo ./install.sh uninstall       # stop, disable and remove the service
#
# Override defaults with env vars:
#   SERVICE_NAME=supersimpleca  SERVICE_USER=<name>  CA_ROOT=<path>  START=1
#
set -euo pipefail

# --- resolve locations -------------------------------------------------------
APP_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
SERVICE_NAME="${SERVICE_NAME:-supersimpleca}"
SERVICE_USER="${SERVICE_USER:-$SERVICE_NAME}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"

# CA data root: honour config.yaml's ca_root if set, else the parent of webca.
default_ca_root="$(dirname "$APP_DIR")"
if [ -z "${CA_ROOT:-}" ] && [ -f "$APP_DIR/config.yaml" ] && command -v python3 >/dev/null; then
  CA_ROOT="$(python3 - "$APP_DIR/config.yaml" <<'PY' 2>/dev/null || true
import sys, yaml, os
d = yaml.safe_load(open(sys.argv[1])) or {}
r = d.get("ca_root")
print(os.path.abspath(r) if r else "")
PY
)"
fi
CA_ROOT="${CA_ROOT:-$default_ca_root}"
[ -n "$CA_ROOT" ] || CA_ROOT="$default_ca_root"

require_root() { [ "$(id -u)" -eq 0 ] || { echo "This script must be run as root (use sudo)." >&2; exit 1; }; }

# --- uninstall ---------------------------------------------------------------
if [ "${1:-}" = "uninstall" ]; then
  require_root
  echo "Uninstalling service '$SERVICE_NAME'..."
  systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable --now "${SERVICE_NAME}-tick.timer" 2>/dev/null || true
  rm -f "$UNIT_PATH" "/etc/systemd/system/${SERVICE_NAME}-tick.service" \
        "/etc/systemd/system/${SERVICE_NAME}-tick.timer"
  systemctl daemon-reload
  echo "Removed $UNIT_PATH and stopped the service."
  echo "The service account '$SERVICE_USER' and the data in '$CA_ROOT' were left in place."
  echo "To remove the account too:  sudo userdel $SERVICE_USER"
  exit 0
fi

require_root

ASSUME_YES=0
[ "${1:-}" = "-y" ] && ASSUME_YES=1

# --- plan --------------------------------------------------------------------
cat <<EOF

SuperSimpleCA — service install plan
------------------------------------
  App directory   : $APP_DIR
  CA data root    : $CA_ROOT
  Service name    : $SERVICE_NAME
  Service account : $SERVICE_USER  (system user, $NOLOGIN)
  systemd unit    : $UNIT_PATH

This will:
  • create the system account '$SERVICE_USER' if missing
  • create $APP_DIR/.venv and install requirements
  • chown -R '$SERVICE_USER' the CA data root and tighten permissions
  • install and enable the systemd service

EOF
if [ "$ASSUME_YES" -ne 1 ]; then
  read -r -p "Proceed? [y/N] " ans
  case "$ans" in y|Y|yes|YES) ;; *) echo "Aborted."; exit 0 ;; esac
fi

# --- 1. service account ------------------------------------------------------
if id "$SERVICE_USER" >/dev/null 2>&1; then
  echo "[*] Service account '$SERVICE_USER' already exists."
else
  echo "[*] Creating system account '$SERVICE_USER'..."
  groupadd --system "$SERVICE_USER" 2>/dev/null || true
  useradd --system --gid "$SERVICE_USER" --home-dir "$APP_DIR" \
          --no-create-home --shell "$NOLOGIN" "$SERVICE_USER"
fi

# --- 2. virtualenv -----------------------------------------------------------
# A .venv copied from another host/arch won't work; validate it really runs and
# has the deps, and rebuild if not.
venv_ok() {
  "$APP_DIR/.venv/bin/python" -c "import flask, yaml, cryptography" >/dev/null 2>&1
}
if [ -x "$APP_DIR/.venv/bin/python" ] && venv_ok; then
  echo "[*] Virtualenv already present and working."
else
  echo "[*] Creating/repairing virtualenv and installing dependencies..."
  rm -rf "$APP_DIR/.venv"
  python3 -m venv "$APP_DIR/.venv"
  "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
  "$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
fi

# --- 3. ownership & permissions ---------------------------------------------
echo "[*] Setting ownership of '$CA_ROOT' to '$SERVICE_USER'..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$CA_ROOT"
chmod 750 "$CA_ROOT"
# Sensitive material (the app also enforces these at runtime).
[ -f "$APP_DIR/config.yaml" ] && chmod 600 "$APP_DIR/config.yaml"
[ -d "$APP_DIR/instance" ]    && chmod -R go-rwx "$APP_DIR/instance"
[ -d "$CA_ROOT/ca" ] && find "$CA_ROOT/ca" -name '*.key.pem' -exec chmod 400 {} + 2>/dev/null || true

# --- 4. systemd unit ---------------------------------------------------------
echo "[*] Installing systemd unit at $UNIT_PATH..."
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=SuperSimpleCA web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/app.py
Restart=on-failure
RestartSec=3
UMask=0077

# --- hardening ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictSUIDSGID=true
LockPersonality=true
# The app must be able to write the CA tree (index.txt, serial, db, certs, backups):
ReadWritePaths=$CA_ROOT

[Install]
WantedBy=multi-user.target
EOF

# Maintenance tick: a oneshot + timer that runs unattended upkeep (expiry
# scan, auto-delete, CRL refresh, CA-expiry warnings) every few hours.
TICK_SVC="/etc/systemd/system/${SERVICE_NAME}-tick.service"
TICK_TIMER="/etc/systemd/system/${SERVICE_NAME}-tick.timer"
echo "[*] Installing maintenance timer at $TICK_TIMER..."
cat > "$TICK_SVC" <<EOF
[Unit]
Description=SuperSimpleCA maintenance tick
After=network-online.target

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/.venv/bin/python $APP_DIR/tick.py
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$CA_ROOT
EOF
cat > "$TICK_TIMER" <<EOF
[Unit]
Description=Run SuperSimpleCA maintenance tick periodically

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null
systemctl enable --now "${SERVICE_NAME}-tick.timer" >/dev/null 2>&1 || systemctl enable "${SERVICE_NAME}-tick.timer" >/dev/null
echo "[*] Service '$SERVICE_NAME' + maintenance timer enabled."

# --- 5. start (only if configured) ------------------------------------------
if [ -f "$APP_DIR/config.yaml" ] && [ "${START:-0}" = "1" ]; then
  systemctl restart "$SERVICE_NAME"
  echo "[*] Service started."
fi

# --- next steps --------------------------------------------------------------
SUDO_RUN="sudo -u $SERVICE_USER $APP_DIR/.venv/bin/python"
cat <<EOF

Done. Next steps
----------------
EOF
if [ ! -f "$APP_DIR/config.yaml" ]; then
cat <<EOF
  1. Set the web-UI admin password (creates config.yaml):
       $SUDO_RUN $APP_DIR/setup.py
  2. Build the SQLite mirror from your existing CA (backs up first):
       $SUDO_RUN $APP_DIR/migrate_to_sqlite.py
  3. Bind to localhost for Caddy: set 'host: 127.0.0.1' in $APP_DIR/config.yaml
  4. Start it:
       sudo systemctl start $SERVICE_NAME
EOF
else
cat <<EOF
  • Ensure 'host: 127.0.0.1' in $APP_DIR/config.yaml (Caddy will proxy TLS).
  • Start / restart:  sudo systemctl start $SERVICE_NAME
EOF
fi
cat <<EOF

  Check status:  systemctl status $SERVICE_NAME
  Follow logs:   journalctl -u $SERVICE_NAME -f

  Caddy note: behind a reverse proxy every request appears to come from
  127.0.0.1, so the app's ip_allowlist can no longer see real client IPs.
  Do any LAN/IP restriction in Caddy, e.g.:

      ca.example.lan {
          @lan remote_ip 192.168.1.0/24
          handle @lan { reverse_proxy 127.0.0.1:$(grep -E '^port:' "$APP_DIR/config.yaml" 2>/dev/null | awk '{print $2}' || echo 8443) }
          respond 403
      }

EOF
