#!/usr/bin/env bash
#
# deploy.sh — push this webca/ tree to a server and restart the service.
#
# Usage:
#   ./deploy.sh user@host:/opt/supersimpleca/webca            # rsync + restart
#   ./deploy.sh user@host:/opt/supersimpleca/webca --dry-run  # preview only
#
# It never overwrites the server's runtime state: .venv/, instance/ (Flask
# secret, persist key), config.yaml and the SQLite db/backups are excluded.
# After copying, it restarts the systemd service over SSH (override the unit
# name with SERVICE_NAME=..., or set NO_RESTART=1 to skip).
#
set -euo pipefail
cd "$(dirname "$0")"

DEST="${1:-}"
DRY=""
[ "${2:-}" = "--dry-run" ] && DRY="--dry-run"
if [ -z "$DEST" ]; then
  echo "Usage: ./deploy.sh user@host:/path/to/webca [--dry-run]" >&2
  exit 1
fi

SERVICE_NAME="${SERVICE_NAME:-supersimpleca}"
REMOTE_HOST="${DEST%%:*}"     # user@host
REMOTE_PATH="${DEST#*:}"      # /path/to/webca

echo "[*] Syncing webca/ -> $DEST"
rsync -az --delete $DRY \
  --exclude ".venv/" \
  --exclude "instance/" \
  --exclude "__pycache__/" \
  --exclude "*.pyc" \
  --exclude "config.yaml" \
  --exclude "*.db" --exclude "*.db-wal" --exclude "*.db-shm" \
  --exclude ".git/" \
  ./ "$DEST/"

if [ -n "$DRY" ]; then
  echo "[*] Dry run complete (no restart)."
  exit 0
fi

# Ensure dependencies are current (in case requirements.txt changed).
echo "[*] Updating dependencies on the server (if needed)..."
ssh "$REMOTE_HOST" "cd '$REMOTE_PATH' && [ -x .venv/bin/pip ] && ./.venv/bin/pip install -q -r requirements.txt || true"

if [ "${NO_RESTART:-0}" = "1" ]; then
  echo "[*] Skipping restart (NO_RESTART=1). Restart manually: sudo systemctl restart $SERVICE_NAME"
  exit 0
fi

echo "[*] Restarting service '$SERVICE_NAME'..."
ssh "$REMOTE_HOST" "sudo systemctl restart '$SERVICE_NAME' && systemctl is-active '$SERVICE_NAME'"
echo "[*] Done."
