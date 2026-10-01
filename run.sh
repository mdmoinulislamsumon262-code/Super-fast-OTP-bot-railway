#!/usr/bin/env bash
set -euo pipefail

: "${BOT_TOKEN:?Set BOT_TOKEN in the Railway service variables before starting the bot}"
: "${ADMIN_ID:?Set ADMIN_ID (numeric Telegram user ID) in Railway service variables}"

if [[ ! "$ADMIN_ID" =~ ^[0-9]+$ ]]; then
  echo "ADMIN_ID must contain only digits." >&2
  exit 1
fi

# Railway sets this automatically when a Volume is mounted. DATA_DIR can
# override the mount path; /app/data is the safe local/container fallback.
export DATA_DIR="${DATA_DIR:-${RAILWAY_VOLUME_MOUNT_PATH:-/app/data}}"
exec python main.py
