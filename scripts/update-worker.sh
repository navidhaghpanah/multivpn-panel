#!/usr/bin/env bash
# Runs in a transient systemd unit outside the panel service's cgroup.
set -euo pipefail
APP_DIR="${IKEGUI_APP:-/opt/ikev2-l2tp-gui}"
DATA_DIR="${IKEGUI_DATA:-/var/lib/ikev2-l2tp-gui}"
REPO_DIR="${IKEGUI_REPO:-/opt/ikev2-gui-src}"
BRANCH="${1:-main}"
[[ $EUID -eq 0 ]] || exit 1
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ && "$BRANCH" != -* ]] || exit 1
exec 9>"$DATA_DIR/update.lock"
flock -n 9 || exit 1
snapshot="$(mktemp -d "$DATA_DIR/update-backup.XXXXXX")"
status() {
  python3 - "$DATA_DIR/update-status.json" "$1" "${2:-}" <<'PY'
import json, os, sys, tempfile
from datetime import datetime, timezone
path, state, detail = sys.argv[1:]
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
with os.fdopen(fd, 'w') as f:
    json.dump({'state': state, 'detail': detail, 'at': datetime.now(timezone.utc).isoformat()}, f)
os.replace(tmp, path)
PY
}
rollback() {
  rc=$?
  trap - ERR
  if [[ -d "$snapshot/app" ]]; then
    cp -a "$snapshot/app/." "$APP_DIR/"
    for item in "$snapshot/units/"*; do
      [[ ! -f "$item" ]] || cp -a "$item" /etc/systemd/system/
    done
    if [[ -f "$snapshot/version" ]]; then
      cp -a "$snapshot/version" "$DATA_DIR/deployment-version"
    else
      rm -f "$DATA_DIR/deployment-version"
    fi
    systemctl daemon-reload || true
    systemctl restart ikev2-l2tp-gui || true
    if systemctl is-enabled panel-telegram-bot >/dev/null 2>&1; then
      systemctl restart panel-telegram-bot || true
    fi
  fi
  status failed "Update failed; application rollback attempted. See update log."
  exit "$rc"
}
trap rollback ERR
cleanup() {
  case "${BASH_SOURCE[0]}" in "$DATA_DIR"/update-worker.*) rm -f "${BASH_SOURCE[0]}" ;; esac
  if [[ -n "${source_dir:-}" && -d "$source_dir" ]]; then rm -rf -- "$source_dir"; fi
}
trap cleanup EXIT
status running "Downloading and validating update"
# Never reset the persistent checkout: operators may keep local work there.
# Build each update from a fresh disposable checkout and leave REPO_DIR untouched.
source_dir="$(mktemp -d "$DATA_DIR/update-source.XXXXXX")"
git clone --depth 1 --branch "$BRANCH" https://github.com/navidhaghpanah/multivpn-panel.git "$source_dir/repo"
REPO_DIR="$source_dir/repo"
python3 -m py_compile "$REPO_DIR/panel/app.py" "$REPO_DIR/panel/state_lock.py" "$REPO_DIR/panel/telegram_bot.py"
for file in install.sh uninstall.sh scripts/deploy.sh scripts/update-worker.sh scripts/multivpn; do
  bash -n "$REPO_DIR/$file"
done
IKEGUI_COLLECTOR=0 python3 "$REPO_DIR/scripts/smoke_panel.py"
IKEGUI_COLLECTOR=0 python3 "$REPO_DIR/scripts/test_regressions.py"
cp -a "$APP_DIR" "$snapshot/app"
mkdir "$snapshot/units"
for unit in ikev2-l2tp-gui panel-telegram-bot; do
  [[ ! -f "/etc/systemd/system/$unit.service" ]] || cp -a "/etc/systemd/system/$unit.service" "$snapshot/units/"
done
[[ ! -f "$DATA_DIR/deployment-version" ]] || cp -a "$DATA_DIR/deployment-version" "$snapshot/version"
status running "Provisioning services and updating application"
bot_was_active=0
if systemctl is-active --quiet panel-telegram-bot; then bot_was_active=1; fi
if (( bot_was_active )); then systemctl stop panel-telegram-bot; fi
EXTRA_ONLY=1 bash "$REPO_DIR/install.sh"
cp -a "$REPO_DIR/panel/." "$APP_DIR/"
install -m 0644 "$REPO_DIR/panel/ikev2-l2tp-gui.service" /etc/systemd/system/ikev2-l2tp-gui.service
install -m 0644 "$REPO_DIR/panel/panel-telegram-bot.service" /etc/systemd/system/panel-telegram-bot.service
install -m 0755 "$REPO_DIR/panel/ppp-ip-up" /etc/ppp/ip-up.d/ikev2-l2tp-gui
install -m 0755 "$REPO_DIR/panel/ppp-ip-down" /etc/ppp/ip-down.d/ikev2-l2tp-gui
install -m 0755 "$REPO_DIR/scripts/multivpn" /usr/local/bin/multivpn
mkdir -p "$APP_DIR/clients"
cp -a "$REPO_DIR/clients/." "$APP_DIR/clients/"
systemctl stop panel-telegram-bot || true
printf '2\n' > "$DATA_DIR/deployment-version"
systemctl daemon-reload
systemctl restart ikev2-l2tp-gui
healthy=0
for attempt in {1..30}; do
  if systemctl is-active --quiet ikev2-l2tp-gui && curl -fsS --max-time 2 http://127.0.0.1:8765/health/ready >/dev/null; then
    healthy=1; break
  fi
  sleep 1
done
[[ "$healthy" == 1 ]]
if (( bot_was_active )); then
  systemctl restart panel-telegram-bot
fi
status complete "Panel updated and verified"
echo "panel restarted OK"
