#!/usr/bin/env bash
# Zero-disruption deploy: updates the panel app in place without touching
# strongSwan/xl2tpd, so established IKEv2/L2TP tunnels are never dropped.
set -euo pipefail

APP_DIR="${IKEGUI_APP:-/opt/ikev2-l2tp-gui}"
REPO_DIR="${IKEGUI_REPO:-${REPO_DIR:-/opt/ikev2-gui-src}}"
BRANCH="${1:-main}"

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

# Updates must outlive the requesting web worker. Use a private, immutable
# copy; fetching the repository cannot overwrite a running worker script.
DATA_DIR="${IKEGUI_DATA:-/var/lib/ikev2-l2tp-gui}"
install -d -m 0700 "$DATA_DIR"
worker="$(mktemp "$DATA_DIR/update-worker.XXXXXX")"
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 0700 "$source_dir/update-worker.sh" "$worker"
systemd-run --unit=multivpn-update --collect --property=Type=exec \
  --setenv=IKEGUI_APP="$APP_DIR" --setenv=IKEGUI_DATA="$DATA_DIR" \
  --setenv=IKEGUI_REPO="$REPO_DIR" /bin/bash "$worker" "$BRANCH" || {
    rm -f "$worker"; exit 1;
  }
echo "panel update queued"
exit 0
