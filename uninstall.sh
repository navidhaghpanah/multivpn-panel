#!/bin/bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "sudo bash uninstall.sh"
  exit 1
fi
BACKUP_PATH_FILE="/etc/ikev2-l2tp-gui/backup-path"
systemctl disable --now ikev2-l2tp-gui panel-telegram-bot panel-shadowsocks panel-hysteria panel-mtg 2>/dev/null || true
rm -f /usr/local/bin/multivpn
rm -f /etc/nginx/sites-enabled/ikev2-l2tp-gui /etc/nginx/sites-available/ikev2-l2tp-gui
rm -f /etc/systemd/system/ikev2-l2tp-gui.service
rm -f /etc/systemd/system/panel-telegram-bot.service
rm -f /etc/ppp/ip-up.d/ikev2-l2tp-gui /etc/ppp/ip-down.d/ikev2-l2tp-gui
rm -rf /opt/ikev2-l2tp-gui
if [[ -f "$BACKUP_PATH_FILE" ]]; then
  BACKUP_DIR="$(<"$BACKUP_PATH_FILE")"
  if [[ -d "$BACKUP_DIR" ]]; then
    cp -a "$BACKUP_DIR/etc/." /etc/
    echo "Config haye qabl az nasb az $BACKUP_DIR bazgardani shod."
  fi
fi
systemctl restart strongswan-starter xl2tpd nginx 2>/dev/null || true
echo "Panel va service ha hazf shodand."
echo "Data va config panel baraye بازیابی در /etc/ikev2-l2tp-gui و /var/lib/ikev2-l2tp-gui نگه داشته شد."
systemctl daemon-reload
