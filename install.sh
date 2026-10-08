#!/bin/bash
# NH MultiVPN installer
set -euo pipefail

# Color even under `sudo bash install.sh` (TERM stays). Opt out with NO_COLOR=1.
if [[ -z "${NO_COLOR:-}" && "${TERM:-}" != "dumb" ]]; then
  C_HDR=$'\033[1;38;5;178m'   # gold #d4af37-ish
  C_OK=$'\033[1;38;5;49m'    # status green
  C_ERR=$'\033[1;38;5;203m'
  C_WARN=$'\033[1;38;5;214m'
  C_DIM=$'\033[0;38;5;245m'
  C_ASK=$'\033[1;38;5;229m'
  C_RST=$'\033[0m'
else
  C_HDR=; C_OK=; C_ERR=; C_WARN=; C_DIM=; C_ASK=; C_RST=
fi
hdr()  { printf '%s%s%s\n' "$C_HDR" "$*" "$C_RST"; }
ok()   { printf '%s%s%s\n' "$C_OK" "$*" "$C_RST"; }
err()  { printf '%s%s%s\n' "$C_ERR" "$*" "$C_RST" >&2; }
warn() { printf '%s%s%s\n' "$C_WARN" "$*" "$C_RST" >&2; }
hint() { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RST"; }
banner() {
  echo
  hdr "╔══════════════════════════════════════════╗"
  hdr "║          NH MultiVPN  —  nasb            ║"
  hdr "╚══════════════════════════════════════════╝"
  echo
}

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  err "in script bayad ba root ejra beshe: sudo bash install.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/ikev2-l2tp-gui"
CFG_DIR="/etc/ikev2-l2tp-gui"
DATA_DIR="/var/lib/ikev2-l2tp-gui"
BACKUP_ROOT="/var/backups/ikev2-l2tp-gui"

valid_domain() { [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; }
valid_ip() { python3 -c 'import ipaddress,sys; ipaddress.ip_address(sys.argv[1])' "$1" >/dev/null 2>&1; }
valid_secret() { [[ "$1" =~ ^[A-Za-z0-9._~!@#%^\&*+=,:\;?/-]{12,128}$ ]]; }
valid_vpn_pass() {
  local s="$1" n=${#1}
  (( n >= 1 && n <= 128 )) || return 1
  case "$s" in
    *'"'*|*$'\\'*|*$'\n'*|*$'\r'*) return 1 ;;
  esac
  return 0
}
backup_file() {
  local file="$1"
  [[ -e "$file" ]] || return 0
  mkdir -p "$BACKUP_DIR$(dirname "$file")"
  cp -a "$file" "$BACKUP_DIR$file"
}

ask() {
  local prompt="$1" def="${2:-}" var
  if [[ -n "${NONINTERACTIVE:-}" ]]; then
    printf '%s\n' "$def"
    return
  fi
  if [[ -n "$def" ]]; then
    read -r -p "${C_ASK}${prompt}${C_RST} ${C_DIM}[$def]${C_RST}: " var || true
    printf '%s\n' "${var:-$def}"
  else
    read -r -p "${C_ASK}${prompt}${C_RST}: " var || true
    printf '%s\n' "$var"
  fi
}

ask_secret() {
  local prompt="$1" def="${2:-}" var
  if [[ -n "${NONINTERACTIVE:-}" ]]; then
    printf '%s\n' "$def"
    return
  fi
  read -r -s -p "${C_ASK}${prompt}${C_RST}: " var || true
  echo
  if [[ -z "$var" && -n "$def" ]]; then
    printf '%s\n' "$def"
  else
    printf '%s\n' "$var"
  fi
}

detect_ip() {
  hostname -I 2>/dev/null | awk '{print $1}'
  curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true
}

need=(
  "$SCRIPT_DIR/panel/app.py"
  "$SCRIPT_DIR/panel/templates/login.html"
  "$SCRIPT_DIR/panel/templates/base.html"
  "$SCRIPT_DIR/panel/templates/index.html"
  "$SCRIPT_DIR/panel/templates/users.html"
  "$SCRIPT_DIR/panel/templates/sessions.html"
  "$SCRIPT_DIR/panel/templates/clients.html"
  "$SCRIPT_DIR/panel/templates/settings.html"
  "$SCRIPT_DIR/panel/templates/logs.html"
  "$SCRIPT_DIR/panel/static/style.css"
  "$SCRIPT_DIR/panel/static/dashboard.js"
  "$SCRIPT_DIR/panel/ikev2-l2tp-gui.service"
  "$SCRIPT_DIR/panel/panel-telegram-bot.service"
  "$SCRIPT_DIR/panel/telegram_bot.py"
  "$SCRIPT_DIR/panel/ppp-ip-up"
  "$SCRIPT_DIR/panel/ppp-ip-down"
  "$SCRIPT_DIR/clients/windows/Install-IKEv2.ps1"
  "$SCRIPT_DIR/clients/windows/Install-IKEv2.bat"
  "$SCRIPT_DIR/clients/windows/Check-Windows.bat"
  "$SCRIPT_DIR/clients/windows/RAHNAMA.txt"
  "$SCRIPT_DIR/clients/ios/IKEv2.mobileconfig"
  "$SCRIPT_DIR/clients/ios/RAHNAMA.txt"
  "$SCRIPT_DIR/scripts/multivpn"
)
for f in "${need[@]}"; do
  if [[ ! -f "$f" ]]; then
    err "missing file: $f"
    exit 1
  fi
done

if [[ "${EXTRA_ONLY:-}" == "1" ]]; then
  banner
  hdr "extra protocols (xray / hysteria / mtg)"
  echo
  # Skip domain/SSL/ipsec/nginx. Jump to binary+unit+ufw provisioning below.
else

banner
hint "Ubuntu 22.04 / 24.04  ·  IKEv2 + L2TP + Reality + VMess + SS + Hy2 + HTTP + MTProto"
echo

PUB_GUESS="$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"
IFACE="$(ip -4 route show default | awk '{print $5; exit}')"
IFACE="${IFACE:-eth0}"

DOMAIN="${DOMAIN:-$(ask 'Domain (mesle vpn.example.com)' '')}"
PUBLIC_IP="${PUBLIC_IP:-$(ask 'IP omumi server' "$PUB_GUESS")}"
EMAIL="${EMAIL:-$(ask 'Email baraye Lets Encrypt (khaali = bedune email)' '')}"
PSK="${PSK:-$(ask 'PSK / Secret L2TP (hadaghal 8 character)' '')}"
PANEL_USER="${PANEL_USER:-$(ask 'User vorud panel' '')}"
if [[ -n "${PANEL_PASS:-}" ]]; then
  :
else
  PANEL_PASS="$(ask_secret 'Password vorud panel')"
fi
VPN_USER="${VPN_USER:-$(ask 'Avalin user VPN (khaali = nemisaze)' '')}"
VPN_PASS="${VPN_PASS:-}"
if [[ -n "$VPN_USER" && -z "$VPN_PASS" ]]; then
  VPN_PASS="$(ask_secret "Password user VPN $VPN_USER")"
fi

if [[ -z "$DOMAIN" || -z "$PUBLIC_IP" || -z "$PSK" || -z "$PANEL_USER" || -z "$PANEL_PASS" ]]; then
  err "domain, IP, PSK, user/pass panel lazeman por bashan."
  exit 1
fi
if ! valid_domain "$DOMAIN"; then
  err "domain namotabar ast."
  exit 1
fi
if ! valid_ip "$PUBLIC_IP"; then
  err "IP namotabar ast."
  exit 1
fi
if ! valid_secret "$PSK" || { [[ -n "$VPN_USER" ]] && ! valid_vpn_pass "$VPN_PASS"; }; then
  err "PSK 12-128 english-safe; VPN pass 1-128 (no quote/backslash/newline)."
  exit 1
fi
if [[ "$PANEL_USER" =~ [^A-Za-z0-9._-] || ${#PANEL_USER} -lt 2 || ${#PANEL_USER} -gt 32 || ${#PANEL_PASS} -lt 12 || ${#PANEL_PASS} -gt 128 ]]; then
  err "user/password panel namotabar ast (password: 12-128 character)."
  exit 1
fi

echo
hdr "Nasb package ha..."
apt-get update -y
apt-get install -y \
  strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins \
  libstrongswan-standard-plugins xl2tpd ppp iptables iptables-persistent \
  certbot nginx python3-flask gunicorn curl openssl unzip

BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
for f in /etc/ipsec.conf /etc/ipsec.secrets /etc/xl2tpd/xl2tpd.conf /etc/ppp/options.xl2tpd \
  /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default; do
  backup_file "$f"
done

install -d "$APP_DIR" "$APP_DIR/templates" "$APP_DIR/static" "$CFG_DIR" "$DATA_DIR" \
  /var/run/ikev2-l2tp-gui /var/www/html /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts

cp -a "$SCRIPT_DIR/panel/." "$APP_DIR/"
rm -rf "$APP_DIR/clients"
cp -a "$SCRIPT_DIR/clients" "$APP_DIR/clients"
chmod 755 "$APP_DIR/app.py" "$APP_DIR/ppp-ip-up" "$APP_DIR/ppp-ip-down"
install -m 0755 "$APP_DIR/ppp-ip-up" /etc/ppp/ip-up.d/ikev2-l2tp-gui
install -m 0755 "$APP_DIR/ppp-ip-down" /etc/ppp/ip-down.d/ikev2-l2tp-gui

# disable plugins that break L2TP
for f in /etc/strongswan.d/charon/forecast.conf /etc/strongswan.d/charon/farp.conf; do
  if [[ -f "$f" ]]; then
    sed -i 's/^[[:space:]]*load.*/    load = no/' "$f" || true
  fi
done

hdr "SSL (Let's Encrypt)..."
HAVE_SSL=0
systemctl stop nginx 2>/dev/null || true
CERT_MAIL=(--register-unsafely-without-email)
if [[ -n "$EMAIL" ]]; then
  CERT_MAIL=(--email "$EMAIL")
fi
KEEP=(--force-renewal)
if [[ -f /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ]]; then
  KEEP=(--keep-until-expiring)
fi
certbot certonly --standalone --non-interactive --agree-tos \
  --cert-name "$DOMAIN" --key-type rsa --rsa-key-size 2048 \
  "${KEEP[@]}" -d "$DOMAIN" "${CERT_MAIL[@]}"

if [[ -f /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ]]; then
  HAVE_SSL=1
  cp -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" /etc/ipsec.d/certs/server.crt
  cp -f "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" /etc/ipsec.d/private/server.key
  chmod 600 /etc/ipsec.d/private/server.key
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/ikev2-l2tp-gui.sh << EOF
#!/bin/bash
cp -f /etc/letsencrypt/live/${DOMAIN}/fullchain.pem /etc/ipsec.d/certs/server.crt
cp -f /etc/letsencrypt/live/${DOMAIN}/privkey.pem /etc/ipsec.d/private/server.key
chmod 600 /etc/ipsec.d/private/server.key
ipsec rereadall >/dev/null 2>&1 || true
systemctl reload nginx >/dev/null 2>&1 || true
systemctl try-restart panel-shadowsocks panel-hysteria >/dev/null 2>&1 || true
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/ikev2-l2tp-gui.sh
  if [[ -f /etc/letsencrypt/renewal/${DOMAIN}.conf ]]; then
    sed -i 's/authenticator = standalone/authenticator = webroot/' "/etc/letsencrypt/renewal/${DOMAIN}.conf" || true
    grep -q webroot_path "/etc/letsencrypt/renewal/${DOMAIN}.conf" || \
      printf '\nwebroot_path = /var/www/html\n' >> "/etc/letsencrypt/renewal/${DOMAIN}.conf"
  fi
else
  err "certificate motabar sakhte nashod; nasb baraye hefz amniat motavaqef shod."
  exit 1
fi

hdr "Config IPsec / L2TP..."
cat >/etc/ipsec.conf << EOF
config setup
  uniqueids=no
  charondebug="ike 1, knl 1, cfg 1"

conn %default
  keyingtries=%forever
  dpddelay=30s
  dpdtimeout=120s
  dpdaction=clear
  compress=no
  rekey=no
  fragmentation=yes
  forceencaps=yes
  mobike=yes

conn L2TP-PSK
  keyexchange=ikev1
  type=transport
  authby=secret
  pfs=no
  mobike=no
  ike=aes256-sha256-modp2048,aes128-sha256-modp2048!
  esp=aes256-sha256,aes128-sha256!
  left=%any
  leftid=${PUBLIC_IP}
  leftprotoport=17/1701
  right=%any
  rightprotoport=17/%any
  auto=add

conn IKEv2-EAP
  keyexchange=ikev2
  type=tunnel
  ike=aes256gcm16-prfsha256-ecp256,aes256-sha256-ecp256,aes256-sha256-modp2048!
  esp=aes256gcm16,aes128gcm16,aes256-sha256,aes128-sha256!
  left=%any
  leftid=@${DOMAIN}
  leftcert=server.crt
  leftauth=pubkey
  leftsendcert=always
  leftsubnet=0.0.0.0/0
  right=%any
  rightid=%any
  rightauth=eap-mschapv2
  eap_identity=%identity
  rightsourceip=10.8.3.0/24
  rightdns=9.9.9.9,1.0.0.1
  auto=add
EOF

cat >/etc/xl2tpd/xl2tpd.conf << 'EOF'
[global]
port = 1701
auth file = /etc/ppp/chap-secrets
access control = no

[lns default]
ip range = 10.8.2.10-10.8.2.200
local ip = 10.8.2.1
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

cat >/etc/ppp/options.xl2tpd << 'EOF'
ipcp-accept-local
ipcp-accept-remote
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
noccp
auth
mtu 1200
mru 1200
hide-password
name l2tpd
connect-delay 5000
ms-dns 9.9.9.9
ms-dns 1.0.0.1
nobsdcomp
nodeflate
nopcomp
noaccomp
noipv6
noproxyarp
lock
EOF

cat >/etc/sysctl.d/99-ikev2-l2tp-gui.conf << EOF
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.${IFACE}.rp_filter=0
EOF
sysctl -p /etc/sysctl.d/99-ikev2-l2tp-gui.conf >/dev/null

# Dedicated NIC with the public IP on it: SNAT. AWS/GCP-style private NIC + Elastic IP: MASQUERADE
# (SNAT-to-EIP is dropped by source/dest check because ens* only has 172.x/10.x).
if ip -4 addr show dev "$IFACE" | grep -q "inet ${PUBLIC_IP}/"; then
  NAT_JUMP="SNAT --to-source $PUBLIC_IP"
else
  NAT_JUMP="MASQUERADE"
  hint "NIC $IFACE has no $PUBLIC_IP (cloud NAT) — using MASQUERADE"
fi
iptables -t nat -C POSTROUTING -s 10.8.2.0/24 -o "$IFACE" -j $NAT_JUMP 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.8.2.0/24 -o "$IFACE" -j $NAT_JUMP
iptables -t nat -C POSTROUTING -s 10.8.3.0/24 -o "$IFACE" -j $NAT_JUMP 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s 10.8.3.0/24 -o "$IFACE" -j $NAT_JUMP
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200 2>/dev/null || \
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1200
iptables -C FORWARD -s 10.8.2.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.8.2.0/24 -j ACCEPT
iptables -C FORWARD -d 10.8.2.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.8.2.0/24 -j ACCEPT
iptables -C FORWARD -s 10.8.3.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.8.3.0/24 -j ACCEPT
iptables -C FORWARD -d 10.8.3.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.8.3.0/24 -j ACCEPT
netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 || true

IKEGUI_INSTALL_CFG_DIR="$CFG_DIR" IKEGUI_INSTALL_DATA_DIR="$DATA_DIR" \
IKEGUI_INSTALL_DOMAIN="$DOMAIN" IKEGUI_INSTALL_PUBLIC_IP="$PUBLIC_IP" \
IKEGUI_INSTALL_PSK="$PSK" IKEGUI_INSTALL_PANEL_USER="$PANEL_USER" \
IKEGUI_INSTALL_PANEL_PASS="$PANEL_PASS" IKEGUI_INSTALL_VPN_USER="$VPN_USER" \
IKEGUI_INSTALL_VPN_PASS="$VPN_PASS" IKEGUI_INSTALL_HTTPS="$HAVE_SSL" \
IKEGUI_INSTALL_INTERFACE="$IFACE" python3 - << 'PY'
import json, os, secrets
from pathlib import Path
from werkzeug.security import generate_password_hash
cfg_dir = Path(os.environ["IKEGUI_INSTALL_CFG_DIR"])
data_dir = Path(os.environ["IKEGUI_INSTALL_DATA_DIR"])
cfg_dir.mkdir(parents=True, exist_ok=True)
data_dir.mkdir(parents=True, exist_ok=True)
cfg = {
  "domain": os.environ["IKEGUI_INSTALL_DOMAIN"],
  "public_ip": os.environ["IKEGUI_INSTALL_PUBLIC_IP"],
  "psk": os.environ["IKEGUI_INSTALL_PSK"],
  "dns": ["9.9.9.9", "1.0.0.1"],
  "interface": os.environ["IKEGUI_INSTALL_INTERFACE"],
  "max_sessions_per_user": 3,
  "https": os.environ["IKEGUI_INSTALL_HTTPS"] == "1",
}
(cfg_dir / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
os.chmod(cfg_dir / "config.json", 0o600)
admin_file = cfg_dir / "admin.json"
admin = {
  "user": os.environ["IKEGUI_INSTALL_PANEL_USER"],
  "password": generate_password_hash(os.environ["IKEGUI_INSTALL_PANEL_PASS"]),
  "secret": secrets.token_hex(32),
}
admin_file.write_text(json.dumps(admin, indent=2) + "\n")
os.chmod(admin_file, 0o600)
users_file = data_dir / "users.json"
users = {}
if users_file.exists():
    try:
        users = json.loads(users_file.read_text())
    except Exception:
        users = {}
vpn_user = os.environ["IKEGUI_INSTALL_VPN_USER"]
vpn_pass = os.environ["IKEGUI_INSTALL_VPN_PASS"]
if vpn_user:
    users[vpn_user] = {
        "password": vpn_pass,
        "expires": "",
        "quota_gb": 0,
        "used_bytes": users.get(vpn_user, {}).get("used_bytes", 0),
        "created": users.get(vpn_user, {}).get("created", ""),
        "enabled": True,
    }
users_file.write_text(json.dumps(users, ensure_ascii=False, indent=2) + "\n")
os.chmod(users_file, 0o600)
print("config json ok")
PY
printf '%s\n' "$BACKUP_DIR" > "$CFG_DIR/backup-path"
chmod 600 "$CFG_DIR/backup-path"

python3 - << PY
import os, sys
sys.path.insert(0, "${APP_DIR}")
os.chdir("${APP_DIR}")
os.environ["IKEGUI_APP"] = "${APP_DIR}"
os.environ["IKEGUI_CFG"] = "${CFG_DIR}"
os.environ["IKEGUI_DATA"] = "${DATA_DIR}"
from app import import_secrets_if_needed, write_secrets, load_users
users = import_secrets_if_needed()
write_secrets(users)
print("secrets ok", list(users))
PY

# nginx
if [[ "$HAVE_SSL" -eq 1 ]]; then
  cat >/etc/nginx/sites-available/ikev2-l2tp-gui << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    server_tokens off;
    client_max_body_size 8m;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Referrer-Policy same-origin;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
fi
ln -sfn /etc/nginx/sites-available/ikev2-l2tp-gui /etc/nginx/sites-enabled/ikev2-l2tp-gui
rm -f /etc/nginx/sites-enabled/default

fi  # EXTRA_ONLY skip of core IKEv2/nginx install

# --- Shadowsocks / VLESS (xray-core) and Hysteria2 binaries + units ---------
# The panel generates the config files for these from users.json and starts or
# stops the services itself. The units carry ConditionPathExists so that an
# enabled-but-unconfigured service is skipped cleanly instead of crash-looping.
case "$(uname -m)" in
  x86_64)  XRAY_ASSET="Xray-linux-64.zip";        HY_ASSET="hysteria-linux-amd64" ;;
  aarch64) XRAY_ASSET="Xray-linux-arm64-v8a.zip"; HY_ASSET="hysteria-linux-arm64" ;;
  *) echo "arch $(uname -m) pshtibani nemishe baraye Shadowsocks/VLESS/Hysteria2" >&2
     XRAY_ASSET=""; HY_ASSET="" ;;
esac

if [[ -n "$XRAY_ASSET" ]]; then
  install -d /opt/panel-xray /etc/panel-xray /opt/panel-hysteria /etc/panel-hysteria
  chmod 700 /etc/panel-xray /etc/panel-hysteria

  XRAY_URL="${XRAY_URL:-}"
  HY_URL="${HY_URL:-}"

  tmp_dl="$(mktemp -d)"
  if [[ -x /opt/panel-xray/xray ]]; then
    ok "xray-core ghablan nasb shode, skip download"
  elif python3 "$SCRIPT_DIR/scripts/verified_download.py" "$XRAY_ASSET" "$tmp_dl/xray.zip" "$XRAY_URL" "${XRAY_SHA256:-}"; then
    unzip -oq "$tmp_dl/xray.zip" xray -d /opt/panel-xray
    chmod 0755 /opt/panel-xray/xray
    ok "xray-core nasb shod"
  else
    warn "hoshdar: download xray-core nashod — Shadowsocks/VLESS kar nemikone"
  fi
  if [[ -x /opt/panel-hysteria/hysteria ]]; then
    ok "hysteria2 ghablan nasb shode, skip download"
  elif python3 "$SCRIPT_DIR/scripts/verified_download.py" "$HY_ASSET" "$tmp_dl/hysteria" "$HY_URL" "${HY_SHA256:-}"; then
    install -m 0755 "$tmp_dl/hysteria" /opt/panel-hysteria/hysteria
    ok "hysteria2 nasb shod"
  else
    warn "hoshdar: download hysteria2 nashod — Hysteria2 kar nemikone"
  fi
  rm -rf "$tmp_dl"

  cat > /etc/systemd/system/panel-shadowsocks.service << 'EOF'
[Unit]
Description=Panel Shadowsocks/VLESS (xray-core)
After=network.target
ConditionPathExists=/etc/panel-xray/config.json

[Service]
Type=simple
ExecStart=/opt/panel-xray/xray run -config /etc/panel-xray/config.json
Restart=on-failure
RestartSec=5
User=root
UMask=0077
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/panel-hysteria.service << 'EOF'
[Unit]
Description=Panel Hysteria2
After=network.target
ConditionPathExists=/etc/panel-hysteria/config.yaml

[Service]
Type=simple
ExecStart=/opt/panel-hysteria/hysteria server -c /etc/panel-hysteria/config.yaml
WorkingDirectory=/etc/panel-hysteria
Restart=on-failure
RestartSec=5
User=root
UMask=0077
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
fi

# --- MTProto sidecar (mtg). Xray has no mtproto inbound (same as 3x-ui v3.3).
# Hardcoded 9seconds/mtg v2.2.8 linux binaries (2026-04-07). Override with MTG_URL.
case "$(uname -m)" in
  x86_64)  MTG_ASSET="mtg-2.2.8-linux-amd64.tar.gz" ;;
  aarch64) MTG_ASSET="mtg-2.2.8-linux-arm64.tar.gz" ;;
  *) MTG_ASSET="" ;;
esac
if [[ -n "$MTG_ASSET" ]]; then
  install -d /opt/panel-mtg /etc/panel-mtg
  chmod 700 /etc/panel-mtg
  if [[ ! -x /opt/panel-mtg/mtg ]]; then
    MTG_URL="${MTG_URL:-}"
    tmp_mtg="$(mktemp -d)"
    if python3 "$SCRIPT_DIR/scripts/verified_download.py" "$MTG_ASSET" "$tmp_mtg/mtg.tar.gz" "$MTG_URL" "${MTG_SHA256:-}"; then
      tar -xzf "$tmp_mtg/mtg.tar.gz" -C "$tmp_mtg"
      mtg_bin="$(find "$tmp_mtg" -type f -name mtg | head -n1)"
      if [[ -n "$mtg_bin" ]]; then
        install -m 0755 "$mtg_bin" /opt/panel-mtg/mtg
        ok "mtg nasb shod"
      else
        warn "hoshdar: binary mtg tu archive nist"
      fi
    else
      warn "hoshdar: download mtg nashod — MTProto kar nemikone"
    fi
    rm -rf "$tmp_mtg"
  fi
  cat > /etc/systemd/system/panel-mtg.service << 'EOF'
[Unit]
Description=Panel MTProto (mtg)
After=network.target
ConditionPathExists=/etc/panel-mtg/mtg.toml

[Service]
Type=simple
ExecStart=/opt/panel-mtg/mtg run /etc/panel-mtg/mtg.toml
Restart=on-failure
RestartSec=5
User=root
UMask=0077
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
fi

# Open the extra protocol ports only when a firewall is actually managing them.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 8443/tcp  >/dev/null 2>&1 || true   # VLESS Reality
  ufw allow 443/udp   >/dev/null 2>&1 || true   # Hysteria2 (QUIC)
  ufw allow 8388:8888/tcp >/dev/null 2>&1 || true   # per-user Shadowsocks (ss_next_port starts at 8388)
  ufw allow 8388:8888/udp >/dev/null 2>&1 || true
  ufw allow 2053/tcp  >/dev/null 2>&1 || true   # VMess WS+TLS
  ufw allow 10809/tcp >/dev/null 2>&1 || true   # HTTP proxy
  ufw allow 3128/tcp  >/dev/null 2>&1 || true   # MTProto (mtg)
fi

if [[ "${EXTRA_ONLY:-}" == "1" ]]; then
  if [[ -f "$APP_DIR/panel-telegram-bot.service" ]]; then
    cp "$APP_DIR/panel-telegram-bot.service" /etc/systemd/system/panel-telegram-bot.service
    rm -f "$APP_DIR/panel-telegram-bot.service"
  elif [[ -f "$SCRIPT_DIR/panel/panel-telegram-bot.service" ]]; then
    cp "$SCRIPT_DIR/panel/panel-telegram-bot.service" /etc/systemd/system/panel-telegram-bot.service
  fi
  systemctl daemon-reload
  if [[ -f /etc/systemd/system/panel-mtg.service ]]; then
    systemctl enable panel-mtg >/dev/null || true
  fi
  if [[ -f /etc/systemd/system/panel-shadowsocks.service ]]; then
    systemctl enable panel-shadowsocks >/dev/null || true
  fi
  if [[ -f /etc/systemd/system/panel-hysteria.service ]]; then
    systemctl enable panel-hysteria >/dev/null || true
  fi
  ok "extra protocols OK (xl2tpd/nginx/panel dast nazadim)"
  exit 0
fi

cp "$APP_DIR/ikev2-l2tp-gui.service" /etc/systemd/system/ikev2-l2tp-gui.service
if [[ -f "$APP_DIR/panel-telegram-bot.service" ]]; then
  cp "$APP_DIR/panel-telegram-bot.service" /etc/systemd/system/panel-telegram-bot.service
fi
rm -f "$APP_DIR/ikev2-l2tp-gui.service" "$APP_DIR/panel-telegram-bot.service"
systemctl daemon-reload
printf '2\n' > "$DATA_DIR/deployment-version"
systemctl enable xl2tpd strongswan-starter ikev2-l2tp-gui nginx >/dev/null
if [[ -f /etc/systemd/system/panel-mtg.service ]]; then
  systemctl enable panel-mtg >/dev/null || true
fi
systemctl restart xl2tpd
systemctl restart strongswan-starter
systemctl restart ikev2-l2tp-gui
nginx -t
systemctl restart nginx

python3 - << PY
from pathlib import Path
import uuid
src = Path("${APP_DIR}/clients")
out = src / "out"
out.mkdir(parents=True, exist_ok=True)
domain = """${DOMAIN}"""
vpn = str(uuid.uuid5(uuid.NAMESPACE_DNS, domain + ":vpn")).upper()
payload = str(uuid.uuid5(uuid.NAMESPACE_DNS, domain + ":profile")).upper()
for rel in (
    "windows/Install-IKEv2.ps1",
    "windows/Install-IKEv2.bat",
    "windows/Check-Windows.bat",
    "windows/RAHNAMA.txt",
    "ios/IKEv2.mobileconfig",
    "ios/RAHNAMA.txt",
):
    text = (src / rel).read_text(encoding="utf-8")
    text = text.replace("__DOMAIN__", domain).replace("__VPN_UUID__", vpn).replace("__PAYLOAD_UUID__", payload)
    (out / Path(rel).name).write_text(text, encoding="utf-8")
print("clients stamped")
PY

echo
hdr "╔══════════════════════════════════════════╗"
hdr "║            nasb tamom shod               ║"
hdr "╚══════════════════════════════════════════╝"
echo
if [[ -f "$SCRIPT_DIR/scripts/multivpn" ]]; then
  install -m 0755 "$SCRIPT_DIR/scripts/multivpn" /usr/local/bin/multivpn
  ok "CLI:     sudo multivpn update | status | uninstall"
fi
ok  "Panel:   https://${DOMAIN}"
hint "Panel user: ${PANEL_USER}"
ok  "IKEv2:   server + Remote ID = ${DOMAIN}"
ok  "L2TP:    haman user/pass + PSK (Settings)"
hint "Windows: panel > download zip   ya  ${APP_DIR}/clients/out/Install-IKEv2.bat"
hint "iOS:     panel > download profile ya  ${APP_DIR}/clients/out/IKEv2.mobileconfig"
echo
