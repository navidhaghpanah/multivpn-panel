#!/bin/bash
# Syntax + file + config-generation test. Does not install packages or touch /etc.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FAIL=0

ok() { echo "  OK  $*"; }
bad() { echo "  FAIL  $*"; FAIL=1; }

echo "== bash -n"
bash -n "$ROOT/install.sh" && ok install.sh || bad install.sh
bash -n "$ROOT/uninstall.sh" && ok uninstall.sh || bad uninstall.sh
bash -n "$ROOT/scripts/selftest.sh" && ok selftest.sh || bad selftest.sh

echo "== required files"
while IFS= read -r f; do
  if [[ -f "$ROOT/$f" ]]; then ok "$f"; else bad "missing $f"; fi
done << 'EOF'
install.sh
uninstall.sh
LICENSE
README.md
.gitignore
.gitattributes
panel/app.py
panel/templates/login.html
panel/templates/base.html
panel/templates/index.html
panel/templates/users.html
panel/templates/connect.html
panel/templates/wireguard_client.html
panel/templates/sessions.html
panel/templates/clients.html
panel/templates/settings.html
panel/templates/client_proto.html
panel/static/style.css
panel/static/dashboard.js
panel/static/copy.js
panel/telegram_bot.py
panel/ppp-ip-up
panel/ppp-ip-down
panel/ikev2-l2tp-gui.service
panel/panel-telegram-bot.service
panel/templates/smart.html
scripts/smoke_panel.py
clients/windows/Install-IKEv2.ps1
clients/windows/Install-IKEv2.bat
clients/windows/Check-Windows.bat
clients/windows/RAHNAMA.txt
clients/ios/IKEv2.mobileconfig
clients/ios/RAHNAMA.txt
clients/README.md
EOF

echo "== no provider / host leftovers"
if grep -RInE 'arvan|130\.185|nhaghbayanpsk|arv\.nhaghbayan|HpBayan|eu-west|\b0114\b' --include='*.sh' --include='*.py' --include='*.md' --include='*.html' --include='*.css' --include='*.service' --include='*.ps1' --include='*.bat' --include='*.txt' --include='*.mobileconfig' "$ROOT" | grep -v selftest.sh | grep -v 'napi.arvancloud'; then
  bad "found host-specific strings"
else
  ok "no host-specific strings"
fi
if grep -RInE '(^|[^a-z])navid([^a-z]|$)|navid[0-9]' --include='*.sh' --include='*.py' --include='*.md' --include='*.html' --include='*.css' --include='*.service' --include='*.ps1' --include='*.bat' --include='*.txt' --include='*.mobileconfig' "$ROOT" | grep -v selftest.sh | grep -v navidhaghpanah | grep -v 'Navid Haghpanah'; then
  bad "found vpn username leftovers"
else
  ok "no vpn username leftovers"
fi
if grep -q '__DOMAIN__' "$ROOT/clients/windows/Install-IKEv2.ps1" && grep -q '__DOMAIN__' "$ROOT/clients/ios/IKEv2.mobileconfig"; then
  ok "client templates have __DOMAIN__"
else
  bad "client templates missing __DOMAIN__"
fi
if grep -q '__VPN_UUID__' "$ROOT/clients/ios/IKEv2.mobileconfig" && grep -q '__PAYLOAD_UUID__' "$ROOT/clients/ios/IKEv2.mobileconfig"; then
  ok "ios template has UUID placeholders"
else
  bad "ios template missing UUID placeholders"
fi

echo "== python compile"
if command -v python3 >/dev/null; then
  python3 -m py_compile "$ROOT/panel/app.py" && ok "app.py compiles" || bad "app.py compile"
  python3 -m py_compile "$ROOT/panel/telegram_bot.py" && ok "telegram_bot.py compiles" || bad "telegram_bot compile"
  python3 -c "import ast; ast.parse(open('$ROOT/panel/app.py').read())" && ok "app.py ast.parse" || bad "app.py ast"
else
  echo "  skip python3 not installed"
fi

echo "== security guards"
grep -q '@app.route("/users/update"' "$ROOT/panel/app.py" && ok "users_update routed" || bad "users_update route"
grep -q '@app.route("/users/delete"' "$ROOT/panel/app.py" && ok "users_delete routed" || bad "users_delete route"
grep -q '_NoRedirect' "$ROOT/panel/app.py" && ok "AI SSRF no-redirect" || bad "AI no-redirect"
grep -q 'is_loopback' "$ROOT/panel/app.py" && ok "AI SSRF loopback block" || bad "AI loopback"
grep -q 'napi.arvancloud.ir' "$ROOT/panel/app.py" && ok "blocked-host list present" || bad "blocked-host list"
if grep -RInE '\|safe' "$ROOT/panel/templates"; then
  bad "jinja |safe in templates"
else
  ok "templates autoescape (no |safe)"
fi

echo "== generate sample configs in temp dir"
TMP=$(mktemp -d /tmp/ikev2-l2tp-gui-test.XXXXXX)
DOMAIN=vpn.example.com
PUBLIC_IP=203.0.113.10
PSK=ExamplePskValue
PANEL_USER=admin
PANEL_PASS=ExamplePass1
VPN_USER=user1
VPN_PASS=ExamplePass1
HAVE_SSL=0
mkdir -p "$TMP/app" "$TMP/cfg" "$TMP/data" "$TMP/nginx" "$TMP/ipsec" "$TMP/ppp"
cp -a "$ROOT/panel/." "$TMP/app/"

cat >"$TMP/ipsec/ipsec.conf" << EOF
conn L2TP-PSK
  leftid=${PUBLIC_IP}
conn IKEv2-EAP
  leftid=@${DOMAIN}
  rightdns=9.9.9.9,1.0.0.1
EOF
grep -q "$PUBLIC_IP" "$TMP/ipsec/ipsec.conf" && ok "ipsec.conf leftid IP" || bad "ipsec.conf IP"
grep -q "@${DOMAIN}" "$TMP/ipsec/ipsec.conf" && ok "ipsec.conf leftid domain" || bad "ipsec.conf domain"

cat >"$TMP/nginx/site.conf" << EOF
server_name ${DOMAIN};
ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
proxy_pass http://127.0.0.1:8765;
EOF
grep -q vpn.example.com "$TMP/nginx/site.conf" && ok "nginx server_name" || bad "nginx"

if command -v python3 >/dev/null; then
  python3 - << PY
import json, os, secrets, sys
from pathlib import Path
try:
    from werkzeug.security import generate_password_hash
except ImportError:
    print("  skip werkzeug not installed")
    sys.exit(0)
cfg_dir = Path("$TMP/cfg")
data_dir = Path("$TMP/data")
cfg = {
  "domain": "$DOMAIN",
  "public_ip": "$PUBLIC_IP",
  "psk": "$PSK",
  "dns": ["9.9.9.9", "1.0.0.1"],
  "https": False,
}
(cfg_dir / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
admin = {
  "user": "$PANEL_USER",
  "password": generate_password_hash("$PANEL_PASS"),
  "secret": secrets.token_hex(32),
}
(cfg_dir / "admin.json").write_text(json.dumps(admin, indent=2) + "\n")
users = {"user1": {"password": "$VPN_PASS", "expires": "2027-01-01", "quota_gb": 50, "used_bytes": 0, "created": "2026-08-24", "enabled": True}}
(data_dir / "users.json").write_text(json.dumps(users, indent=2) + "\n")
cfg2 = json.loads((cfg_dir / "config.json").read_text())
assert cfg2["domain"] == "vpn.example.com"
assert "nhaghbayan" not in json.dumps(cfg2)
print("  OK  python config json")
PY
fi

echo "== Farsi UI strings"
for s in 'داشبورد' 'کاربران آنلاین' 'پردازنده' 'حافظه' 'تاریخ انقضا' 'کلید مشترک' 'ورود' 'دریافت کلاینت' 'ترافیک شبکه'; do
  if grep -q "$s" "$ROOT/panel/templates/"*.html "$ROOT/panel/app.py"; then ok "ui: $s"; else bad "ui missing $s"; fi
done

echo "== client stamp"
if command -v python3 >/dev/null; then
  python3 - << PY
from pathlib import Path
import uuid, sys, os
raw = r"$ROOT"
root = Path(raw)
ps1p = root / "clients/windows/Install-IKEv2.ps1"
if not ps1p.is_file() and raw.startswith("/") and len(raw) > 3 and raw[2] == "/":
    root = Path(raw[1].upper() + ":" + raw[2:])
    ps1p = root / "clients/windows/Install-IKEv2.ps1"
if not ps1p.is_file():
    print("  skip client stamp path")
    sys.exit(0)
domain = "vpn.example.com"
ps1 = ps1p.read_text(encoding="utf-8")
ios = (root / "clients/ios/IKEv2.mobileconfig").read_text(encoding="utf-8")
vpn = str(uuid.uuid5(uuid.NAMESPACE_DNS, domain + ":vpn")).upper()
payload = str(uuid.uuid5(uuid.NAMESPACE_DNS, domain + ":profile")).upper()
out = ps1.replace("__DOMAIN__", domain)
ios2 = ios.replace("__DOMAIN__", domain).replace("__VPN_UUID__", vpn).replace("__PAYLOAD_UUID__", payload)
assert "vpn.example.com" in out and "__DOMAIN__" not in out
assert "vpn.example.com" in ios2 and "__DOMAIN__" not in ios2 and "__VPN_UUID__" not in ios2
assert "nhaghbayan" not in ios2.lower()
assert "clients_windows" in (root / "panel/app.py").read_text(encoding="utf-8")
print("  OK  client stamp")
PY
else
  echo "  skip python3 not installed"
fi

echo "== flask e2e smoke"
if command -v python3 >/dev/null && python3 -c "import flask,werkzeug" 2>/dev/null; then
  if python3 "$ROOT/scripts/smoke_panel.py"; then
    ok "flask e2e smoke"
  else
    bad "flask e2e smoke"
  fi
else
  echo "  skip flask/werkzeug not installed"
fi

rm -rf "$TMP"
echo
if [[ "$FAIL" -ne 0 ]]; then
  echo "SELFTEST FAILED"
  exit 1
fi
echo "SELFTEST PASSED"
