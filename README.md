# NH MultiVPN

پنل مدیریت VPN برای Ubuntu ۲۲.۰۴ / ۲۴.۰۴.

<!-- LTR-only badges so GitHub does not mix directions -->
<p dir="ltr">
  <a href="https://github.com/navidhaghpanah/multivpn-panel/releases"><img alt="AI Smart Connect" src="https://img.shields.io/badge/AI-Smart%20Connect-d4af37?style=for-the-badge"></a>
  <a href="https://github.com/navidhaghpanah/multivpn-panel/releases"><img alt="Release" src="https://img.shields.io/github/v/release/navidhaghpanah/multivpn-panel?style=for-the-badge&color=111111"></a>
</p>

---

## فارسی

نصب روی یک VPS، مدیریت از مرورگر. یک نام‌کاربری و رمز برای این پروتکل‌ها:

- `IKEv2` (گواهی Let’s Encrypt + EAP-MSCHAPv2)
- `L2TP/IPsec PSK`
- `VLESS Reality`
- `VMess` روی `WS+TLS`
- `Shadowsocks 2022`
- `Hysteria2`
- `HTTPS` proxy
- `MTProto` با `mtg`

### اتصال هوشمند

بدون کلید هم کار می‌کند. اگر Gateway سازگار با OpenAI بگذارید، مدل می‌تواند رتبهٔ پروتکل را بین گزینه‌های همین سرور عوض کند.

1. یک endpoint چت بسازید (مدل ارزان کافی است).
2. سه چیز را کپی کنید: آدرس کامل Gateway (معمولاً با `/v1`)، کلید، شناسهٔ دقیق مدل.
3. در پنل: تنظیمات، بخش مدل، ذخیره.
4. صفحهٔ اتصال هوشمند: اگر کلید باشد، مدل ترتیب را چک می‌کند.

کلید داخل گیت نیست. هر نصب endpoint خودش را می‌خواهد.

پیش‌فرض فرم برای فیلترینگ ایران است: موبایل، Reality و Hysteria بالاتر، IKEv2 و L2TP پایین‌تر. این پروب زندهٔ ISP نیست.

آدرس Gateway باید `HTTPS` عمومی باشد. آدرس خصوصی یا localhost رد می‌شود.

### امکانات

- داشبورد، کاربران، نشست‌ها، کلاینت‌ها، تنظیمات، گزارش
- سایدبار چپ، تم روشن و تیره، فارسی و انگلیسی
- تیک جدا برای هر پروتکل هنگام ساخت کاربر
- تاریخ انقضا و حجم به گیگ، مشترک بین پروتکل‌ها
- سقف مجموع نشست‌های IKEv2/L2TP هر کاربر (پیش‌فرض ۱)؛ پروکسی‌ها سقف دستگاه ندارند
- آنلاین‌ها، نشست‌ها، ترافیک
- قطع دستی نشست و پاک‌سازی خودکار
- QR و لینک برای VLESS / VMess / Shadowsocks / Hysteria2 / HTTP / MTProto و لینک اشتراک
- CPU، RAM، بار سیستم، آی‌پی سرور، دانلود و آپلود کل از بوت
- تست سرعت خود VPS (نه موبایل شما)
- تغییر PSK و دامنه از پنل
- DNS تونل
- نصب تعاملی: دامنه، SSL، یوزر پنل، PSK

### پروتکل‌های اضافه

تاریخ انقضا روی همه اعمال می‌شود. حجم بین IKEv2/L2TP، Xray و Hysteria2 مشترک است. MTProto فقط برای حساب بدون سقف حجم است؛ با حذف عضو، secret مشترک عوض می‌شود و اعضای باقی‌مانده باید لینک جدید بگیرند.

| پروتکل | سرویس | پورت | احراز هویت |
| --- | --- | --- | --- |
| VLESS Reality + vision | `panel-shadowsocks.service` | TCP `8443` | UUID + Reality، بدون Let’s Encrypt |
| VMess WS+TLS | همان xray | TCP `2053`، path `/vmess` | UUID، فقط با گواهی دامنه |
| Shadowsocks 2022 | همان xray | TCP/UDP از `8388` | کلید `2022-blake3-aes-128-gcm` |
| Hysteria2 | `panel-hysteria.service` | UDP `443` | همان یوزر و رمز پنل |
| HTTP proxy | همان xray | TCP `10809` | یوزر و رمز حساب VPN، با TLS و پورت اختصاصی هر کاربر |
| MTProto | `panel-mtg.service` | TCP `3128` | یک secret برای کل پنل |

- VLESS و VMess و Shadowsocks و HTTP داخل یک `xray-core` هستند. MTProto با sidecar `mtg` است.
- Reality به گواهی دامنه نیاز ندارد. کلیدها بار اول ساخته می‌شوند و در `config.json` می‌مانند. مقصد پیش‌فرض `www.microsoft.com:443`.
- لینک قدیمی VLESS+TLS بعد از آپدیت کار نمی‌کند. UUID همان است؛ کلاینت باید لینک Reality جدید بگیرد.
- VMess و Hysteria2 تا وقتی گواهی دامنه نباشد بالا نمی‌آیند.
- Hysteria2 روی UDP است و با nginx روی TCP 443 تداخل ندارد.
- دامنه IKEv2 از تنظیمات عوض می‌شود. اگر certbot شکست بخورد دامنه باز هم ذخیره می‌شود.
- کانفیگ را دستی ویرایش نکنید. پنل از `users.json` می‌سازد.
- `install.sh` باینری `xray-core`، `hysteria` و `mtg` را نصب می‌کند. روی پنل موجود: `sudo multivpn update`.

### نصب

دامنه را از قبل به IP سرور بدهید. این پورت‌ها باز باشند:

| پورت | برای |
| --- | --- |
| TCP `80` / `443` | پنل و Let’s Encrypt |
| UDP `500` / `4500` / `1701` | IKEv2 و L2TP |
| TCP `8443` | VLESS Reality |
| TCP `2053` | VMess |
| TCP from `10809` | HTTPS proxy (one port per user) |
| TCP `3128` | MTProto |
| UDP `443` | Hysteria2 |
| TCP/UDP از `8388` | Shadowsocks، یک پورت برای هر کاربر |

اگر `ufw` روشن باشد، نصب این پورت‌ها را باز می‌کند.

```bash
git clone https://github.com/navidhaghpanah/multivpn-panel.git
cd multivpn-panel
sudo bash install.sh
```

نصب می‌پرسد: دامنه، IP، ایمیل Let’s Encrypt، PSK، یوزر پنل، اولین کاربر VPN (اختیاری).

نصب غیرتعاملی:

```bash
sudo DOMAIN=vpn.example.com \
  PUBLIC_IP=1.2.3.4 \
  PSK=YourLongPskHere \
  PANEL_USER=admin \
  PANEL_PASS='ChangeMe' \
  VPN_USER=user1 \
  VPN_PASS='ChangeMe' \
  NONINTERACTIVE=1 \
  bash install.sh
```

بعد از نصب آدرس پنل `https://دامنه` است.

### کلاینت

از داشبورد دانلود کنید (ویندوز zip یا آیفون mobileconfig) یا از `/opt/ikev2-l2tp-gui/clients/out/`. قالب‌ها در [`clients/`](clients/README.md).

ویندوز: `Install-IKEv2.bat` را Run as administrator. Settings، Network، VPN. اگر RasMan خطای ۱۰۶۲ داد `Check-Windows.bat`.

آیفون: فایل `IKEv2.mobileconfig` را نصب کنید. یا دستی: نوع IKEv2، Server و Remote ID همان دامنه، Certificate برابر None.

اندروید: اپ strongSwan، نوع IKEv2 EAP. روی سامسونگ داخلی: IKEv2/IPSec MSCHAPv2، نه PSK و نه RSA.

### مسیر فایل‌ها

| مسیر | نقش |
| --- | --- |
| `/opt/ikev2-l2tp-gui` | کد پنل |
| `/etc/ikev2-l2tp-gui` | config و ادمین |
| `/var/lib/ikev2-l2tp-gui` | کاربران و ترافیک |
| `/etc/ipsec.conf` و `/etc/ipsec.secrets` | strongSwan |
| `/opt/panel-xray` | VLESS، VMess، SS، HTTP |
| `/opt/panel-hysteria` | Hysteria2 |
| `/opt/panel-mtg` | MTProto |

حذف: `sudo multivpn uninstall` یا `sudo bash uninstall.sh`.

### به‌روزرسانی

```bash
sudo multivpn update
sudo multivpn status
sudo multivpn restart
sudo multivpn logs -n 80
sudo multivpn uninstall
```

اگر CLI نیست: `sudo bash scripts/multivpn install-cli`.

---

## English

VPN admin panel for Ubuntu 22.04 / 24.04. One username and password across IKEv2, L2TP/IPsec, VLESS Reality, VMess, Shadowsocks 2022, Hysteria2, HTTP proxy, and MTProto.

### Smart Connect

Works without an API key. With an OpenAI-compatible chat gateway, the model can reorder protocols from this VPS inventory.

1. Create a cheap chat endpoint.
2. Copy the full Gateway URL (usually ending in `/v1`), the API key, and the exact model id.
3. Paste them in panel Settings and save.
4. Open Smart Connect. If a key is set, the model may change the ranking.

No shared credentials in git. The Gateway URL must be public HTTPS (localhost and private addresses are rejected).

The form defaults to an Iran-filtering bias (mobile, Reality/Hysteria up, IKEv2/L2TP down). It is not a live ISP probe.

### Features

- Dashboard, users, sessions, clients, settings, logs
- Left sidebar, light/dark, FA/EN
- Per-protocol checkboxes on each account
- Shared expiry and quota
- Combined IKEv2/L2TP session cap (default 1); proxy device limits are not supported
- Live sessions, traffic, CPU, RAM, public IP, totals since boot
- VPS speed test (server uplink, not your phone)
- QR/links plus a subscription URL; HTTPS proxy links use `https://`
- Change PSK and IKEv2 domain from the panel
- Interactive or non-interactive install

### Extra protocols

Expiry is enforced across protocols. Quota is shared across IKEv2/L2TP, Xray and Hysteria2. MTProto is available only for unlimited-quota accounts; membership changes rotate its shared secret, so remaining members must refresh their links.

| Protocol | Unit | Default port | Auth |
| --- | --- | --- | --- |
| VLESS Reality + vision | `panel-shadowsocks.service` | TCP `8443` | UUID + Reality (no Let’s Encrypt) |
| VMess WS+TLS | same xray | TCP `2053`, path `/vmess` | UUID; needs a domain cert |
| Shadowsocks 2022 | same xray | TCP/UDP from `8388` | `2022-blake3-aes-128-gcm` |
| Hysteria2 | `panel-hysteria.service` | UDP `443` | same panel password |
| HTTP proxy | same xray | TCP `10809` | VPN account user/pass, TLS, a dedicated port per account |
| MTProto | `panel-mtg.service` | TCP `3128` | one FakeTLS secret |

VLESS Reality does not need a domain cert. Keys are minted on first xray write and stored in `config.json`. Default dest is `www.microsoft.com:443`. Old VLESS+TLS links stop working after the Reality cutover; keep the UUID and import the new link.

VMess and Hysteria2 stay down until Let’s Encrypt is present. Hysteria2 is UDP, so it does not fight nginx on TCP 443.

Do not edit generated configs by hand. `sudo multivpn update` queues a detached update worker, provisions missing services, validates the application, and checks readiness. Deleted/blocked VPN sessions are disconnected. Proxy connections may reconnect during migration.

### Install

Point the domain at the VPS first. Open:

| Port | Use |
| --- | --- |
| TCP `80` / `443` | panel, Let’s Encrypt |
| UDP `500` / `4500` / `1701` | IKEv2 / L2TP |
| TCP `8443` | VLESS Reality |
| TCP `2053` | VMess |
| TCP from `10809` | HTTPS proxy (one port per user) |
| TCP `3128` | MTProto |
| UDP `443` | Hysteria2 |
| TCP/UDP from `8388` | Shadowsocks, one port per user |

```bash
git clone https://github.com/navidhaghpanah/multivpn-panel.git
cd multivpn-panel
sudo bash install.sh
```

Non-interactive:

```bash
sudo DOMAIN=vpn.example.com \
  PUBLIC_IP=1.2.3.4 \
  PSK=YourLongPskHere \
  PANEL_USER=admin \
  PANEL_PASS='ChangeMe' \
  VPN_USER=user1 \
  VPN_PASS='ChangeMe' \
  NONINTERACTIVE=1 \
  bash install.sh
```

Panel URL: `https://your-domain`.

### Clients

Download Windows zip or iOS mobileconfig from the dashboard, or from `/opt/ikev2-l2tp-gui/clients/out/`. Templates live in [`clients/`](clients/README.md).

Windows: run `Install-IKEv2.bat` as Administrator. If RasMan returns 1062, run `Check-Windows.bat`.

iPhone: install `IKEv2.mobileconfig`. Or add IKEv2 by hand: Server and Remote ID are the domain, Certificate is None.

Android: strongSwan, type IKEv2 EAP. Samsung built-in: IKEv2/IPSec MSCHAPv2 (not PSK, not RSA).

### Paths

| Path | Role |
| --- | --- |
| `/opt/ikev2-l2tp-gui` | panel code |
| `/etc/ikev2-l2tp-gui` | config and admin |
| `/var/lib/ikev2-l2tp-gui` | users and traffic |
| `/etc/ipsec.conf`, `/etc/ipsec.secrets` | strongSwan |
| `/opt/panel-xray` | VLESS, VMess, SS, HTTP |
| `/opt/panel-hysteria` | Hysteria2 |
| `/opt/panel-mtg` | MTProto |

### CLI

```bash
sudo multivpn update
sudo multivpn status
sudo multivpn restart
sudo multivpn logs -n 80
sudo multivpn uninstall
```

If the CLI is missing: `sudo bash scripts/multivpn install-cli`.

---

## Updating an existing installation from the panel

Open the panel and press **Update** in the top bar or Settings. The first update from an older version may close the browser connection while the web service restarts. Wait a few minutes and reload Settings. A detached worker completes provisioning, runs smoke/regression tests, and reports `complete` or `failed` in Settings. Failed updates attempt an application rollback; account data is retained.

The old updater's application-only copy is supported: the new application detects the missing deployment marker and schedules the full migration automatically. No fresh installation or deletion of existing users is needed. New installations receive the marker during installation.

Important migration changes:

- Existing deleted/disabled/expired/over-quota IKEv2 and L2TP sessions are terminated, and stale system credentials no longer recreate users in the panel.
- MTProto members must refresh their shared link after migration and subsequent membership changes. Metered accounts cannot use this unmetered shared backend.
- HTTP proxy now requires TLS and uses an individual port per account. Refresh the proxy link and use a client supporting HTTPS proxies; the old plaintext proxy settings stop working. The active UFW firewall is updated for generated ports; external provider firewalls must allow those ports too.
- The session limit is a combined IKEv2/L2TP limit. Proxy protocols do not implement a reliable device cap. TCP connection count is not used as a substitute for device count.
- Account expiry/quota enforcement runs immediately on changes and periodically (about every 20 seconds). Traffic accounting remains a polling system, rather than an exact billing ledger.
- Admin password or TOTP changes revoke old panel sessions.
- Certificate issuance runs outside the HTTP worker. Settings shows its result; failed issuance restores the previous domain configuration.

Update logs: `journalctl -u multivpn-update`. Certificate logs: `journalctl -u multivpn-domain`.

GitHub SSH deployment is manual (`workflow_dispatch`). Pushing source changes does not automatically deploy to a VPS; use the panel Update button for the existing installation.

New core downloads are version-pinned and SHA256-verified using `scripts/core-releases.json`. Existing core binaries are retained during panel updates. Custom download URLs require corresponding `XRAY_SHA256`, `HY_SHA256`, or `MTG_SHA256` values.

Validation: `bash scripts/selftest.sh` and `python3 scripts/test_regressions.py`. GitHub CI runs the suite with the Ubuntu 22.04/24.04 Python versions. These tests simulate host service operations; they do not replace live VPN connectivity and fresh-install tests.


## Authors

Navid Haghpanah

Project page: GitHub Pages on the `docs/` branch.

## License

MIT
