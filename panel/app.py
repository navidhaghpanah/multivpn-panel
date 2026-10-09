#!/usr/bin/env python3
# IKEv2 GUI — پنل مدیریت
import base64
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import math
import os
import re
import shutil
import struct
import socket
import signal
import subprocess
import threading
import time
import secrets
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
import tempfile
from datetime import date, datetime
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from state_lock import StateLock

APP_DIR = Path(os.environ.get("IKEGUI_APP", "/opt/ikev2-l2tp-gui"))
CFG_DIR = Path(os.environ.get("IKEGUI_CFG", "/etc/ikev2-l2tp-gui"))
REPO_DIR = Path(os.environ.get("IKEGUI_REPO", "/opt/ikev2-gui-src"))
REPO_URL = "https://github.com/navidhaghpanah/multivpn-panel.git"
REPO_BRANCH = "main"
DATA_DIR = Path(os.environ.get("IKEGUI_DATA", "/var/lib/ikev2-l2tp-gui"))
CLIENTS_DIR = APP_DIR / "clients"
PPP_ONLINE = Path("/var/run/ikev2-l2tp-gui")
ADMIN_FILE = CFG_DIR / "admin.json"
CONFIG_FILE = CFG_DIR / "config.json"
USERS_FILE = DATA_DIR / "users.json"
DELETED_USERS_FILE = DATA_DIR / "deleted-users.json"
SNAP_FILE = DATA_DIR / "traffic-snap.json"
SPEED_FILE = DATA_DIR / "speedtest.json"
IPSEC_SECRETS = Path("/etc/ipsec.secrets")
CHAP_SECRETS = Path("/etc/ppp/chap-secrets")
IPSEC_CONF = Path("/etc/ipsec.conf")
PPP_OPTS = Path("/etc/ppp/options.xl2tpd")

DNS_PRESETS = (
    ("shecan", "Shecan", ("178.22.122.100", "185.51.200.2")),
    ("electro", "Electro", ("78.157.42.100", "78.157.42.101")),
    ("cloudflare", "Cloudflare", ("1.1.1.1", "1.0.0.1")),
    ("google", "Google", ("8.8.8.8", "8.8.4.4")),
    ("quad9", "Quad9", ("9.9.9.9", "149.112.112.112")),
    ("adguard", "AdGuard", ("94.140.14.14", "94.140.15.15")),
)


def match_dns_preset(parts):
    got = tuple(str(p) for p in (parts or []))
    for pid, label, ips in DNS_PRESETS:
        if got == tuple(ips):
            return pid
    return "custom"


def apply_tunnel_dns(parts):
    if PPP_OPTS.exists():
        text = PPP_OPTS.read_text(encoding="utf-8", errors="replace")
        lines = [ln for ln in text.splitlines() if not ln.startswith("ms-dns ")]
        for d in parts[:2]:
            lines.append("ms-dns " + d)
        PPP_OPTS.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if IPSEC_CONF.exists() and parts:
        conf = IPSEC_CONF.read_text(encoding="utf-8", errors="replace")
        conf = re.sub(r"rightdns=.*", "rightdns=" + ",".join(parts[:2]), conf)
        IPSEC_CONF.write_text(conf, encoding="utf-8")
        run(["ipsec", "reload"])

STROKE = Path("/usr/lib/ipsec/stroke")
XRAY_SS_BIN = Path("/opt/panel-xray/xray")
XRAY_SS_CONFIG = Path("/etc/panel-xray/config.json")
HYSTERIA_BIN = Path("/opt/panel-hysteria/hysteria")
HYSTERIA_CONFIG = Path("/etc/panel-hysteria/config.yaml")
MTG_BIN = Path("/opt/panel-mtg/mtg")
MTG_CONFIG = Path("/etc/panel-mtg/mtg.toml")
NGINX_SITE = Path("/etc/nginx/sites-available/ikev2-l2tp-gui")
LE_LIVE = Path("/etc/letsencrypt/live")
IPSEC_CERT = Path("/etc/ipsec.d/certs/server.crt")
IPSEC_KEY = Path("/etc/ipsec.d/private/server.key")
CERTBOT_HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/ikev2-l2tp-gui.sh")
SS_METHOD = "2022-blake3-aes-128-gcm"
VMESS_PATH = "/vmess"
TZ = ZoneInfo("Asia/Tehran")
USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")
# Same rule as install.sh valid_domain.
DOMAIN_RE = re.compile(
    r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
FA_D = str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹")

I18N = {
    "fa": {
        "brand_sub": "مدیریت شبکه خصوصی",
        "server_live": "سرور فعال",
        "nav_manage": "مدیریت",
        "nav_dash": "داشبورد",
        "nav_users": "کاربران",
        "nav_sessions": "نشست‌ها",
        "nav_clients": "کلاینت‌ها",
        "nav_system": "سیستم",
        "nav_settings": "تنظیمات",
        "nav_logs": "گزارش‌ها",
        "logout": "خروج",
        "admin_fallback": "مدیر",
        "admin_role": "مدیر سیستم",
        "live": "سرویس آنلاین",
        "stale": "اطلاعات قدیمی",
        "cpu": "CPU",
        "ram": "RAM",
        "theme_to_light": "روشن",
        "theme_to_dark": "تیره",
        "restart": "ری‌استارت پنل",
        "restart_confirm": "پنل وب ری‌استارت شود؟ تونل‌های VPN قطع نمی‌شوند.",
        "update": "به‌روزرسانی",
        "update_confirm": "پنل به‌روزرسانی می‌شود. حساب‌های حذف‌شده قطع می‌شوند و ممکن است اتصال پروکسی‌ها کوتاه قطع شود. ادامه می‌دهید؟",
        "confirm_title": "تأیید عملیات",
        "cancel": "انصراف",
        "confirm": "تأیید",
        "copied": "کپی شد ✓",
        "show_pass": "نمایش",
        "hide_pass": "پنهان",
        "working": "در حال انجام…",
        "menu": "منو",
        "dash_title": "داشبورد",
        "dash_sub": "نمای کلی سرور و اتصال‌های فعال",
        "users_title": "کاربران",
        "users_sub": "ساخت حساب و مدیریت حجم و انقضا",
        "sessions_title": "نشست‌ها",
        "sessions_sub": "اتصال‌های زنده و پاک‌سازی نشست‌های قدیمی",
        "clients_title": "کلاینت‌ها",
        "clients_sub": "فایل‌های آمادهٔ اتصال برای دستگاه‌ها",
        "settings_title": "تنظیمات",
        "settings_sub": "امنیت، DNS، پشتیبان و محدودیت نشست‌ها",
        "logs_title": "گزارش‌ها",
        "logs_sub": "آخرین ۲۰۰ خط journalctl سرویس‌های پنل",
        "online_users": "کاربران آنلاین",
        "of_accounts": "از %(total)s حساب",
        "active_sessions": "نشست‌های فعال",
        "ike_l2": "IKEv2 و L2TP",
        "sys_load": "بار سیستم",
        "cpu_cores": "%(n)s هستهٔ پردازشی",
        "uptime": "زمان فعالیت",
        "recent_sessions": "نشست‌های اخیر",
        "recent_sessions_p": "آخرین اتصال‌های فعال روی سرور",
        "view_all": "مشاهده همه ←",
        "col_user": "کاربر",
        "col_proto": "پروتکل",
        "col_vip": "آی‌پی داخلی",
        "col_remote": "آی‌پی اینترنت",
        "col_uptime": "مدت اتصال",
        "col_traffic": "ترافیک",
        "unknown": "نامشخص",
        "no_sessions": "نشست فعالی وجود ندارد.",
        "resources": "منابع سرور",
        "resources_p": "وضعیت لحظه‌ای سیستم",
        "healthy": "سالم",
        "processor": "پردازنده",
        "memory": "حافظه RAM",
        "of": "از",
        "disk": "فضای دیسک",
        "net_traffic": "ترافیک شبکه",
        "net_traffic_p": "سرعت لحظه‌ای و مجموع اینترفیس %(iface)s",
        "down_speed": "↓ سرعت دانلود",
        "up_speed": "↑ سرعت آپلود",
        "rx_total": "کل دانلود از زمان بوت",
        "tx_total": "کل آپلود از زمان بوت",
        "server_ip": "آی‌پی سرور",
        "speed_test": "تست سرعت",
        "speed_test_p": "اینترنت همین VPS را می‌سنجد، نه موبایل یا لپ‌تاپ شما.",
        "speed_run": "شروع تست سرعت",
        "speed_running": "در حال تست…",
        "speed_down": "دانلود",
        "speed_up": "آپلود",
        "speed_ping": "پینگ",
        "speed_fail": "تست سرعت انجام نشد.",
        "speed_idle": "هنوز تست نشده",
        "speed_start": "شروع",
        "speed_end": "پایان",
        "mbps": "مگابیت بر ثانیه",
        "ms": "ms",
        "quick": "دسترسی سریع",
        "quick_p": "کارهای پرکاربرد مدیریت سرور",
        "quick_add": "ساخت کاربر",
        "quick_add_p": "حساب VPN جدید بسازید",
        "quick_sess": "مدیریت نشست‌ها",
        "quick_sess_p": "اتصال‌های قدیمی را ببندید",
        "quick_cli": "دریافت کلاینت",
        "quick_cli_p": "فایل ویندوز و آیفون",
        "quick_set": "تنظیمات سرور",
        "quick_set_p": "DNS، امنیت و محدودیت‌ها",
        "online_now": "کاربران آنلاین",
        "online_now_p": "حساب‌های متصل در این لحظه",
        "nobody_online": "کسی آنلاین نیست.",
        "all_accounts": "کل حساب‌ها",
        "offline": "آفلاین",
        "online": "آنلاین",
        "max_per_user": "نشست مجاز هر کاربر",
        "add_user": "افزودن کاربر جدید",
        "add_user_p": "برای کاربر نام، رمز و در صورت نیاز محدودیت تعیین کنید.",
        "username": "نام کاربری",
        "password": "رمز عبور",
        "pass_ph": "هر رمزی می‌خواهید (۱ تا ۱۲۸ نویسه)",
        "expires": "تاریخ انقضا",
        "expires_hint": "خالی یعنی بدون انقضا",
        "quota": "حجم (GB)",
        "quota_hint": "صفر یعنی نامحدود. MTProto فقط برای حساب بدون سقف حجم فعال می‌شود.",
        "create_user": "+ ساخت کاربر",
        "user_list": "فهرست کاربران",
        "user_list_p": "ویرایش حجم، تاریخ و رمز بدون نمایش رمز فعلی",
        "n_users": "%(n)s کاربر",
        "col_status": "وضعیت",
        "col_expires": "انقضا",
        "col_quota": "مصرف / سهمیه",
        "col_edit": "ویرایش حساب",
        "unlimited": "نامحدود",
        "created": "ایجاد",
        "no_users": "هنوز کاربری ساخته نشده است.",
        "edit_account": "ویرایش حساب",
        "edit_account_p": "تنظیمات حساب",
        "new_pass": "رمز جدید",
        "keep_pass": "برای حفظ رمز خالی بگذارید",
        "active_protos": "پروتکل‌های فعال",
        "reset_traffic": "مصرف ترافیک این کاربر صفر شود",
        "save": "ذخیره تغییرات",
        "close": "بستن",
        "delete_user_q": "حساب %(name)s حذف شود؟ این عملیات قابل بازگشت نیست.",
        "delete_user": "حذف کاربر",
        "delete_user_aria": "حذف %(name)s",
        "cap_per_user": "سقف هر کاربر",
        "cleanup_old": "پاک‌سازی نشست‌های قدیمی",
        "sess_info": "جدیدترین %(n)s نشست هر کاربر حفظ می‌شود. نشست‌های اضافه به‌صورت خودکار حداکثر تا ۲۰ ثانیه بعد بسته می‌شوند.",
        "live_conns": "اتصال‌های زنده",
        "live_conns_p": "برای بستن فوری یک اتصال IKEv2 از دکمهٔ انتهای ردیف استفاده کنید.",
        "col_id": "شناسه",
        "col_duration": "مدت",
        "col_du": "دانلود / آپلود",
        "drop_conn": "قطع اتصال",
        "drop_conn_q": "نشست #%(id)s مربوط به %(user)s قطع شود؟",
        "drop_title": "قطع اتصال",
        "no_conn": "در حال حاضر اتصال فعالی وجود ندارد.",
        "recommended": "پیشنهادی",
        "win_title": "Windows — IKEv2",
        "win_p": "نصب خودکار اتصال IKEv2 همراه ابزار بررسی",
        "dl_zip": "دانلود فایل ZIP",
        "ready_profile": "پروفایل آماده",
        "ios_title": "iPhone / iPad — IKEv2",
        "ios_p": "پروفایل استاندارد برای اتصال سریع IKEv2",
        "dl_mobileconfig": "دانلود mobileconfig",
        "guide_ike": "راهنمای اتصال — IKEv2",
        "guide_l2": "راهنمای اتصال — L2TP",
        "ike_step1": "ویندوز / strongSwan / سامسونگ: IKEv2 MSCHAPv2.",
        "ike_step3": "گواهی: None. همان کاربر پنل.",
        "l2_step1": "ویندوز: L2TP/IPsec with pre-shared key. آیفون: Add VPN → L2TP.",
        "l2_step2": "UDP 1701. xl2tpd ری‌استارت نمی‌شود.",
        "l2_step3": "PSK از تنظیمات پنل. یوزر/پس همان IKEv2. تیک L2TP روی کاربر لازم است.",
        "android_l2": "اندروید L2TP: نوع L2TP/IPSec PSK، سرور همین دامنه، Secret همان PSK.",
        "authors": "نویسندگان: Navid Haghpanah",
        "guide_extra": "راهنمای اتصال — VLESS / Shadowsocks / Hysteria2",
        "guide_more": "راهنمای اتصال — VMess / HTTP / MTProto",
        "android_ike": "Android — IKEv2",
        "get_client": "دریافت کلاینت ←",
        "conn_info": "اطلاعات اتصال",
        "conn_info_p": "مقادیر مرجع برای راه‌اندازی دستی کلاینت",
        "conn_type": "نوع اتصال",
        "cert": "Certificate",
        "dns_now": "DNS فعلی",
        "card_sessions": "نشست‌های هم‌زمان",
        "card_sessions_p": "کنترل تعداد اتصال مجاز برای هر حساب",
        "max_sess": "حداکثر نشست برای هر کاربر",
        "max_sess_h": "بین ۱ تا ۱۰؛ سقف مجموع نشست‌های IKEv2 و L2TP هر کاربر. پروکسی‌ها محدودیت تعداد دستگاه ندارند.",
        "save_cleanup": "ذخیره و پاک‌سازی",
        "card_dns": "DNS تونل",
        "card_dns_p": "DNS کلاینت‌های VPN. از دکمه‌ها انتخاب کنید یا IP دلخواه بگذارید.",
        "dns_addrs": "آدرس‌های DNS",
        "dns_h": "حداکثر چهار IP، جداشده با ویرگول",
        "dns_presets": "انتخاب سریع",
        "save_dns": "ذخیره DNS",
        "card_profile": "پروفایل من",
        "card_profile_p": "نام و راه ارتباطی که فقط برای شما در پنل نمایش داده می‌شود",
        "display_name": "نام نمایشی",
        "contact": "راه ارتباطی (اختیاری)",
        "save_profile": "ذخیره پروفایل",
        "card_admin": "امنیت پنل",
        "card_admin_p": "تغییر رمز حساب مدیر %(user)s",
        "admin_pass": "رمز جدید مدیر",
        "admin_pass_ph": "حداقل ۱۲ نویسه",
        "admin_pass_h": "از یک رمز اختصاصی و طولانی استفاده کنید.",
        "change_admin": "تغییر رمز پنل",
        "card_psk": "کلید مشترک L2TP",
        "card_psk_p": "فقط برای اتصال‌های قدیمی L2TP",
        "new_psk": "PSK جدید",
        "save_psk": "ذخیره PSK",
        "card_domain": "دامنه IKEv2 / L2TP",
        "card_domain_p": "آدرس سرور و Remote ID کلاینت‌ها",
        "domain_now": "دامنه فعلی / جدید",
        "save_domain": "ذخیره دامنه",
        "card_update": "به‌روزرسانی پنل",
        "update_none": "مخزن گیت روی سرور پیدا نشد",
        "update_behind": "%(n)s کامیت جدید موجود است",
        "update_ok": "پنل به‌روز است",
        "ver_current": "نسخه فعلی",
        "ver_latest": "آخرین نسخه",
        "update_now": "به‌روزرسانی الان",
        "update_install": "نصب و به‌روزرسانی",
        "update_again": "بررسی و اعمال دوباره",
        "card_tg": "ربات تلگرام",
        "card_tg_on": "مدیریت کاربران از تلگرام — فعال (%(tok)s)",
        "card_tg_off": "مدیریت کاربران از تلگرام — غیرفعال",
        "tg_token": "توکن ربات (از BotFather)",
        "save_tg": "ذخیره تنظیمات ربات",
        "card_backup": "پشتیبان و بازیابی",
        "card_backup_p": "users.json، ترافیک و config.json — بدون فایل PSK آی‌پی‌سک",
        "download_backup": "دانلود پشتیبان",
        "restore": "بازیابی",
        "restore_h": "فایل zip پشتیبان را انتخاب کنید. تنظیمات و کاربران جایگزین می‌شوند.",
        "card_restart": "ری‌استارت پنل",
        "card_restart_p": "فقط سرویس وب؛ تونل‌های فعال قطع نمی‌شوند",
        "card_logs": "گزارش سرویس‌ها",
        "card_logs_p": "journalctl واحدهای پنل، xray، hysteria، mtg و nginx",
        "open_logs": "مشاهده گزارش‌ها",
        "login_title": "ورود — NH MultiVPN",
        "login_h": "ورود به NH MultiVPN",
        "login_p": "پنل مدیریت کاربران",
        "login_user": "نام کاربری پنل",
        "login_pass": "رمز عبور",
        "login_btn": "ورود",
        "proto_uri": "لینک اتصال (برای کپی کلیک کنید)",
        "port": "پورت",
        "server": "سرور",
        "back_clients": "بازگشت به کلاینت‌ها",
        "proto_only": "این کانفیگ فقط برای همین کاربر معتبر است؛ آن را با کسی به‌اشتراک نگذارید.",
        "copy_title": "برای کپی کلیک کنید",
        "csrf_bad": "درخواست نامعتبر یا منقضی شده است.",
        "login_csrf": "درخواست نامعتبر است؛ صفحه را تازه‌سازی کنید.",
        "login_lock": "تلاش‌های ورود زیاد بوده؛ چند دقیقه بعد دوباره امتحان کنید.",
        "login_bad": "نام کاربری یا رمز عبور اشتباه است.",
        "user_name_bad": "نام کاربری فقط حروف انگلیسی و عدد، ۲ تا ۳۲ نویسه.",
        "vpn_pass_bad": "رمز VPN باید ۱ تا ۱۲۸ نویسه باشد و شامل \" یا بک‌اسلش یا خط جدید نباشد.",
        "expires_bad": "تاریخ انقضا نامعتبر است.",
        "quota_bad": "حجم باید عدد باشد (۰ = نامحدود).",
        "user_exists": "این کاربر از قبل وجود دارد.",
        "user_added": "کاربر %(name)s اضافه شد (%(label)s).",
        "user_bad": "نام کاربری نامعتبر است.",
        "user_missing": "کاربر پیدا نشد.",
        "pass_bad": "رمز عبور نامعتبر است.",
        "quota_invalid": "حجم نامعتبر است.",
        "user_saved": "تنظیمات کاربر %(name)s ذخیره شد.",
        "user_deleted": "کاربر %(name)s حذف شد.",
        "old_marked": "%(n)s نشست قدیمی برای بسته‌شدن علامت‌گذاری شد.",
        "no_extra_sess": "نشست اضافه‌ای پیدا نشد.",
        "sess_id_bad": "شناسهٔ نشست نامعتبر است.",
        "sess_missing": "نشست پیدا نشد یا قبلاً بسته شده است.",
        "sess_marked": "نشست %(id)s برای بسته‌شدن علامت‌گذاری شد.",
        "domain_bad": "دامنه نامعتبر است.",
        "domain_ssl_ok": "دامنه IKEv2 / L2TP به %(domain)s تغییر کرد و گواهی SSL به‌روز شد.",
        "domain_ssl_fail": "دامنه %(domain)s ذخیره شد اما صدور گواهی SSL ناموفق بود؛ باید گواهی Let's Encrypt برای این دامنه صادر شود.%(extra)s",
        "psk_bad": "کلید مشترک باید ۱۶ تا ۱۲۸ نویسه و فقط شامل نویسه‌های امن انگلیسی باشد.",
        "psk_ok": "کلید مشترک (PSK) عوض شد. کلاینت‌های L2TP باید PSK جدید بزنند.",
        "dns_count": "یک تا چهار DNS وارد کنید.",
        "dns_bad": "DNS باید یک آدرس IPv4 یا IPv6 معتبر باشد.",
        "dns_ok": "DNS ذخیره شد. اتصال‌های بعدی با DNS جدید می‌آیند.",
        "admin_len": "رمز پنل باید ۱۲ تا ۱۲۸ نویسه باشد.",
        "admin_ok": "رمز ورود پنل عوض شد.",
        "profile_ok": "پروفایل ذخیره شد.",
        "sess_limit_bad": "تعداد نشست هم‌زمان باید بین ۱ تا ۱۰ باشد.",
        "sess_limit_cut": "محدودیت ذخیره شد و %(n)s نشست قدیمی بسته شد.",
        "sess_limit_ok": "محدودیت نشست‌های هم‌زمان ذخیره شد.",
        "tg_token_bad": "توکن ربات تلگرام نامعتبر است.",
        "tg_id_bad": "آیدی عددی تلگرام نامعتبر است: %(part)s",
        "tg_need_admin": "برای فعال‌کردن ربات باید حداقل یک آیدی عددی ادمین وارد کنید.",
        "tg_ok": "تنظیمات ربات تلگرام ذخیره و ربات ری‌استارت شد.",
        "tg_off": "ربات تلگرام غیرفعال شد.",
        "upd_ok": "پنل به‌روزرسانی شد و ری‌استارت شد.",
        "upd_fail": "به‌روزرسانی ناموفق بود. جزئیات: %(out)s",
        "no_domain": "دامنه در تنظیمات نیست.",
        "no_win_client": "فایل کلاینت ویندوز روی سرور نیست.",
        "ss_off": "Shadowsocks برای این کاربر فعال نیست.",
        "restart_ok": "پنل تا چند ثانیه دیگر ری‌استارت می‌شود.",
        "backup_ok": "پشتیبان بازیابی شد و کانفیگ سرویس‌ها بازنویسی شد.",
        "backup_bad": "فایل پشتیبان نامعتبر است.",
        "backup_missing": "فایل zip انتخاب نشده است.",
        "unit_b": "بایت",
        "unit_kb": "کیلوبایت",
        "unit_mb": "مگابایت",
        "unit_gb": "گیگابایت",
        "unit_tb": "ترابایت",
        "u_day": "روز",
        "u_hour": "ساعت",
        "u_min": "دقیقه",
        "per_sec": "/ثانیه",
        "blocked": "غیرفعال",
        "expired": "منقضی",
        "quota_full": "اتمام حجم",
        "quota_nan": "حجم نامعتبر",
        "nav_smart": "اتصال هوشمند",
        "smart_title": "اتصال هوشمند",
        "smart_sub": "رتبه‌بندی پروتکل از موجودی VPS و شرایط کلاینت",
        "smart_intro": "این صفحه اینترنت کلاینت را پروب نمی‌کند. پیش‌فرض فرم پروفایل فیلترینگ ایران است (با آپدیت پنل عوض می‌شود). رتبه از موجودی همین سرور + فرم + آن پروفایل است؛ باز بودن پورت از ISP ادعا نمی‌شود مگر خودتان در فرم گفته باشید.",
        "smart_filter": "فیلترینگ",
        "smart_filter_iran": "ایران (پیش‌فرض، با آپدیت پنل)",
        "smart_filter_none": "فقط فرم — بدون پروفایل کشور",
        "smart_user": "کاربر",
        "smart_os": "سیستم‌عامل / کلاینت",
        "smart_net": "شبکه",
        "smart_udp": "UDP",
        "smart_path": "مسیر TCP",
        "smart_native": "ترجیح VPN داخلی سیستم‌عامل",
        "smart_os_windows": "ویندوز",
        "smart_os_ios": "iOS",
        "smart_os_android": "اندروید",
        "smart_os_linux": "لینوکس",
        "smart_os_mac": "macOS",
        "smart_os_telegram": "تلگرام",
        "smart_net_wifi": "وای‌فای",
        "smart_net_mobile": "موبایل",
        "smart_net_unknown": "نامشخص",
        "smart_udp_ok": "باز / سالم",
        "smart_udp_blocked": "مسدود",
        "smart_udp_unknown": "نامشخص",
        "smart_path_extra": "پورت‌های غیر از ۸۰/۴۴۳ احتمالاً بازند",
        "smart_path_only443": "فقط TCP ۸۰/۴۴۳",
        "smart_path_unknown": "نامشخص",
        "smart_submit": "رتبه‌بندی کن",
        "smart_results": "پیشنهادهای رتبه‌بندی‌شده",
        "smart_rank": "رتبه",
        "smart_score": "امتیاز",
        "smart_reason": "دلیل",
        "smart_uri": "لینک اتصال",
        "smart_host_user": "میزبان و کاربر (URI ساختگی ندارد)",
        "smart_open": "صفحهٔ کلاینت این پروتکل",
        "smart_inventory": "موجودی این VPS",
        "smart_inventory_p": "سرویس و پورت پیکربندی‌شده روی سرور؛ یعنی «اینجا گوش می‌دهد»، نه «از ISP کلاینت می‌رسد».",
        "smart_le": "گواهی Let’s Encrypt دامنه",
        "smart_reality": "کلیدهای Reality",
        "smart_ufw": "ufw",
        "smart_yes": "هست",
        "smart_no": "نیست",
        "smart_unk": "نامشخص",
        "smart_svc": "سرویس‌ها",
        "smart_ports": "پورت‌های پیکربندی",
        "smart_no_users": "ابتدا یک کاربر بسازید.",
        "smart_no_match": "با این شرایط هیچ پروتکل مناسبی نماند. پورت اضافه یا UDP احتمالاً مسدود فرض شده‌اند.",
        "smart_honest_443": "فقط TCP ۸۰/۴۴۳ و UDP مسدود: پورت‌های اضافه (۸۴۴۳ / ۲۰۵۳ / ۱۰۸۰۹ / ۳۱۲۸ / Shadowsocks) احتمالاً کار نمی‌کنند. IKEv2 و L2TP به UDP ۵۰۰/۱۷۰۱ نیاز دارند. Hysteria2 به UDP ۴۴۳ نیاز دارد.",
        "smart_ai_box": "بازبینی مدل",
        "smart_ai_none": "Gateway یا کلید تنظیم نشده؛ فقط رتبهٔ قاعده‌ای.",
        "smart_ai_fail": "بازبینی مدل ناموفق بود؛ همان رتبهٔ قاعده‌ای ماند.",
        "smart_ai_changed": "مدل رتبه را عوض کرد",
        "smart_ai_kept": "مدل همان رتبه را تأیید کرد",
        "smart_pick": "پیشنهاد اول",
        "smart_skipped": "ردشده",
        "card_ai": "اتصال هوشمند — مدل (اختیاری)",
        "card_ai_p": "Gateway سازگار با OpenAI. رتبهٔ قاعده‌ای بدون کلید هم کار می‌کند. اگر کلید باشد مدل همان کاندیداها را بازبینی می‌کند و می‌تواند ترتیب و امتیاز را عوض کند، ولی پروتکل یا پورت تازه اختراع نمی‌کند.",
        "ai_base": "Gateway URL",
        "ai_base_h": "آدرس کامل Gateway سازگار با OpenAI را بچسبانید (معمولاً با /v1).",
        "ai_base_ph": "https://…/v1",
        "ai_model": "model",
        "ai_model_h": "شناسهٔ دقیق مدل همان endpoint را بچسبانید؛ از پیش پر نمی‌شود.",
        "ai_api_key": "API key",
        "ai_api_key_h": "اگر خالی بماند کلید قبلی حفظ می‌شود.",
        "ai_api_key_clear": "حذف کلید ذخیره‌شده",
        "save_ai": "ذخیرهٔ تنظیمات مدل",
        "ai_ok": "تنظیمات مدل ذخیره شد.",
        "ai_base_bad": "Gateway URL نامعتبر است؛ فقط HTTPS عمومی، بدون اطلاعات ورود، localhost یا نشانی خصوصی.",
        "card_totp": "Google Authenticator",
        "card_totp_p": "ورود دو مرحله‌ای با برنامه Authenticator (Google / Aegis / Authy).",
        "card_totp_on": "Authenticator فعال است. برای ورود علاوه بر رمز، کد ۶ رقمی لازم است.",
        "totp_add": "افزودن Authenticator",
        "totp_scan": "QR را با Authenticator اسکن کنید، یا کلید را دستی وارد کنید.",
        "totp_code": "کد ۶ رقمی",
        "totp_enable": "فعال کردن",
        "totp_off": "خاموش کردن Authenticator",
        "totp_off_confirm": "ورود دو مرحله‌ای خاموش شود؟",
        "totp_ok": "Authenticator فعال شد.",
        "totp_bad": "کد Authenticator نادرست است.",
        "totp_disabled": "Authenticator خاموش شد.",
        "login_totp": "کد Authenticator",
    },
    "en": {
        "brand_sub": "Private network admin",
        "server_live": "Server online",
        "nav_manage": "Manage",
        "nav_dash": "Dashboard",
        "nav_users": "Users",
        "nav_sessions": "Sessions",
        "nav_clients": "Clients",
        "nav_system": "System",
        "nav_settings": "Settings",
        "nav_logs": "Logs",
        "logout": "Log out",
        "admin_fallback": "Admin",
        "admin_role": "System admin",
        "live": "Service online",
        "stale": "Stale data",
        "cpu": "CPU",
        "ram": "RAM",
        "theme_to_light": "Light",
        "theme_to_dark": "Dark",
        "restart": "Restart panel",
        "restart_confirm": "Restart the web panel? VPN tunnels stay up.",
        "update": "Update",
        "update_confirm": "Update panel? Deleted accounts will be disconnected; proxy connections may briefly reconnect.",
        "confirm_title": "Confirm",
        "cancel": "Cancel",
        "confirm": "Confirm",
        "copied": "Copied ✓",
        "show_pass": "Show",
        "hide_pass": "Hide",
        "working": "Working…",
        "menu": "Menu",
        "dash_title": "Dashboard",
        "dash_sub": "Server overview and live connections",
        "users_title": "Users",
        "users_sub": "Create accounts and manage quota and expiry",
        "sessions_title": "Sessions",
        "sessions_sub": "Live connections and cleanup",
        "clients_title": "Clients",
        "clients_sub": "Ready-made connection files",
        "settings_title": "Settings",
        "settings_sub": "Security, DNS, backup and session limits",
        "logs_title": "Logs",
        "logs_sub": "Last 200 journalctl lines for panel services",
        "online_users": "Online users",
        "of_accounts": "of %(total)s accounts",
        "active_sessions": "Active sessions",
        "ike_l2": "IKEv2 and L2TP",
        "sys_load": "Load",
        "cpu_cores": "%(n)s CPU cores",
        "uptime": "Uptime",
        "recent_sessions": "Recent sessions",
        "recent_sessions_p": "Latest active connections",
        "view_all": "View all →",
        "col_user": "User",
        "col_proto": "Protocol",
        "col_vip": "Internal IP",
        "col_remote": "Public IP",
        "col_uptime": "Duration",
        "col_traffic": "Traffic",
        "unknown": "Unknown",
        "no_sessions": "No active sessions.",
        "resources": "Server resources",
        "resources_p": "Live system status",
        "healthy": "Healthy",
        "processor": "CPU",
        "memory": "RAM",
        "of": "of",
        "disk": "Disk",
        "net_traffic": "Network",
        "net_traffic_p": "Live speed and totals on %(iface)s",
        "down_speed": "↓ Download",
        "up_speed": "↑ Upload",
        "rx_total": "Total download since boot",
        "tx_total": "Total upload since boot",
        "server_ip": "Server IP",
        "speed_test": "Speed test",
        "speed_test_p": "Measures this VPS uplink, not your phone or laptop.",
        "speed_run": "Run speed test",
        "speed_running": "Testing…",
        "speed_down": "Download",
        "speed_up": "Upload",
        "speed_ping": "Ping",
        "speed_fail": "Speed test failed.",
        "speed_idle": "Not run yet",
        "speed_start": "Start",
        "speed_end": "End",
        "mbps": "Mbps",
        "ms": "ms",
        "quick": "Quick actions",
        "quick_p": "Common admin tasks",
        "quick_add": "New user",
        "quick_add_p": "Create a VPN account",
        "quick_sess": "Sessions",
        "quick_sess_p": "Drop old connections",
        "quick_cli": "Get clients",
        "quick_cli_p": "Windows and iPhone files",
        "quick_set": "Settings",
        "quick_set_p": "DNS, security and limits",
        "online_now": "Online users",
        "online_now_p": "Accounts connected right now",
        "nobody_online": "Nobody is online.",
        "all_accounts": "Accounts",
        "offline": "Offline",
        "online": "Online",
        "max_per_user": "Sessions per user",
        "add_user": "Add user",
        "add_user_p": "Name, password and optional limits.",
        "username": "Username",
        "password": "Password",
        "pass_ph": "Any password (1–128 characters)",
        "expires": "Expiry",
        "expires_hint": "Empty means never",
        "quota": "Quota (GB)",
        "quota_hint": "Zero means unlimited. MTProto is available only for unlimited-quota accounts.",
        "create_user": "+ Create user",
        "user_list": "Users",
        "user_list_p": "Edit quota, expiry and password without showing the current one",
        "n_users": "%(n)s users",
        "col_status": "Status",
        "col_expires": "Expiry",
        "col_quota": "Used / quota",
        "col_edit": "Edit",
        "unlimited": "Unlimited",
        "created": "Created",
        "no_users": "No users yet.",
        "edit_account": "Edit account",
        "edit_account_p": "Account settings",
        "new_pass": "New password",
        "keep_pass": "Leave empty to keep",
        "active_protos": "Enabled protocols",
        "reset_traffic": "Reset this user's traffic",
        "save": "Save",
        "close": "Close",
        "delete_user_q": "Delete %(name)s? This cannot be undone.",
        "delete_user": "Delete user",
        "delete_user_aria": "Delete %(name)s",
        "cap_per_user": "Cap per user",
        "cleanup_old": "Clean old sessions",
        "sess_info": "The newest %(n)s sessions per user are kept. Extra sessions are dropped within about 20 seconds.",
        "live_conns": "Live connections",
        "live_conns_p": "Use the end-of-row button to drop an IKEv2 session immediately.",
        "col_id": "ID",
        "col_duration": "Duration",
        "col_du": "Down / up",
        "drop_conn": "Drop",
        "drop_conn_q": "Drop session #%(id)s for %(user)s?",
        "drop_title": "Drop connection",
        "no_conn": "No active connections.",
        "recommended": "Recommended",
        "win_title": "Windows — IKEv2",
        "win_p": "Automatic IKEv2 profile plus a checker",
        "dl_zip": "Download ZIP",
        "ready_profile": "Ready profile",
        "ios_title": "iPhone / iPad — IKEv2",
        "ios_p": "Standard profile for a quick IKEv2 connect",
        "dl_mobileconfig": "Download mobileconfig",
        "guide_ike": "Connect — IKEv2",
        "guide_l2": "Connect — L2TP",
        "ike_step1": "Windows / strongSwan / Samsung: IKEv2 MSCHAPv2.",
        "ike_step3": "Certificate: None. Same panel user.",
        "l2_step1": "Windows: L2TP/IPsec with pre-shared key. iPhone: Add VPN → L2TP.",
        "l2_step2": "UDP 1701. xl2tpd is not restarted.",
        "l2_step3": "PSK from panel Settings. User/pass same as IKEv2. L2TP checkbox must be on.",
        "android_l2": "Android L2TP: type L2TP/IPSec PSK, server this domain, Secret = PSK.",
        "authors": "Authors: Navid Haghpanah",
        "guide_extra": "Connect — VLESS / Shadowsocks / Hysteria2",
        "guide_more": "Connect — VMess / HTTP / MTProto",
        "android_ike": "Android — IKEv2",
        "get_client": "Get clients →",
        "conn_info": "Connection info",
        "conn_info_p": "Reference values for a manual client",
        "conn_type": "Type",
        "cert": "Certificate",
        "dns_now": "Current DNS",
        "card_sessions": "Concurrent sessions",
        "card_sessions_p": "How many connections each account may keep",
        "max_sess": "Max sessions per user",
        "max_sess_h": "1 to 10; combined IKEv2/L2TP sessions per user. Proxy protocols do not enforce device limits.",
        "save_cleanup": "Save and clean",
        "card_dns": "Tunnel DNS",
        "card_dns_p": "DNS pushed to VPN clients. Pick a preset or type IPs.",
        "dns_addrs": "DNS addresses",
        "dns_h": "Up to four IPs, comma-separated",
        "dns_presets": "Quick pick",
        "save_dns": "Save DNS",
        "card_profile": "My profile",
        "card_profile_p": "Name and contact shown only to you",
        "display_name": "Display name",
        "contact": "Contact (optional)",
        "save_profile": "Save profile",
        "card_admin": "Panel security",
        "card_admin_p": "Change password for admin %(user)s",
        "admin_pass": "New admin password",
        "admin_pass_ph": "At least 12 characters",
        "admin_pass_h": "Use a long, unique password.",
        "change_admin": "Change panel password",
        "card_psk": "L2TP shared key",
        "card_psk_p": "Only for legacy L2TP",
        "new_psk": "New PSK",
        "save_psk": "Save PSK",
        "card_domain": "IKEv2 / L2TP domain",
        "card_domain_p": "Server address and client Remote ID",
        "domain_now": "Current / new domain",
        "save_domain": "Save domain",
        "card_update": "Update panel",
        "update_none": "Git repo not found on the server",
        "update_behind": "%(n)s new commits available",
        "update_ok": "Panel is up to date",
        "ver_current": "Current",
        "ver_latest": "Latest",
        "update_now": "Update now",
        "update_install": "Install and update",
        "update_again": "Check and apply again",
        "card_tg": "Telegram bot",
        "card_tg_on": "Manage users from Telegram — on (%(tok)s)",
        "card_tg_off": "Manage users from Telegram — off",
        "tg_token": "Bot token (BotFather)",
        "save_tg": "Save bot settings",
        "card_backup": "Backup and restore",
        "card_backup_p": "users.json, traffic files and config.json — not the IPsec PSK file",
        "download_backup": "Download backup",
        "restore": "Restore",
        "restore_h": "Choose a backup zip. Users and config will be replaced.",
        "card_restart": "Restart panel",
        "card_restart_p": "Web service only; live tunnels stay up",
        "card_logs": "Service logs",
        "card_logs_p": "journalctl for panel, xray, hysteria, mtg and nginx",
        "open_logs": "Open logs",
        "login_title": "Login — NH MultiVPN",
        "login_h": "Sign in to NH MultiVPN",
        "login_p": "User admin panel",
        "login_user": "Panel username",
        "login_pass": "Password",
        "login_btn": "Sign in",
        "proto_uri": "URI (click to copy)",
        "port": "Port",
        "server": "Server",
        "back_clients": "Back to clients",
        "proto_only": "This config is only for this user; do not share it.",
        "copy_title": "Click to copy",
        "csrf_bad": "Invalid or expired request.",
        "login_csrf": "Invalid request; refresh the page.",
        "login_lock": "Too many login attempts; try again in a few minutes.",
        "login_bad": "Wrong username or password.",
        "user_name_bad": "Username: English letters and digits, 2–32 characters.",
        "vpn_pass_bad": "VPN password must be 1–128 characters and cannot contain \", backslash, or newlines.",
        "expires_bad": "Invalid expiry date.",
        "quota_bad": "Quota must be a number (0 = unlimited).",
        "user_exists": "That user already exists.",
        "user_added": "User %(name)s added (%(label)s).",
        "user_bad": "Invalid username.",
        "user_missing": "User not found.",
        "pass_bad": "Invalid password.",
        "quota_invalid": "Invalid quota.",
        "user_saved": "Saved settings for %(name)s.",
        "user_deleted": "Deleted %(name)s.",
        "old_marked": "%(n)s old sessions marked to drop.",
        "no_extra_sess": "No extra sessions found.",
        "sess_id_bad": "Invalid session id.",
        "sess_missing": "Session not found or already closed.",
        "sess_marked": "Session %(id)s marked to drop.",
        "domain_bad": "Invalid domain.",
        "domain_ssl_ok": "IKEv2 / L2TP domain changed to %(domain)s and the SSL cert was updated.",
        "domain_ssl_fail": "Domain %(domain)s saved but SSL issuance failed; a Let's Encrypt cert is still needed.%(extra)s",
        "psk_bad": "PSK must be 16–128 English-safe characters.",
        "psk_ok": "PSK changed. L2TP clients must use the new key.",
        "dns_count": "Enter one to four DNS servers.",
        "dns_bad": "DNS must be a valid IPv4 or IPv6 address.",
        "dns_ok": "DNS saved. New connections will use it.",
        "admin_len": "Panel password must be 12–128 characters.",
        "admin_ok": "Panel password changed.",
        "profile_ok": "Profile saved.",
        "sess_limit_bad": "Concurrent sessions must be 1–10.",
        "sess_limit_cut": "Limit saved and %(n)s old sessions dropped.",
        "sess_limit_ok": "Concurrent session limit saved.",
        "tg_token_bad": "Invalid Telegram bot token.",
        "tg_id_bad": "Invalid Telegram numeric id: %(part)s",
        "tg_need_admin": "Enter at least one admin numeric id to enable the bot.",
        "tg_ok": "Telegram bot settings saved and the bot restarted.",
        "tg_off": "Telegram bot disabled.",
        "upd_ok": "Panel updated and restarted.",
        "upd_fail": "Update failed. Details: %(out)s",
        "no_domain": "Domain is not set.",
        "no_win_client": "Windows client files are missing on the server.",
        "ss_off": "Shadowsocks is not enabled for this user.",
        "restart_ok": "The panel will restart in a moment.",
        "backup_ok": "Backup restored and service configs rewritten.",
        "backup_bad": "Invalid backup file.",
        "backup_missing": "No zip file selected.",
        "unit_b": "B",
        "unit_kb": "KB",
        "unit_mb": "MB",
        "unit_gb": "GB",
        "unit_tb": "TB",
        "u_day": "d",
        "u_hour": "h",
        "u_min": "m",
        "per_sec": "/s",
        "blocked": "disabled",
        "expired": "expired",
        "quota_full": "quota used",
        "quota_nan": "invalid quota",
        "nav_smart": "Smart Connect",
        "smart_title": "Smart Connect",
        "smart_sub": "Rank the best protocol from VPS inventory and client conditions",
        "smart_intro": "This page does not probe the client ISP. Form defaults use the Iran filtering profile (ships with panel updates). Ranking is this VPS inventory + the form + that profile. A port is not claimed reachable unless the form said so.",
        "smart_filter": "Filtering",
        "smart_filter_iran": "Iran (default, with panel updates)",
        "smart_filter_none": "Form only — no country profile",
        "smart_user": "User",
        "smart_os": "OS / client",
        "smart_net": "Network",
        "smart_udp": "UDP",
        "smart_path": "TCP path",
        "smart_native": "Prefer OS built-in VPN",
        "smart_os_windows": "Windows",
        "smart_os_ios": "iOS",
        "smart_os_android": "Android",
        "smart_os_linux": "Linux",
        "smart_os_mac": "macOS",
        "smart_os_telegram": "Telegram",
        "smart_net_wifi": "Wi-Fi",
        "smart_net_mobile": "Mobile",
        "smart_net_unknown": "Unknown",
        "smart_udp_ok": "OK / open",
        "smart_udp_blocked": "Blocked",
        "smart_udp_unknown": "Unknown",
        "smart_path_extra": "Non-80/443 TCP is likely open",
        "smart_path_only443": "Only TCP 80/443",
        "smart_path_unknown": "Unknown",
        "smart_submit": "Rank protocols",
        "smart_results": "Ranked recommendations",
        "smart_rank": "Rank",
        "smart_score": "Score",
        "smart_reason": "Reason",
        "smart_uri": "Connection URI",
        "smart_host_user": "Host and user (no fake URI)",
        "smart_open": "Open this protocol’s client page",
        "smart_inventory": "This VPS inventory",
        "smart_inventory_p": "Configured listeners and flags on the server — not a client-ISP reachability test.",
        "smart_le": "Let’s Encrypt cert for domain",
        "smart_reality": "Reality keys",
        "smart_ufw": "ufw",
        "smart_yes": "yes",
        "smart_no": "no",
        "smart_unk": "unknown",
        "smart_svc": "Services",
        "smart_ports": "Configured ports",
        "smart_no_users": "Create a user first.",
        "smart_no_match": "No protocol fits these conditions. Extra TCP ports or UDP were treated as blocked.",
        "smart_honest_443": "Only TCP 80/443 and UDP blocked: extra ports (8443 / 2053 / 10809 / 3128 / Shadowsocks) probably will not work. IKEv2/L2TP need UDP 500/1701. Hysteria2 needs UDP 443.",
        "smart_ai_box": "Model review",
        "smart_ai_none": "No Gateway or API key; rules ranking only.",
        "smart_ai_fail": "Model review failed; keeping the rules ranking.",
        "smart_ai_changed": "Model changed the ranking",
        "smart_ai_kept": "Model kept the rules ranking",
        "smart_pick": "Top pick",
        "smart_skipped": "Skipped",
        "card_ai": "Smart Connect — model (optional)",
        "card_ai_p": "OpenAI-compatible chat gateway. Rules ranking works with no key. With a key, the model reviews those candidates and may change order and scores, but must not invent protocols or ports.",
        "ai_base": "Gateway URL",
        "ai_base_h": "Paste the full OpenAI-compatible Gateway URL (usually ending in /v1).",
        "ai_base_ph": "https://…/v1",
        "ai_model": "model",
        "ai_model_h": "Paste the exact model id from that endpoint; nothing is pre-filled.",
        "ai_api_key": "API key",
        "ai_api_key_h": "Leave empty to keep the stored key.",
        "ai_api_key_clear": "Remove stored key",
        "save_ai": "Save model settings",
        "ai_ok": "Model settings saved.",
        "ai_base_bad": "Invalid Gateway URL; use public HTTPS with no credentials, localhost, or private addresses.",
        "card_totp": "Google Authenticator",
        "card_totp_p": "Two-factor login with an Authenticator app (Google / Aegis / Authy).",
        "card_totp_on": "Authenticator is on. Login needs the 6-digit code as well as the password.",
        "totp_add": "Add Authenticator",
        "totp_scan": "Scan the QR with Authenticator, or type the key by hand.",
        "totp_code": "6-digit code",
        "totp_enable": "Enable",
        "totp_off": "Turn off Authenticator",
        "totp_off_confirm": "Turn off two-factor login?",
        "totp_ok": "Authenticator enabled.",
        "totp_bad": "Authenticator code is wrong.",
        "totp_disabled": "Authenticator turned off.",
        "login_totp": "Authenticator code",
    },
}

COOKIE_MAX_AGE = 60 * 60 * 24 * 365
LOG_UNITS = (
    "ikev2-l2tp-gui",
    "panel-shadowsocks",
    "panel-hysteria",
    "panel-mtg",
    "panel-telegram-bot",
    "nginx",
)

app = Flask(
    __name__,
    template_folder=str(APP_DIR / "templates"),
    static_folder=str(APP_DIR / "static"),
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 60 * 60 * 12
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

_cpu_prev = None
_net_prev = None
_lock = StateLock(DATA_DIR / "state.lock")
state_transaction = _lock.transaction
_login_attempts = {}
LOGIN_WINDOW = 15 * 60
LOGIN_MAX_ATTEMPTS = 5


def fa(v):
    return str(v).translate(FA_D)


def current_lang():
    try:
        cookie = (request.cookies.get("nh_lang") or "").strip()
        if cookie in ("fa", "en"):
            return cookie
    except RuntimeError:
        pass
    lang = (load_config().get("lang") or "fa")
    return lang if lang in ("fa", "en") else "fa"


def current_theme():
    try:
        cookie = (request.cookies.get("nh_theme") or "").strip()
        if cookie in ("dark", "light"):
            return cookie
    except RuntimeError:
        pass
    theme = (load_config().get("theme") or "dark")
    return theme if theme in ("dark", "light") else "dark"


class I18NView:
    """Jinja t.update must not resolve to dict.update()."""

    __slots__ = ("_t",)

    def __init__(self, table):
        object.__setattr__(self, "_t", table or {})

    def __getattr__(self, key):
        # Dunders like __html__ must AttributeError; otherwise MarkupSafe
        # thinks this object is HTML-safe and every template can 500.
        if key.startswith("_"):
            raise AttributeError(key)
        table = object.__getattribute__(self, "_t")
        if key in table:
            return table[key]
        fa = I18N.get("fa") or {}
        if key in fa:
            return fa[key]
        return key

    def __getitem__(self, key):
        return self.__getattr__(key)


def tr(key, **kwargs):
    lang = current_lang()
    table = I18N.get(lang) or I18N["fa"]
    text = table.get(key) or I18N["fa"].get(key) or key
    if kwargs:
        try:
            return text % kwargs
        except (TypeError, ValueError, KeyError):
            return text
    return text


def flash_t(key, **kwargs):
    flash(tr(key, **kwargs))


def set_ui_cookies(resp, theme=None, lang=None):
    if theme in ("dark", "light"):
        resp.set_cookie(
            "nh_theme",
            theme,
            max_age=COOKIE_MAX_AGE,
            httponly=False,
            samesite="Lax",
            secure=True,
            path="/",
        )
    if lang in ("fa", "en"):
        resp.set_cookie(
            "nh_lang",
            lang,
            max_age=COOKIE_MAX_AGE,
            httponly=False,
            samesite="Lax",
            secure=True,
            path="/",
        )
    return resp


def flag_on(u, key, default=True):
    if not isinstance(u, dict) or key not in u:
        return default
    return bool(u.get(key))


def vpn_password_ok(value):
    if not isinstance(value, str):
        return False
    if not (1 <= len(value) <= 128):
        return False
    if '"' in value or "\\" in value:
        return False
    if "\r" in value or "\n" in value or "\x00" in value:
        return False
    return True


def now_tehran():
    return datetime.now(TZ)


def today_iso():
    return now_tehran().date().isoformat()


def human(n, lang=None):
    try:
        n = float(n)
    except (TypeError, ValueError):
        n = 0
    lang = lang or current_lang()
    units = (tr("unit_b"), tr("unit_kb"), tr("unit_mb"), tr("unit_gb"), tr("unit_tb"))
    last = units[-1]
    for unit in units:
        if n < 1024 or unit == last:
            if unit == units[0]:
                s = "%d %s" % (int(n), unit)
            else:
                s = "%.1f %s" % (n, unit)
            return fa(s) if lang == "fa" else s
        n /= 1024.0
    s = "%.1f %s" % (n, last)
    return fa(s) if lang == "fa" else s


class CommandOutput(str):
    def __new__(cls, value, returncode=0):
        result = super().__new__(cls, value)
        result.returncode = returncode
        return result


def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return CommandOutput((p.stdout or "") + (p.stderr or ""), p.returncode)
    except Exception as e:
        return CommandOutput(str(e), -1)


def run_checked(cmd, timeout=10):
    output = run(cmd, timeout=timeout)
    if getattr(output, "returncode", 0) != 0:
        raise RuntimeError("Command failed: " + str(cmd[0]))
    return output


def save_private_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", delete=False) as stream:
            tmp = Path(stream.name)
            os.chmod(tmp, 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(path)
    finally:
        if tmp and tmp.exists():
            tmp.unlink()


def load_json(path, default):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
    if default is None:
        return data
    if not isinstance(data, type(default)):
        return default
    return data


@state_transaction
def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", delete=False) as stream:
            tmp = Path(stream.name)
            os.chmod(tmp, 0o600)
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        tmp.replace(path)
    finally:
        if tmp and tmp.exists():
            tmp.unlink()


@state_transaction
def load_config():
    cfg = load_json(
        CONFIG_FILE,
        {
            "domain": "",
            "public_ip": "",
            "psk": "",
            "dns": ["9.9.9.9", "1.0.0.1"],
            "interface": "",
            "max_sessions_per_user": 1,
        },
    )
    changed = False
    if "ss_next_port" not in cfg:
        cfg["ss_next_port"] = 8388
        changed = True
    if "hy_port" not in cfg:
        cfg["hy_port"] = 443
        changed = True
    if not cfg.get("hy_stats_secret"):
        cfg["hy_stats_secret"] = secrets.token_urlsafe(24)
        changed = True
    if "telegram_bot_token" not in cfg:
        cfg["telegram_bot_token"] = ""
        changed = True
    if "telegram_admin_ids" not in cfg:
        cfg["telegram_admin_ids"] = []
        changed = True
    if "vless_port" not in cfg:
        cfg["vless_port"] = 8443
        changed = True
    if not cfg.get("hy_obfs_password"):
        cfg["hy_obfs_password"] = secrets.token_urlsafe(16)
        changed = True
    if "vmess_port" not in cfg:
        cfg["vmess_port"] = 2053
        changed = True
    if "http_port" not in cfg:
        cfg["http_port"] = 10809
        changed = True
    if "mtg_port" not in cfg:
        cfg["mtg_port"] = 3128
        changed = True
    if not cfg.get("mtg_domain"):
        cfg["mtg_domain"] = "cloudflare.com"
        changed = True
    if not cfg.get("reality_dest"):
        cfg["reality_dest"] = "www.microsoft.com:443"
        changed = True
    names = cfg.get("reality_server_names")
    if not isinstance(names, list) or not names:
        cfg["reality_server_names"] = ["www.microsoft.com"]
        changed = True
    if cfg.get("theme") not in ("dark", "light"):
        cfg["theme"] = "dark"
        changed = True
    if cfg.get("lang") not in ("fa", "en"):
        cfg["lang"] = "fa"
        changed = True
    if "ai_base" not in cfg:
        cfg["ai_base"] = ""
        changed = True
    if "ai_model" not in cfg:
        cfg["ai_model"] = ""
        changed = True
    if "ai_api_key" not in cfg:
        cfg["ai_api_key"] = ""
        changed = True
    if changed:
        save_json(CONFIG_FILE, cfg)
    return cfg


def allocate_ss_port():
    # Caller must already hold _lock (called from users_add/users_update).
    cfg = load_config()
    port = int(cfg.get("ss_next_port") or 8388)
    users = load_users()
    reserved = {int(u.get(k) or 0) for u in users.values() for k in ("ss_port", "http_port")}
    reserved.update(int(cfg.get(k) or default) for k, default in
                    (("vless_port", 8443), ("vmess_port", 2053), ("mtg_port", 3128), ("http_port", 10809)))
    while port in reserved:
        port += 1
    if port > 65535:
        raise ValueError("No free Shadowsocks port")
    cfg["ss_next_port"] = port + 1
    save_config(cfg)
    return port


def save_config(cfg):
    save_json(CONFIG_FILE, cfg)


@state_transaction
def load_admin():
    data = load_json(ADMIN_FILE, {})
    if not data.get("secret"):
        data["secret"] = secrets.token_hex(32)
        try:
            if ADMIN_FILE.parent.is_dir():
                save_admin(data)
        except OSError:
            pass
    app.secret_key = data["secret"]
    # Installation requires TLS. Never downgrade session cookies to HTTP.
    app.config["SESSION_COOKIE_SECURE"] = True
    return data


def save_admin(data):
    save_json(ADMIN_FILE, data)


def totp_new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_at(secret, when):
    pad = secret + "=" * ((8 - len(secret) % 8) % 8)
    try:
        key = base64.b32decode(pad, casefold=True)
    except Exception:
        return ""
    counter = int(when // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    num = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return "%06d" % (num % 1000000)


def totp_ok(secret, code):
    digits = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(digits) != 6 or not secret:
        return False
    now = time.time()
    for delta in (-1, 0, 1):
        expected = totp_at(secret, now + delta * 30)
        if expected and secrets.compare_digest(expected, digits):
            return True
    return False


def totp_otpauth(secret, user, host):
    label = urllib.parse.quote("NH MultiVPN:" + (user or "admin"), safe="")
    issuer = urllib.parse.quote("NH MultiVPN", safe="")
    return "otpauth://totp/%s?secret=%s&issuer=%s&period=30&digits=6" % (label, secret, issuer)


def load_users():
    data = load_json(USERS_FILE, {})
    if not isinstance(data, dict):
        return {}
    out = {}
    for name, u in data.items():
        if isinstance(name, str) and USER_RE.match(name) and isinstance(u, dict):
            out[name] = u
        elif isinstance(name, str) and isinstance(u, dict):
            # keep oddly-named records so we do not silently drop them
            out[name] = u
    return out


def save_users(users):
    save_json(USERS_FILE, users)


def deleted_user_names():
    data = load_json(DELETED_USERS_FILE, [])
    return {str(name).casefold() for name in data if isinstance(name, str)}


def remember_deleted_user(name):
    names = deleted_user_names()
    names.add(name.casefold())
    save_json(DELETED_USERS_FILE, sorted(names))


def forget_deleted_user(name):
    names = deleted_user_names()
    if name.casefold() in names:
        names.remove(name.casefold())
        save_json(DELETED_USERS_FILE, sorted(names))


def find_user_record(users, identity):
    if identity in users:
        return users[identity]
    folded = str(identity or "").casefold()
    for name, user in users.items():
        if name.casefold() == folded:
            return user
    return None


@app.before_request
def invalidate_stale_sessions():
    if session.get("ok") and session.get("auth_version", 0) != load_admin().get("auth_version", 0):
        session.clear()


def login_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        admin = load_admin()
        if not session.get("ok") or session.get("auth_version", 0) != admin.get("auth_version", 0):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"error": "auth"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrap


def csrf_token():
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


@app.context_processor
def csrf_context():
    lang = current_lang()
    return {
        "csrf_token": csrf_token,
        "lang": lang,
        "theme": current_theme(),
        "t": I18NView(I18N.get(lang) or I18N["fa"]),
        "content_dir": "rtl" if lang == "fa" else "ltr",
    }


def _same_host_redirect(fallback):
    dest = fallback
    ref = request.referrer
    if ref:
        try:
            parsed = urllib.parse.urlparse(ref)
            if parsed.scheme in ("http", "https") and parsed.netloc == request.host:
                dest = ref
        except ValueError:
            pass
    return redirect(dest)


def csrf_required(fn):
    @wraps(fn)
    def wrap(*args, **kwargs):
        submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRFToken", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            flash_t("csrf_bad")
            fallback = url_for("index") if session.get("ok") else url_for("login")
            return _same_host_redirect(fallback)
        return fn(*args, **kwargs)

    return wrap


@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src https://fonts.gstatic.com; script-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    )
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if "nh_theme" not in request.cookies:
        set_ui_cookies(response, theme=current_theme())
    if "nh_lang" not in request.cookies:
        set_ui_cookies(response, lang=current_lang())
    return response


def parse_secrets_users():
    found = []
    if IPSEC_SECRETS.exists():
        for raw in IPSEC_SECRETS.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r'^([A-Za-z0-9._-]+)\s*:\s*EAP\s+"([^"]*)"\s*$', raw.strip())
            if m:
                found.append((m.group(1), m.group(2)))
    return found


@state_transaction
def import_secrets_if_needed():
    # users.json is authoritative. Never resurrect a deleted account from
    # stale system credentials or overwrite its newer password.
    if USERS_FILE.exists():
        return load_users()
    users = load_users()
    if not isinstance(users, dict):
        users = {}
    changed = False
    for name, pw in parse_secrets_users():
        if name not in users:
            users[name] = {
                "password": pw,
                "expires": "",
                "quota_gb": 0,
                "used_bytes": 0,
                "created": today_iso(),
                "enabled": True,
            }
            changed = True
        elif users[name].get("password") != pw:
            users[name]["password"] = pw
            changed = True
    if changed:
        save_users(users)
    return users


def user_blocked(u):
    if not u.get("enabled", True):
        return tr("blocked")
    exp = u.get("expires") or ""
    if not isinstance(exp, str):
        return tr("expired")
    exp = exp.strip()
    if exp:
        try:
            expiry = date.fromisoformat(exp)
            # Older Iranian installations may contain a Jalali-looking year
            # (for example 1405-01-01) in this field. Treat values outside the
            # supported Gregorian range as legacy data instead of revoking
            # every account during the first reconciliation after an update.
            if expiry.year >= 2000 and expiry < now_tehran().date():
                return tr("expired")
        except ValueError:
            pass
    try:
        q = float(u.get("quota_gb") or 0)
    except (TypeError, ValueError):
        return tr("quota_nan")
    if not math.isfinite(q) or q < 0:
        return tr("quota_nan")
    try:
        used = float(u.get("used_bytes") or 0)
    except (TypeError, ValueError):
        return tr("quota_nan")
    if not math.isfinite(used) or used < 0:
        return tr("quota_nan")
    if q > 0 and used >= q * (1024 ** 3):
        return tr("quota_full")
    return ""


@state_transaction
def write_secrets(users=None, psk=None, public_ip=None, domain=None):
    # Always read users.json from disk. A stale in-memory copy (traffic
    # collector) must not wipe a user that was just added in the panel.
    users = load_users()
    cfg = load_config()
    psk = psk if psk is not None else cfg.get("psk", "")
    public_ip = public_ip or cfg.get("public_ip", "")
    domain = domain or cfg.get("domain", "")
    lines = [": RSA server.key"]
    if public_ip:
        lines.append(public_ip + ' %any : PSK "' + psk + '"')
    if domain:
        lines.append(domain + ' %any : PSK "' + psk + '"')
    lines.append('%any %any : PSK "' + psk + '"')
    chap = ["# client  server  secret  IP"]
    for name, u in users.items():
        if user_blocked(u):
            continue
        pw = u.get("password") or ""
        # These values are rendered into strongSwan/PPP configuration files.
        # Routes validate them; this guard also protects imported legacy data.
        if not vpn_password_ok(pw):
            continue
        if flag_on(u, "ikev2_enabled", True):
            lines.append('%s : EAP "%s"' % (name, pw))
        if flag_on(u, "l2tp_enabled", True):
            chap.append('%s  l2tpd  "%s"  *' % (name, pw))
    text = "\n".join(lines) + "\n"
    chap_text = "\n".join(chap) + "\n"
    try:
        IPSEC_SECRETS.parent.mkdir(parents=True, exist_ok=True)
        CHAP_SECRETS.parent.mkdir(parents=True, exist_ok=True)
        save_private_text(IPSEC_SECRETS, text)
        try:
            os.chmod(IPSEC_SECRETS, 0o600)
        except OSError:
            pass
        save_private_text(CHAP_SECRETS, chap_text)
        try:
            os.chmod(CHAP_SECRETS, 0o600)
        except OSError:
            pass
    except OSError:
        raise
    # Some strongSwan packages do not expose rereadsecrets through the same
    # frontend. The credentials are already written; do not abort the rest of
    # account reconciliation just because this compatibility command differs.
    result = run(["ipsec", "rereadsecrets"])
    if getattr(result, "returncode", 0) != 0:
        run(["systemctl", "reload", "strongswan-starter"], timeout=15)


def safe_secret(value, minimum=8, maximum=128):
    return bool(
        isinstance(value, str)
        and minimum <= len(value) <= maximum
        and re.fullmatch(r"[A-Za-z0-9._~!@#%^&*+=,:;?/-]+", value)
    )


def new_ss_key():
    return base64.b64encode(secrets.token_bytes(16)).decode()


def new_vless_uuid():
    return str(uuid.uuid4())


def new_sub_token():
    return secrets.token_urlsafe(24)


def mtg_allowed(u):
    # Shared mtg cannot attribute usage. Do not let metered accounts bypass
    # their quota through an unmetered shared secret.
    try:
        return bool(u.get("mtg_enabled") and not user_blocked(u) and float(u.get("quota_gb") or 0) == 0)
    except (TypeError, ValueError):
        return False


def new_vmess_uuid():
    return str(uuid.uuid4())


def b64url_nopad(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def parse_x25519_output(text):
    # xray x25519 labels evolved: "Public key" -> "Password" -> "Password (PublicKey)".
    # Hash32 is a different field and must never be used as the Reality pbk.
    priv = pub = ""
    for raw in (text or "").splitlines():
        if ":" not in raw:
            continue
        label, value = raw.split(":", 1)
        label_n = re.sub(r"[^a-z0-9]", "", label.strip().lower())
        value = value.strip()
        if not value:
            continue
        if label_n in ("privatekey", "private"):
            priv = value
        elif label_n in ("publickey", "passwordpublickey", "password"):
            pub = value
    return priv, pub


def generate_reality_keys():
    """Mint x25519 Reality keys at runtime. Never commit placeholders.

    Prefer `/opt/panel-xray/xray x25519`. Fallback: `openssl genpkey -algorithm x25519`
    then take the last 32 bytes of PKCS8/SPKI DER (raw Curve25519 seed/point) and
    encode url-safe base64 without padding — the same wire format xray uses.
    """
    if XRAY_SS_BIN.is_file():
        try:
            p = subprocess.run(
                [str(XRAY_SS_BIN), "x25519"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            priv, pub = parse_x25519_output((p.stdout or "") + "\n" + (p.stderr or ""))
            if priv and pub:
                return priv, pub
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        gen = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "x25519"],
            capture_output=True,
            timeout=10,
        )
        if gen.returncode != 0 or not gen.stdout:
            return "", ""
        der_priv = subprocess.run(
            ["openssl", "pkey", "-outform", "DER"],
            input=gen.stdout,
            capture_output=True,
            timeout=10,
        ).stdout
        der_pub = subprocess.run(
            ["openssl", "pkey", "-pubout", "-outform", "DER"],
            input=gen.stdout,
            capture_output=True,
            timeout=10,
        ).stdout
        if len(der_priv) < 32 or len(der_pub) < 32:
            return "", ""
        return b64url_nopad(der_priv[-32:]), b64url_nopad(der_pub[-32:])
    except (OSError, subprocess.SubprocessError):
        return "", ""


def ensure_reality_keys(cfg):
    """Generate Reality material once and store it in config.json."""
    changed = False
    if not cfg.get("reality_dest"):
        cfg["reality_dest"] = "www.microsoft.com:443"
        changed = True
    names = cfg.get("reality_server_names")
    if not isinstance(names, list) or not names:
        cfg["reality_server_names"] = ["www.microsoft.com"]
        changed = True
    if not cfg.get("reality_short_id"):
        cfg["reality_short_id"] = secrets.token_hex(4)
        changed = True
    priv = (cfg.get("reality_private") or "").strip()
    pub = (cfg.get("reality_public") or "").strip()
    if not priv or not pub:
        priv, pub = generate_reality_keys()
        if priv and pub:
            cfg["reality_private"] = priv
            cfg["reality_public"] = pub
            changed = True
    if changed:
        save_config(cfg)
    return cfg


def le_cert_paths(domain):
    live = LE_LIVE / (domain or "")
    return live / "fullchain.pem", live / "privkey.pem"


def new_mtg_secret(front_domain):
    """FakeTLS secret: 0xee + 16 random bytes + ASCII hostname, hex-encoded.

    Same layout as 9seconds/mtg `generate-secret --hex`. Prefer the binary
    when installed; Python fallback lets the panel mint a secret before mtg
    is downloaded.
    """
    host = (front_domain or "cloudflare.com").strip() or "cloudflare.com"
    host = re.sub(r"[^A-Za-z0-9.-]", "", host) or "cloudflare.com"
    if MTG_BIN.is_file():
        try:
            p = subprocess.run(
                [str(MTG_BIN), "generate-secret", "--hex", host],
                capture_output=True,
                text=True,
                timeout=10,
            )
            secret = (p.stdout or "").strip().split()[0] if p.stdout else ""
            if re.fullmatch(r"ee[0-9a-fA-F]{32,}", secret):
                return secret.lower()
        except (OSError, subprocess.SubprocessError, IndexError):
            pass
    key = secrets.token_bytes(16)
    return "ee" + key.hex() + host.encode("ascii").hex()


@state_transaction
def write_xray_ss_config(users=None):
    # One dedicated inbound per user (own port + own key) rather than a
    # single shared-port multi-user (EIH) inbound: xray-core's shadowsocks
    # *outbound* does not appear to speak the 2022 multi-user identity
    # handshake (verified empirically — a shared port with a "users" array
    # consistently fails with "cipher: message authentication failed"
    # regardless of whether the per-user password is the raw key or
    # "serverKey:userKey"). Per-user ports sidestep that entirely and work
    # with any standard Shadowsocks-2022 client.
    users = load_users() if users is None else users
    cfg = ensure_reality_keys(load_config())
    inbounds = []
    for name, u in users.items():
        if user_blocked(u) or not u.get("ss_enabled"):
            continue
        key = u.get("ss_key") or ""
        port = u.get("ss_port")
        if not re.fullmatch(r"[A-Za-z0-9+/]{22}==", key) or not port:
            continue
        inbounds.append(
            {
                "tag": "ss-%s" % name,
                "listen": "0.0.0.0",
                "port": int(port),
                "protocol": "shadowsocks",
                "settings": {
                    "network": "tcp,udp",
                    "method": SS_METHOD,
                    "password": key,
                    "email": name,
                },
            }
        )
    # VLESS Reality (xtls-rprx-vision + TCP). No Let's Encrypt required.
    # Port stays at vless_port (default 8443) because nginx already owns 443/tcp.
    vless_clients = []
    for name, u in users.items():
        if user_blocked(u) or not u.get("vless_enabled"):
            continue
        uid = u.get("vless_uuid") or ""
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uid):
            continue
        vless_clients.append(
            {
                "id": uid,
                "level": 0,
                "email": name,
                "flow": "xtls-rprx-vision",
            }
        )
    if vless_clients:
        cfg = ensure_reality_keys(cfg)
        priv = (cfg.get("reality_private") or "").strip()
        dest = (cfg.get("reality_dest") or "www.microsoft.com:443").strip()
        names = cfg.get("reality_server_names") or ["www.microsoft.com"]
        short_id = (cfg.get("reality_short_id") or "").strip()
        if priv:
            inbounds.append(
                {
                    "tag": "vless-in",
                    "listen": "0.0.0.0",
                    "port": int(cfg.get("vless_port") or 8443),
                    "protocol": "vless",
                    "settings": {"clients": vless_clients, "decryption": "none"},
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "show": False,
                            "dest": dest,
                            "serverNames": list(names),
                            "privateKey": priv,
                            "shortIds": [short_id] if short_id else [""],
                        },
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": True,
                    },
                }
            )
    # VMess: shared port, TCP + WebSocket + TLS on the Let's Encrypt cert of config.domain.
    # Only added when the cert files exist (same constraint the old VLESS-TLS inbound had).
    vmess_clients = []
    for name, u in users.items():
        if user_blocked(u) or not u.get("vmess_enabled"):
            continue
        uid = u.get("vmess_uuid") or ""
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uid):
            continue
        vmess_clients.append({"id": uid, "alterId": 0, "email": name, "security": "auto"})
    domain = (cfg.get("domain") or "").strip()
    cert, key_path = le_cert_paths(domain)
    if vmess_clients and cert.is_file() and key_path.is_file():
        ws_settings = {"path": VMESS_PATH}
        if domain:
            ws_settings["headers"] = {"Host": domain}
        inbounds.append(
            {
                "tag": "vmess-in",
                "listen": "0.0.0.0",
                "port": int(cfg.get("vmess_port") or 2053),
                "protocol": "vmess",
                "settings": {"clients": vmess_clients},
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [
                            {"certificateFile": str(cert), "keyFile": str(key_path)}
                        ]
                    },
                    "wsSettings": ws_settings,
                },
            }
        )
    # HTTPS proxy: encrypt credentials on the client-to-proxy connection.
    http_ports = []
    users_changed = False
    reserved = {int(u.get("ss_port") or 0) for u in users.values()}
    reserved.update(int(u.get("http_port") or 0) for u in users.values())
    reserved.update(int(cfg.get(k) or default) for k, default in
                    (("vless_port", 8443), ("vmess_port", 2053), ("mtg_port", 3128)))
    next_http_port = int(cfg.get("http_port") or 10809)
    for name, u in users.items():
        if user_blocked(u) or not u.get("http_enabled"):
            continue
        pw = u.get("password") or ""
        if not vpn_password_ok(pw):
            continue
        if not u.get("http_port"):
            while next_http_port in reserved:
                next_http_port += 1
            if next_http_port > 65535:
                raise ValueError("No free HTTPS proxy port")
            u["http_port"] = next_http_port
            reserved.add(next_http_port)
            users_changed = True
        if not cert.is_file() or not key_path.is_file():
            continue
        http_ports.append(int(u["http_port"]))
        inbounds.append(
            {
                "tag": "http-%s" % name,
                "listen": "0.0.0.0",
                "port": int(u["http_port"]),
                "protocol": "http",
                "settings": {"accounts": [{"user": name, "pass": pw}], "allowTransparent": False},
                "streamSettings": {
                    "network": "tcp", "security": "tls",
                    "tlsSettings": {"certificates": [
                        {"certificateFile": str(cert), "keyFile": str(key_path)}
                    ]},
                },
            }
        )
    if users_changed:
        save_users(users)
    doc = {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["StatsService"]},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    new_text = json.dumps(doc, indent=2)
    # A restart drops every live SS connection, not just the one being
    # edited — skip it when this call didn't actually change anything
    # (e.g. an unrelated IKEv2-only user was added/edited/deleted).
    try:
        unchanged = XRAY_SS_CONFIG.read_text(encoding="utf-8") == new_text
    except OSError:
        unchanged = False
    if unchanged:
        if inbounds and _systemctl_active("panel-shadowsocks") is False:
            run_checked(["systemctl", "start", "panel-shadowsocks"], timeout=15)
        return
    if http_ports and "Status: active" in run(["ufw", "status"]):
        for port in http_ports:
            run(["ufw", "allow", "%d/tcp" % port])
    XRAY_SS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = XRAY_SS_CONFIG.with_suffix(".tmp")
    tmp.write_text(new_text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(XRAY_SS_CONFIG)
    if inbounds:
        run_checked(["systemctl", "restart", "panel-shadowsocks"], timeout=15)
    else:
        run_checked(["systemctl", "stop", "panel-shadowsocks"], timeout=15)



def yaml_str(value):
    return json.dumps(str(value))


@state_transaction
def write_hysteria_config(users=None):
    users = load_users() if users is None else users
    cfg = load_config()
    port = int(cfg.get("hy_port") or 443)
    domain = (cfg.get("domain") or "").strip()
    secret = cfg.get("hy_stats_secret") or ""
    cert = Path("/etc/letsencrypt/live") / domain / "fullchain.pem"
    key = Path("/etc/letsencrypt/live") / domain / "privkey.pem"
    obfs_pw = cfg.get("hy_obfs_password") or ""
    lines = [
        "listen: :%d" % port,
        "tls:",
        "  cert: %s" % yaml_str(str(cert)),
        "  key: %s" % yaml_str(str(key)),
        "obfs:",
        "  type: salamander",
        "  salamander:",
        "    password: %s" % yaml_str(obfs_pw),
        "auth:",
        "  type: userpass",
        "  userpass:",
    ]
    any_user = False
    for name, u in users.items():
        if user_blocked(u) or not u.get("hy_enabled"):
            continue
        pw = u.get("password") or ""
        if not vpn_password_ok(pw):
            continue
        lines.append("    %s: %s" % (yaml_str(name), yaml_str(pw)))
        any_user = True
    if not any_user:
        # Deterministic (not freshly random) so an idle config with no
        # Hysteria2 users compares equal across calls and skips the restart.
        placeholder = hashlib.sha256(("hy-placeholder:" + secret).encode()).hexdigest()
        lines.append("    __disabled__: %s" % yaml_str(placeholder))
    lines += [
        "trafficStats:",
        "  listen: 127.0.0.1:9999",
        "  secret: %s" % yaml_str(secret),
    ]
    new_text = "\n".join(lines) + "\n"
    # Same reasoning as write_xray_ss_config: a restart drops every live
    # Hysteria2 connection, so skip it when nothing actually changed.
    try:
        unchanged = HYSTERIA_CONFIG.read_text(encoding="utf-8") == new_text
    except OSError:
        unchanged = False
    if unchanged:
        if cert.is_file() and key.is_file() and _systemctl_active("panel-hysteria") is False:
            run_checked(["systemctl", "start", "panel-hysteria"], timeout=15)
        return
    HYSTERIA_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = HYSTERIA_CONFIG.with_suffix(".tmp")
    tmp.write_text(new_text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(HYSTERIA_CONFIG)
    if cert.is_file() and key.is_file():
        run_checked(["systemctl", "restart", "panel-hysteria"], timeout=15)
    else:
        run_checked(["systemctl", "stop", "panel-hysteria"], timeout=15)


@state_transaction
def write_mtg_config(users=None):
    # Xray has no mtproto inbound. Like 3x-ui v3.3 we run sidecar mtg
    # (9seconds/mtg) with a single FakeTLS secret at panel/settings level.
    # Per-user mtg_enabled only controls whether that user sees the same
    # tg:// link — minting a unique secret per account is too heavy for mtg.
    users = load_users() if users is None else users
    cfg = load_config()
    any_user = any(
        mtg_allowed(u) for u in users.values()
    )
    if not any_user:
        if MTG_BIN.exists():
            run_checked(["systemctl", "stop", "panel-mtg"], timeout=15)
        if cfg.get("mtg_membership"):
            cfg["mtg_membership"] = ""
            cfg["mtg_secret"] = ""
            save_config(cfg)
        return
    changed = False
    members = sorted(name for name, u in users.items()
                     if mtg_allowed(u))
    membership = hashlib.sha256(json.dumps(members).encode()).hexdigest()
    # The shared backend cannot revoke one holder. Rotate on membership
    # changes (including the first upgrade) to invalidate removed holders.
    if cfg.get("mtg_membership") != membership:
        cfg["mtg_secret"] = new_mtg_secret(cfg.get("mtg_domain") or "cloudflare.com")
        cfg["mtg_membership"] = membership
        changed = True
    if not cfg.get("mtg_domain"):
        cfg["mtg_domain"] = "cloudflare.com"
        changed = True
    try:
        port = int(cfg.get("mtg_port") or 3128)
    except (TypeError, ValueError):
        port = 3128
        cfg["mtg_port"] = port
        changed = True
    secret = (cfg.get("mtg_secret") or "").strip()
    if not re.fullmatch(r"ee[0-9a-fA-F]{32,}", secret):
        secret = new_mtg_secret(cfg.get("mtg_domain") or "cloudflare.com")
        cfg["mtg_secret"] = secret
        changed = True
    if changed:
        save_config(cfg)
    # Secret is hex-only so it is safe inside TOML double quotes.
    new_text = 'secret = "%s"\nbind-to = "0.0.0.0:%d"\n' % (secret, port)
    try:
        unchanged = MTG_CONFIG.read_text(encoding="utf-8") == new_text
    except OSError:
        unchanged = False
    if unchanged:
        if _systemctl_active("panel-mtg") is False:
            run_checked(["systemctl", "start", "panel-mtg"], timeout=15)
        return
    if not unchanged:
        MTG_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        tmp = MTG_CONFIG.with_suffix(".tmp")
        tmp.write_text(new_text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(MTG_CONFIG)
    run_checked(["systemctl", "restart", "panel-mtg"], timeout=15)


def rewrite_ipsec_leftid(domain):
    """Set leftid=@DOMAIN on the IKEv2-EAP conn only; leave L2TP-PSK alone."""
    if not IPSEC_CONF.exists():
        return
    text = IPSEC_CONF.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"(?=^conn )", text, flags=re.M)
    out = []
    for part in parts:
        if re.match(r"^conn\s+IKEv2-EAP\b", part):
            part = re.sub(r"(?m)^([ \t]*leftid=)\S+", r"\1@" + domain, part)
        out.append(part)
    new_text = "".join(out)
    if new_text != text:
        IPSEC_CONF.write_text(new_text, encoding="utf-8")


def _copy_le_to_ipsec(domain):
    cert, key = le_cert_paths(domain)
    if not cert.is_file() or not key.is_file():
        return False
    IPSEC_CERT.parent.mkdir(parents=True, exist_ok=True)
    IPSEC_KEY.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(cert, IPSEC_CERT)
    shutil.copy2(key, IPSEC_KEY)
    os.chmod(IPSEC_KEY, 0o600)
    return True


def _write_certbot_hook(domain):
    CERTBOT_HOOK.parent.mkdir(parents=True, exist_ok=True)
    CERTBOT_HOOK.write_text(
        "#!/bin/bash\n"
        "cp -f /etc/letsencrypt/live/%s/fullchain.pem /etc/ipsec.d/certs/server.crt\n"
        "cp -f /etc/letsencrypt/live/%s/privkey.pem /etc/ipsec.d/private/server.key\n"
        "chmod 600 /etc/ipsec.d/private/server.key\n"
        "ipsec rereadall >/dev/null 2>&1 || true\n"
        "systemctl reload nginx >/dev/null 2>&1 || true\n"
        "systemctl try-restart panel-shadowsocks panel-hysteria >/dev/null 2>&1 || true\n" % (domain, domain),
        encoding="utf-8",
    )
    os.chmod(CERTBOT_HOOK, 0o755)


def _nginx_set_server_name(text, domain):
    return re.sub(r"(?m)^( *server_name\s+)\S+;", r"\1%s;" % domain, text)


def _nginx_set_cert_paths(text, domain):
    text = re.sub(
        r"(ssl_certificate\s+)/etc/letsencrypt/live/[^/]+/fullchain\.pem;",
        r"\1/etc/letsencrypt/live/%s/fullchain.pem;" % domain,
        text,
    )
    text = re.sub(
        r"(ssl_certificate_key\s+)/etc/letsencrypt/live/[^/]+/privkey\.pem;",
        r"\1/etc/letsencrypt/live/%s/privkey.pem;" % domain,
        text,
    )
    return text


def apply_domain_ssl(old_domain, domain):
    """Try Let's Encrypt webroot + nginx/ipsec certs. Never restart xl2tpd.

    Returns (ok, note). Domain is already saved in config.json by the caller.
    If certbot fails we keep existing nginx certs so HTTPS of the old name
    still works, and flash that SSL must be issued for the new domain.
    """
    if not NGINX_SITE.exists() or not shutil.which("certbot"):
        run(["ipsec", "rereadall"])
        run(["ipsec", "reload"])
        return False, "certbot یا سایت nginx پیدا نشد."
    try:
        site = NGINX_SITE.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return False, str(e)
    updated = _nginx_set_server_name(site, domain)
    if updated != site:
        NGINX_SITE.write_text(updated, encoding="utf-8")
        site = updated
    test = run(["nginx", "-t"], timeout=15)
    if "syntax is ok" not in test.lower() and "test is successful" not in test.lower() and "successful" not in test.lower():
        # nginx -t prints to stderr which run() concatenates.
        if "failed" in test.lower() or "error" in test.lower():
            return False, test[-300:]
    run(["systemctl", "reload", "nginx"], timeout=15)
    cmd = [
        "certbot",
        "certonly",
        "--webroot",
        "-w",
        "/var/www/html",
        "--non-interactive",
        "--agree-tos",
        "--cert-name",
        domain,
        "--key-type",
        "rsa",
        "--rsa-key-size",
        "2048",
        "-d",
        domain,
        "--register-unsafely-without-email",
    ]
    cert, key = le_cert_paths(domain)
    if cert.is_file():
        cmd.append("--keep-until-expiring")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        certbot_out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
        ok = p.returncode == 0 and cert.is_file() and key.is_file()
    except (OSError, subprocess.SubprocessError) as e:
        certbot_out = str(e)
        ok = False
    if not ok:
        run(["ipsec", "rereadall"])
        run(["ipsec", "reload"])
        return False, certbot_out[-300:]
    site = _nginx_set_cert_paths(site, domain)
    NGINX_SITE.write_text(site, encoding="utf-8")
    test = run(["nginx", "-t"], timeout=15)
    if "failed" in test.lower() and "successful" not in test.lower():
        return False, test[-300:]
    run(["systemctl", "reload", "nginx"], timeout=15)
    _copy_le_to_ipsec(domain)
    _write_certbot_hook(domain)
    run(["ipsec", "rereadall"])
    run(["ipsec", "reload"])
    run(["systemctl", "reload", "strongswan-starter"], timeout=15)
    return True, ""


def xray_ss_stats():
    result = {}
    try:
        p = subprocess.run(
            [str(XRAY_SS_BIN), "api", "statsquery", "-server=127.0.0.1:10085"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        data = json.loads(p.stdout or "{}")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return result
    for stat in data.get("stat", []):
        name = stat.get("name") or ""
        m = re.match(r"^user>>>(.+)>>>traffic>>>(uplink|downlink)$", name)
        if not m:
            m = re.match(r"^inbound>>>http-(.+)>>>traffic>>>(uplink|downlink)$", name)
        if not m:
            continue
        user = m.group(1)
        result[user] = result.get(user, 0) + int(stat.get("value") or 0)
    return result


def hysteria_stats():
    cfg = load_config()
    secret = cfg.get("hy_stats_secret") or ""
    req = urllib.request.Request(
        "http://127.0.0.1:9999/traffic",
        headers={"Authorization": secret},
    )
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return {}
    result = {}
    for user, v in (data or {}).items():
        if isinstance(v, dict):
            result[user] = int(v.get("tx") or 0) + int(v.get("rx") or 0)
    return result


def parse_sessions():
    text = run(["ipsec", "statusall"])
    sessions = []
    current = None
    for line in text.splitlines():
        s = line.strip()
        m = re.search(
            r"^(IKEv2-EAP|L2TP-PSK)\[(\d+)\]:\s+ESTABLISHED\s+(.+?),\s+"
            r"[^\s\[]+\[.*?\]\.\.\.([^\s\[]+)\[",
            s,
        )
        if m:
            if current:
                sessions.append(current)
            current = {
                "conn": m.group(1),
                "id": m.group(2),
                "uptime": m.group(3).replace(" ago", "").replace("minutes", "دقیقه").replace("minute", "دقیقه").replace("hours", "ساعت").replace("hour", "ساعت").replace("seconds", "ثانیه").replace("second", "ثانیه").replace("days", "روز").replace("day", "روز"),
                "remote": m.group(4),
                "user": "",
                "vip": "",
                "bytes_in": 0,
                "bytes_out": 0,
                "bytes_total": 0,
                "proto": "IKEv2" if m.group(1) == "IKEv2-EAP" else "L2TP",
            }
            age = re.search(r"(\d+)\s+(second|minute|hour|day)", m.group(3))
            scale = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
            current["order"] = time.time() - (int(age[1]) * scale[age[2]] if age else 0)
            continue
        if not current:
            continue
        m = re.search(r"Remote EAP identity:\s+(\S+)", s, re.I)
        if m:
            current["user"] = m.group(1).strip("'\"")
        m = re.search(r"0\.0\.0\.0/0\s+===\s+([\d.]+)/32", s)
        if m:
            current["vip"] = m.group(1)
        m = re.search(
            r"([\d]+)\s+bytes_i\s+\((\d+)\s+pkts.*?\)\s*,\s*([\d]+)\s+bytes_o\s+\((\d+)\s+pkts",
            s,
        )
        if m:
            current["bytes_in"] = int(m.group(1))
            current["bytes_out"] = int(m.group(3))
            current["bytes_total"] = current["bytes_in"] + current["bytes_out"]
    if current:
        sessions.append(current)

    if PPP_ONLINE.exists():
        have = {(s.get("user"), s.get("proto")) for s in sessions}
        for f in PPP_ONLINE.glob("ppp*"):
            try:
                parts = f.read_text(encoding="utf-8", errors="replace").strip().split()
            except OSError:
                continue
            if len(parts) >= 2:
                name = parts[0]
                if (name, "L2TP") not in have:
                    rx = tx = 0
                    try:
                        rx = int(Path("/sys/class/net/%s/statistics/rx_bytes" % f.name).read_text())
                        tx = int(Path("/sys/class/net/%s/statistics/tx_bytes" % f.name).read_text())
                    except (OSError, ValueError):
                        pass
                    sessions.append(
                        {
                            "conn": "L2TP-PPP",
                            "id": f.name,
                            "started": parts[2] if len(parts) >= 3 else "",
                            "uptime": "",
                            "remote": "",
                            "user": name,
                            "vip": parts[1],
                            "bytes_in": rx,
                            "bytes_out": tx,
                            "bytes_total": rx + tx,
                            "proto": "L2TP",
                        }
                    )
    return sessions


def max_sessions_per_user():
    try:
        value = int(load_config().get("max_sessions_per_user", 1))
    except (TypeError, ValueError):
        value = 1
    return max(1, min(10, value))


def cleanup_excess_sessions(sessions=None):
    """Keep the newest IKEv2 sessions for each EAP identity.

    IKE IDs are monotonically increasing for the lifetime of charon, so a
    larger ID is a newer session.  We intentionally avoid `uniqueids=yes` as
    clients often present the same outer IKE identity even for different EAP
    users, and enabling it could disconnect unrelated accounts.
    """
    sessions = sessions if sessions is not None else parse_sessions()
    limit = max_sessions_per_user()
    grouped = {}
    for session_info in sessions:
        if session_info.get("proto") not in ("IKEv2", "L2TP") or not session_info.get("user"):
            continue
        if session_info.get("conn") == "L2TP-PSK":
            continue  # PPP records carry authenticated usernames.
        try:
            age_key = int(session_info.get("order") or session_info.get("started") or session_info.get("id"))
        except (TypeError, ValueError):
            age_key = 0
        grouped.setdefault(session_info["user"], []).append((age_key, session_info))

    terminated = []
    for username, active in grouped.items():
        active.sort(key=lambda item: item[0], reverse=True)
        for _, old_session in active[limit:]:
            target = terminate_user_session(old_session)
            terminated.append({"user": username, "target": target})
    return terminated


def terminate_ike_session(session_info):
    target = "%s[%s]" % (session_info.get("conn") or "IKEv2-EAP", session_info["id"])
    if STROKE.is_file():
        run([str(STROKE), "down-nb", target], timeout=5)
    else:
        run(["ipsec", "down", target], timeout=5)
    return target


def terminate_user_session(s):
    if s.get("conn") != "L2TP-PPP":
        return terminate_ike_session(s)
    interface = str(s.get("id") or "")
    if not re.fullmatch(r"ppp\d+", interface):
        return None
    try:
        pid = int((Path("/run") / (interface + ".pid")).read_text().strip())
        if pid <= 1 or (Path("/proc") / str(pid) / "comm").read_text().strip() != "pppd":
            return None
        os.kill(pid, signal.SIGTERM)
        return interface
    except (OSError, ValueError):
        return None


def revoke_invalid_sessions(users, sessions=None):
    sessions = parse_sessions() if sessions is None else sessions
    deleted = deleted_user_names()
    for s in sessions:
        name = s.get("user")
        if not name:
            continue
        u = find_user_record(users, name)
        field = "ikev2_enabled" if s.get("proto") == "IKEv2" else "l2tp_enabled"
        # strongSwan identity formatting can differ from the panel key. An
        # unknown identity is therefore not proof that an account was deleted.
        # Only an explicit deletion tombstone may revoke an unknown identity.
        explicitly_deleted = u is None and str(name).casefold() in deleted
        if explicitly_deleted or (u is not None and (user_blocked(u) or not flag_on(u, field, True))):
            terminate_user_session(s)


@state_transaction
def sync_accounts(users=None):
    app._accounts_ready = False
    users = load_users() if users is None else users
    write_secrets(users)
    revoke_invalid_sessions(users)
    write_xray_ss_config(users)
    write_hysteria_config(users)
    write_mtg_config(users)
    app._accounts_ready = True


@state_transaction
def sample_traffic():
    sessions = parse_sessions()
    cleanup_excess_sessions(sessions)
    # TCP socket count is not a device count. Do not kill ordinary parallel
    # Shadowsocks connections. Proxy device caps are not currently supported.
    with _lock:
        users = load_users()
        snap = load_json(SNAP_FILE, {})
        new_snap = {k: v for k, v in snap.items()
                    if k.startswith("__") or k.split(":", 1)[0] in users}
        changed = False
        for s in sessions:
            name = s.get("user") or ""
            if name not in users:
                continue
            total = int(s.get("bytes_total") or 0)
            key = "%s:%s:%s:%s" % (name, s.get("proto"), s.get("id"), s.get("started", ""))
            prev = int(snap.get(key, 0))
            if total >= prev:
                delta = total - prev
            else:
                delta = total
            if delta > 0:
                users[name]["used_bytes"] = int(users[name].get("used_bytes") or 0) + delta
                changed = True
            new_snap[key] = total
        account_ppp_disconnects(users, new_snap)
        for proto, totals in (("ss", xray_ss_stats()), ("hy", hysteria_stats())):
            unit = "panel-shadowsocks" if proto == "ss" else "panel-hysteria"
            epoch = run(["systemctl", "show", unit, "--property=ActiveEnterTimestampMonotonic", "--value"]).strip()
            if totals and epoch.isdigit() and epoch != "0":
                old_epoch = snap.get("__epoch_" + proto)
                if old_epoch and old_epoch != epoch:
                    for key in list(new_snap):
                        if key.endswith(":" + proto):
                            new_snap.pop(key)
                    snap = dict(snap)
                    for key in list(snap):
                        if key.endswith(":" + proto):
                            snap.pop(key)
                new_snap["__epoch_" + proto] = epoch
            for name, total in totals.items():
                if name not in users:
                    continue
                key = "%s:%s" % (name, proto)
                prev = int(snap.get(key, 0))
                delta = total - prev if total >= prev else total
                if delta > 0:
                    users[name]["used_bytes"] = int(users[name].get("used_bytes") or 0) + delta
                    changed = True
                new_snap[key] = total
        save_users(users)
        save_json(SNAP_FILE, new_snap)
        # Also reconcile deleted/disabled accounts on upgrade and every poll.
        # Writers skip unchanged proxy configs to preserve unrelated sessions.
        sync_accounts(users)
        return users, sessions


def account_ppp_disconnects(users, snap):
    logfile = DATA_DIR / "ppp-acct.log"
    try:
        with logfile.open("rb") as stream:
            offset = int(snap.get("__ppp_offset", 0))
            if logfile.stat().st_size < offset:
                offset = 0
            stream.seek(offset)
            while True:
                start = stream.tell()
                line = stream.readline()
                if not line or not line.endswith(b"\n"):
                    stream.seek(start)
                    break
                fields = line.decode("utf-8", errors="replace").split()
                # New hook: name IP rx tx end-time interface start-time.
                if len(fields) == 7 and fields[0] in users:
                    name, _, rx, tx, _, interface, started = fields
                    try:
                        total = int(rx) + int(tx)
                        key = "%s:L2TP:%s:%s" % (name, interface, started)
                        previous = int(snap.get(key, 0))
                        users[name]["used_bytes"] = int(users[name].get("used_bytes") or 0) + max(0, total - previous)
                        snap[key] = total
                    except (ValueError, TypeError):
                        pass
            snap["__ppp_offset"] = stream.tell()
    except (OSError, ValueError):
        pass


def host_stats():
    global _cpu_prev, _net_prev
    load1, load5, load15 = 0.0, 0.0, 0.0
    try:
        a, b, c = Path("/proc/loadavg").read_text().split()[:3]
        load1, load5, load15 = float(a), float(b), float(c)
    except (OSError, ValueError):
        pass
    cpu_pct = 0.0
    try:
        line = Path("/proc/stat").read_text().splitlines()[0].split()
        vals = [int(x) for x in line[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        total = sum(vals)
        prev = _cpu_prev
        _cpu_prev = (idle, total)
        if prev:
            didle = idle - prev[0]
            dtotal = total - prev[1]
            if dtotal > 0:
                cpu_pct = max(0.0, min(100.0, 100.0 * (1.0 - didle / dtotal)))
    except (OSError, ValueError, IndexError):
        pass
    mem_total = mem_used = 0
    try:
        info = {}
        for ln in Path("/proc/meminfo").read_text().splitlines():
            k, rest = ln.split(":", 1)
            info[k] = int(rest.strip().split()[0]) * 1024
        mem_total = info.get("MemTotal", 0)
        mem_used = mem_total - info.get("MemAvailable", info.get("MemFree", 0))
    except (OSError, ValueError):
        pass
    disk = shutil.disk_usage("/")
    uptime = 0.0
    try:
        uptime = float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError):
        pass
    net_iface = (load_config().get("interface") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", net_iface):
        net_iface = ""
    if not net_iface:
        try:
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) > 1 and fields[1] == "00000000":
                    net_iface = fields[0]
                    break
        except OSError:
            pass
    net_rx = net_tx = 0
    net_down_bps = net_up_bps = 0.0
    if net_iface:
        try:
            net_rx = int(Path("/sys/class/net").joinpath(net_iface, "statistics", "rx_bytes").read_text())
            net_tx = int(Path("/sys/class/net").joinpath(net_iface, "statistics", "tx_bytes").read_text())
            sampled_at = time.monotonic()
            previous = _net_prev
            _net_prev = (net_iface, net_rx, net_tx, sampled_at)
            if previous and previous[0] == net_iface:
                elapsed = sampled_at - previous[3]
                if elapsed > 0:
                    net_down_bps = max(0.0, (net_rx - previous[1]) / elapsed)
                    net_up_bps = max(0.0, (net_tx - previous[2]) / elapsed)
        except (OSError, ValueError):
            net_rx = net_tx = 0
    cores = os.cpu_count() or 1
    return {
        "cpu": round(cpu_pct, 1),
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "cores": cores,
        "mem_total": mem_total,
        "mem_used": mem_used,
        "mem_pct": round(100.0 * mem_used / mem_total, 1) if mem_total else 0,
        "disk_total": disk.total,
        "disk_used": disk.used,
        "disk_pct": round(100.0 * disk.used / disk.total, 1) if disk.total else 0,
        "uptime": uptime,
        "net_iface": net_iface,
        "net_rx": net_rx,
        "net_tx": net_tx,
        "net_down_bps": net_down_bps,
        "net_up_bps": net_up_bps,
    }


def fmt_uptime(sec):
    sec = int(sec)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, _ = divmod(sec, 60)
    lang = current_lang()
    parts = []
    if d:
        parts.append((fa(d) if lang == "fa" else str(d)) + " " + tr("u_day"))
    if h:
        parts.append((fa(h) if lang == "fa" else str(h)) + " " + tr("u_hour"))
    parts.append((fa(m) if lang == "fa" else str(m)) + " " + tr("u_min"))
    return " ".join(parts)


def dashboard_payload():
    users = import_secrets_if_needed()
    if not isinstance(users, dict):
        users = {}
    sessions = parse_sessions()
    if not isinstance(sessions, list):
        sessions = []
    online = sorted({s["user"] for s in sessions if isinstance(s, dict) and s.get("user")})
    hs = host_stats()
    rows = []
    for name, u in sorted(users.items()):
        if not isinstance(u, dict):
            continue
        block = user_blocked(u)
        try:
            q = float(u.get("quota_gb") or 0)
            if not math.isfinite(q) or q < 0:
                q = 0
        except (TypeError, ValueError):
            q = 0
        try:
            used = float(u.get("used_bytes") or 0)
            if not math.isfinite(used) or used < 0:
                used = 0
        except (TypeError, ValueError):
            used = 0
        ses = next((s for s in sessions if s.get("user") == name), None)
        rows.append(
            {
                "name": name,
                "password": u.get("password") or "",
                "expires": u.get("expires") or "",
                "quota_gb": q,
                "used_bytes": used,
                "used_h": human(used),
                "quota_h": tr("unlimited") if q <= 0 else (
                    (fa(gtrim(q)) if current_lang() == "fa" else gtrim(q)) + " GB"
                ),
                "created": u.get("created") or "",
                "online": name in online,
                "block": block,
                "proto": ses["proto"] if ses else "",
                "vip": ses["vip"] if ses else "",
                "remote": ses["remote"] if ses else "",
                "uptime": ses["uptime"] if ses else "",
                "ikev2_enabled": flag_on(u, "ikev2_enabled", True),
                "l2tp_enabled": flag_on(u, "l2tp_enabled", True),
                "ss_enabled": bool(u.get("ss_enabled")),
                "hy_enabled": bool(u.get("hy_enabled")),
                "vless_enabled": bool(u.get("vless_enabled")),
                "vmess_enabled": bool(u.get("vmess_enabled")),
                "http_enabled": bool(u.get("http_enabled")),
                "mtg_enabled": mtg_allowed(u),
            }
        )
    cfg = load_config()
    for s in sessions:
        s["bytes_h"] = human(s.get("bytes_total") or 0)
        s["in_h"] = human(s.get("bytes_in") or 0)
        s["out_h"] = human(s.get("bytes_out") or 0)
    return {
        "users": rows,
        "sessions": sessions,
        "online": online,
        "online_count": len(online),
        "total": len(rows),
        "host": cfg.get("domain") or cfg.get("public_ip") or "",
        "public_ip": (cfg.get("public_ip") or "").strip() or (cfg.get("domain") or "").strip(),
        "speed_last": load_speed_last(),
        "dns": ",".join(cfg.get("dns") or []),
        "max_sessions_per_user": max_sessions_per_user(),
        "stats": hs,
        "cpu_fa": fa(hs["cpu"]),
        "mem_fa": fa(hs["mem_pct"]),
        "mem_used_h": human(hs["mem_used"]),
        "mem_total_h": human(hs["mem_total"]),
        "disk_fa": fa(hs["disk_pct"]),
        "load_fa": fa("%.2f" % hs["load1"]),
        "uptime_h": fmt_uptime(hs["uptime"]),
        "net_iface": hs["net_iface"] or "—",
        "net_rx_h": human(hs["net_rx"]),
        "net_tx_h": human(hs["net_tx"]),
        "net_down_h": human(hs["net_down_bps"]) + tr("per_sec"),
        "net_up_h": human(hs["net_up_bps"]) + tr("per_sec"),
        "now": now_tehran().strftime("%Y/%m/%d %H:%M"),
        "now_fa": fa(now_tehran().strftime("%Y/%m/%d %H:%M")),
        "profile_display_name": (load_admin().get("display_name") or "").strip(),
        "profile_contact": (load_admin().get("contact") or "").strip(),
    }


def gtrim(q):
    if float(q) == int(q):
        return str(int(q))
    return str(q)


@app.route("/login", methods=["GET", "POST"])
def login():
    load_admin()
    err = ""
    cfg = load_config()
    host = cfg.get("domain") or ""
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            return render_template("login.html", err=tr("login_csrf"), host=host, totp_on=bool(load_admin().get("totp_enabled") and load_admin().get("totp_secret"))), 400
        remote = (request.remote_addr or "").strip()
        forwarded = (request.headers.get("X-Real-IP") or "").strip()
        if forwarded and remote in ("127.0.0.1", "::1"):
            remote = forwarded.split(",")[0].strip()[:64]
        now = time.monotonic()
        attempts = [t for t in _login_attempts.get(remote, []) if now - t < LOGIN_WINDOW]
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            return render_template("login.html", err=tr("login_lock"), host=host, totp_on=bool(load_admin().get("totp_enabled") and load_admin().get("totp_secret"))), 429
        admin = load_admin()
        user = (request.form.get("user") or "").strip()
        pw = request.form.get("password") or ""
        totp_on = bool(admin.get("totp_enabled") and admin.get("totp_secret"))
        if user == admin.get("user") and admin.get("password") and check_password_hash(admin["password"], pw):
            if totp_on and not totp_ok(admin.get("totp_secret") or "", request.form.get("totp") or ""):
                attempts.append(now)
                _login_attempts[remote] = attempts
                err = tr("totp_bad")
            else:
                session.clear()
                session["ok"] = True
                session["auth_version"] = admin.get("auth_version", 0)
                session.permanent = True
                _login_attempts.pop(remote, None)
                resp = redirect(url_for("index"))
                return set_ui_cookies(resp, current_theme(), current_lang())
        else:
            attempts.append(now)
            _login_attempts[remote] = attempts
            err = tr("login_bad")
    totp_on = bool(load_admin().get("totp_enabled") and load_admin().get("totp_secret"))
    return render_template("login.html", err=err, host=host, totp_on=totp_on)


@app.route("/logout", methods=["POST"])
@login_required
@csrf_required
def logout():
    session.clear()
    return redirect(url_for("login"))


def page_chrome(page, title_key, subtitle_key, extra=None):
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d["page"] = page
    d["page_title"] = tr(title_key)
    d["page_subtitle"] = tr(subtitle_key)
    if extra:
        d.update(extra)
    return d


@app.route("/")
@login_required
def index():
    return render_template("index.html", **page_chrome("dash", "dash_title", "dash_sub"))


@app.route("/users")
@login_required
def users_page():
    return render_template("users.html", **page_chrome("users", "users_title", "users_sub"))


@app.route("/sessions")
@login_required
def sessions_page():
    return render_template("sessions.html", **page_chrome("sessions", "sessions_title", "sessions_sub"))


@app.route("/clients")
@login_required
def clients_page():
    return render_template("clients.html", **page_chrome("clients", "clients_title", "clients_sub"))


@app.route("/smart", methods=["GET", "POST"])
@login_required
def smart_page():
    users = load_users()
    names = sorted(users.keys())
    form = {
        "user": names[0] if names else "",
        "os": "android",
        "net": "mobile",
        "udp": "unknown",
        "path": "unknown",
        "native": False,
        "filter": "iran",
    }
    result = None
    ai_text = ""
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "") or ""
        expected = session.get("csrf", "") or ""
        if not expected or not secrets.compare_digest(submitted, expected):
            flash_t("csrf_bad")
            return redirect(url_for("smart_page"))
        form = parse_smart_form(request.form)
        name = form["user"]
        u = users.get(name)
        if not names:
            flash_t("smart_no_users")
        elif not u:
            flash_t("user_missing")
        else:
            cfg = load_config()
            result = rank_smart_connect(name, u, cfg, form, current_lang())
            if not result["ranked"]:
                flash_t("smart_no_match")
            before_ids = [r.get("id") for r in (result.get("ranked") or [])]
            ai_text, ai_st, ai_ranked = smart_ai_review(result, current_lang())
            if ai_st == "fail":
                flash_t("smart_ai_fail")
            changed = False
            if ai_ranked:
                after_ids = [r.get("id") for r in ai_ranked]
                changed = after_ids != before_ids
                result["ranked"] = ai_ranked
            result["ai_text"] = ai_text or ""
            result["ai_status"] = ai_st
            result["ai_changed"] = changed
    extra = {
        "user_names": names,
        "form": form,
        "result": result,
        "os_opts": SMART_OS,
        "net_opts": SMART_NET,
        "udp_opts": SMART_UDP,
        "path_opts": SMART_PATH,
        "filter_opts": SMART_FILTER,
    }
    return render_template("smart.html", **page_chrome("smart", "smart_title", "smart_sub", extra))




@app.route("/settings")
@login_required
def settings():
    d = page_chrome("settings", "settings_title", "settings_sub")
    cfg = load_config()
    token = cfg.get("telegram_bot_token") or ""
    d["telegram_bot_set"] = bool(token)
    d["telegram_bot_masked"] = ("…" + token[-6:]) if token else ""
    d["telegram_admin_ids"] = ", ".join(str(i) for i in (cfg.get("telegram_admin_ids") or []))
    d["update_info"] = update_status()
    d["update_job"] = load_json(DATA_DIR / "update-status.json", {})
    d["domain_job"] = load_json(DATA_DIR / "domain-status.json", {})
    d["domain"] = (cfg.get("domain") or "").strip()
    d["ai_base"] = (cfg.get("ai_base") or "").strip()
    d["ai_model"] = (cfg.get("ai_model") or "").strip()
    ai_key = (cfg.get("ai_api_key") or "").strip()
    d["ai_key_set"] = bool(ai_key)
    d["ai_key_masked"] = ("••••" + ai_key[-4:]) if len(ai_key) >= 4 else ("••••" if ai_key else "")
    admin = load_admin()
    d["totp_on"] = bool(admin.get("totp_enabled") and admin.get("totp_secret"))
    pending = session.get("totp_pending") or ""
    d["totp_secret"] = pending
    d["totp_otpauth"] = totp_otpauth(pending, admin.get("user") or "admin", d.get("host") or "") if pending and not d["totp_on"] else ""
    dns_parts = list(cfg.get("dns") or [])
    d["dns_preset"] = match_dns_preset(dns_parts)
    d["dns_presets"] = [{"id": pid, "label": label, "dns": ",".join(ips)} for pid, label, ips in DNS_PRESETS]
    return render_template("settings.html", **d)


def client_domain():
    cfg = load_config()
    return (cfg.get("domain") or "").strip()


def stamp_client_text(text, domain):
    vpn_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, domain + ":vpn")).upper()
    payload_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, domain + ":profile")).upper()
    return (
        text.replace("__DOMAIN__", domain)
        .replace("__VPN_UUID__", vpn_uuid)
        .replace("__PAYLOAD_UUID__", payload_uuid)
    )


def load_client_template(rel, domain):
    path = CLIENTS_DIR / rel
    return stamp_client_text(path.read_text(encoding="utf-8"), domain)


@app.route("/clients/windows.zip")
@login_required
def clients_windows():
    domain = client_domain()
    if not domain:
        flash_t("no_domain")
        return redirect(url_for("clients_page"))
    if not (CLIENTS_DIR / "windows" / "Install-IKEv2.ps1").is_file():
        flash_t("no_win_client")
        return redirect(url_for("clients_page"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in (
            "windows/Install-IKEv2.ps1",
            "windows/Install-IKEv2.bat",
            "windows/Check-Windows.bat",
            "windows/RAHNAMA.txt",
        ):
            z.writestr(Path(rel).name, load_client_template(rel, domain))
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name="IKEv2-windows.zip",
    )


@app.route("/clients/ios.mobileconfig")
@login_required
def clients_ios():
    domain = client_domain()
    if not domain:
        flash("دامنه در تنظیمات نیست.")
        return redirect(url_for("clients_page"))
    path = CLIENTS_DIR / "ios" / "IKEv2.mobileconfig"
    if not path.is_file():
        flash("فایل پروفایل iOS روی سرور نیست.")
        return redirect(url_for("clients_page"))
    data = load_client_template("ios/IKEv2.mobileconfig", domain).encode("utf-8")
    return send_file(
        io.BytesIO(data),
        mimetype="application/x-apple-aspen-config",
        as_attachment=True,
        download_name="IKEv2.mobileconfig",
    )




SMART_OS = ("windows", "ios", "android", "linux", "mac", "telegram")
SMART_NET = ("wifi", "mobile", "unknown")
SMART_UDP = ("ok", "blocked", "unknown")
SMART_PATH = ("extra_ok", "only443", "unknown")
SMART_FILTER = ("iran", "none")
# Score bias only — never a live ISP probe. Bump as_of when the panel ships a new snapshot.
FILTER_SNAPSHOT = {
    "iran": {
        "as_of": "2026-09",
        "note": "typical nationwide filtering; not a client-ISP probe",
        "bias": {
            "ikev2": -22,
            "l2tp": -28,
            "hy": 8,
            "vless": 10,
            "vmess": -8,
            "ss": -6,
            "http": -12,
            "mtg": 4,
        },
    }
}
SMART_UNITS = (
    "ikev2-l2tp-gui",
    "strongswan-starter",
    "xl2tpd",
    "panel-shadowsocks",
    "panel-hysteria",
    "panel-mtg",
)
PROTO_LABELS_SMART = {
    "ikev2": "IKEv2",
    "l2tp": "L2TP",
    "ss": "Shadowsocks",
    "hy": "Hysteria2",
    "vless": "VLESS Reality",
    "vmess": "VMess",
    "http": "HTTP",
    "mtg": "MTProto",
}
# Port class used only from the client form — never from a packet probe.
# extra TCP: VLESS 8443, VMess 2053, HTTP 10809, MTProto 3128, SS per-user
# UDP 500/4500/1701: IKEv2 / L2TP
# UDP 443: Hysteria2
PROTO_PORT_CLASS = {
    "ikev2": "udp_ike",
    "l2tp": "udp_ike",
    "hy": "udp_443",
    "vless": "extra_tcp",
    "vmess": "extra_tcp",
    "http": "extra_tcp",
    "mtg": "extra_tcp",
    "ss": "extra_tcp",
}


def _systemctl_active(unit):
    try:
        p = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return (p.stdout or "").strip() == "active"
    except Exception:
        return None


def _ufw_active():
    try:
        p = subprocess.run(
            ["ufw", "status"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        out = (p.stdout or "") + (p.stderr or "")
        if "Status: active" in out:
            return True
        if "Status: inactive" in out:
            return False
        return None
    except Exception:
        return None


def smart_vps_inventory(name, u, cfg):
    """Collect what this VPS actually has. Listening/configured, not ISP-reachable."""
    domain = (cfg.get("domain") or "").strip()
    fullchain, privkey = le_cert_paths(domain)
    le_ok = bool(domain) and fullchain.is_file() and privkey.is_file()
    services = {}
    for unit in SMART_UNITS:
        services[unit] = _systemctl_active(unit)
    ports = {
        "vless": int(cfg.get("vless_port") or 8443),
        "vmess": int(cfg.get("vmess_port") or 2053),
        "http": int(u.get("http_port") or cfg.get("http_port") or 10809),
        "mtg": int(cfg.get("mtg_port") or 3128),
        "hy": "%s/udp" % int(cfg.get("hy_port") or 443),
        "ss": int(u.get("ss_port") or 0) or None,
    }
    return {
        "note": "server inventory: configured/listening on this VPS, not a client-ISP probe",
        "user": name,
        "domain": domain,
        "public_ip": (cfg.get("public_ip") or "").strip(),
        "flags": {
            "ikev2": flag_on(u, "ikev2_enabled", True),
            "l2tp": flag_on(u, "l2tp_enabled", True),
            "ss": bool(u.get("ss_enabled")),
            "hy": bool(u.get("hy_enabled")),
            "vless": bool(u.get("vless_enabled")),
            "vmess": bool(u.get("vmess_enabled")),
            "http": bool(u.get("http_enabled")),
            "mtg": mtg_allowed(u),
        },
        "services": services,
        "le_cert": le_ok,
        "reality_public": bool((cfg.get("reality_public") or "").strip()),
        "mtg_secret": bool((cfg.get("mtg_secret") or "").strip()),
        "ports": ports,
        "ufw_active": _ufw_active(),
    }


def _smart_reason(key, lang, **kwargs):
    table = {
        "telegram_mtg": {
            "fa": "کلاینت تلگرام است و MTProto روی این کاربر و سرویس mtg فعال است.",
            "en": "Client is Telegram and MTProto is enabled for this user with mtg present.",
        },
        "hy_mobile": {
            "fa": "UDP باز است، گواهی LE هست، و روی موبایل Hysteria2 (UDP ۴۴۳) معمولاً پایدارترین گزینه است.",
            "en": "UDP is OK, LE cert exists, and on mobile Hysteria2 (UDP 443) is usually the most stable pick.",
        },
        "hy_udp": {
            "fa": "UDP باز و گواهی LE موجود است؛ Hysteria2 روی UDP ۴۴۳ امتیاز بالایی می‌گیرد.",
            "en": "UDP is OK and an LE cert is present; Hysteria2 on UDP 443 scores high.",
        },
        "hy_udp_unk": {
            "fa": "گواهی LE هست اما UDP نامشخص است؛ Hysteria2 فقط اگر UDP ۴۴۳ برسد کار می‌کند.",
            "en": "LE cert is present but UDP is unknown; Hysteria2 only works if UDP 443 arrives.",
        },
        "vless_extra": {
            "fa": "VLESS Reality روی TCP اضافه (پیش‌فرض ۸۴۴۳) ضدپروب است و به گواهی LE نیاز ندارد.",
            "en": "VLESS Reality on extra TCP (default 8443) is anti-probe and needs no LE cert.",
        },
        "vless_unk": {
            "fa": "مسیر TCP نامشخص است؛ VLESS Reality بدون LE و با ضدپروب هنوز گزینهٔ قوی است.",
            "en": "TCP path is unknown; VLESS Reality still ranks high (no LE, anti-probe).",
        },
        "vmess_extra": {
            "fa": "گواهی LE هست و پورت TCP اضافه برای VMess WS+TLS باز فرض شده.",
            "en": "LE cert exists and extra TCP is assumed open for VMess WS+TLS.",
        },
        "vmess_unk": {
            "fa": "گواهی LE هست اما مسیر TCP نامشخص است؛ VMess به پورت اضافه نیاز دارد.",
            "en": "LE cert exists but TCP path is unknown; VMess still needs an extra TCP port.",
        },
        "ss_extra": {
            "fa": "Shadowsocks روی پورت اختصاصی TCP/UDP این کاربر است؛ پورت اضافه باز فرض شده.",
            "en": "Shadowsocks uses this user’s extra TCP/UDP port; extra path is assumed open.",
        },
        "ss_unk": {
            "fa": "مسیر TCP نامشخص است؛ Shadowsocks فقط اگر پورت اختصاصی برسد کار می‌کند.",
            "en": "TCP path is unknown; Shadowsocks only works if the per-user port arrives.",
        },
        "ike_native": {
            "fa": "VPN داخلی سیستم‌عامل ترجیح داده شده و UDP مسدود نیست؛ IKEv2 بهترین گزینهٔ native است.",
            "en": "OS built-in VPN is preferred and UDP is not blocked; IKEv2 is the native pick.",
        },
        "ike_os": {
            "fa": "این سیستم‌عامل IKEv2 داخلی دارد و UDP مسدود نیست.",
            "en": "This OS has built-in IKEv2 and UDP is not blocked.",
        },
        "ike_other": {
            "fa": "IKEv2 روی سرور فعال است و UDP مسدود نیست؛ روی این OS معمولاً strongSwan لازم است.",
            "en": "IKEv2 is enabled and UDP is not blocked; this OS usually needs strongSwan.",
        },
        "l2_native_noike": {
            "fa": "VPN داخلی خواسته شده، IKEv2 خاموش است و UDP مسدود نیست؛ L2TP گزینهٔ native باقی‌مانده است.",
            "en": "Built-in VPN wanted, IKEv2 is off, UDP not blocked; L2TP is the remaining native option.",
        },
        "l2_low": {
            "fa": "L2TP از IKEv2 ضعیف‌تر است (DPI آسان) ولی روی سرور فعال و UDP مسدود نیست.",
            "en": "L2TP ranks below IKEv2 (easy DPI) but is enabled and UDP is not blocked.",
        },
        "http_last": {
            "fa": "پروکسی HTTP آخرین گزینه است؛ پورت TCP اضافه می‌خواهد و برای عبور از سانسور ضعیف است.",
            "en": "HTTP proxy is last; it needs extra TCP and is a weak censorship bypass.",
        },
        "generic": {
            "fa": "با موجودی سرور و شرایط واردشده هم‌خوان است.",
            "en": "Matches server inventory and the conditions you entered.",
        },
    }
    text = (table.get(key) or table["generic"]).get(lang) or table[key]["en"]
    if kwargs:
        try:
            return text % kwargs
        except (TypeError, ValueError, KeyError):
            return text
    return text


def _proto_enabled_for_user(pid, u):
    if pid == "ikev2":
        return flag_on(u, "ikev2_enabled", True)
    if pid == "l2tp":
        return flag_on(u, "l2tp_enabled", True)
    if pid == "ss":
        return bool(u.get("ss_enabled") and u.get("ss_key") and u.get("ss_port"))
    if pid == "hy":
        return bool(u.get("hy_enabled"))
    if pid == "vless":
        return bool(u.get("vless_enabled") and u.get("vless_uuid"))
    if pid == "vmess":
        return bool(u.get("vmess_enabled") and u.get("vmess_uuid"))
    if pid == "http":
        return bool(u.get("http_enabled"))
    if pid == "mtg":
        return mtg_allowed(u)
    return False


def _proto_inventory_ok(pid, inv):
    if pid in ("hy", "vmess", "http") and not inv.get("le_cert"):
        return False
    if pid == "vless" and not inv.get("reality_public"):
        return False
    if pid == "mtg":
        if not inv.get("mtg_secret"):
            return False
        mtg_svc = (inv.get("services") or {}).get("panel-mtg")
        if mtg_svc is False:
            return False
    return True


def _port_class_allowed(pid, form):
    """Do not recommend a protocol whose port class the form says is blocked."""
    cls = PROTO_PORT_CLASS.get(pid)
    path = form.get("path") or "unknown"
    udp = form.get("udp") or "unknown"
    if cls == "extra_tcp" and path == "only443":
        return False
    if cls in ("udp_ike", "udp_443") and udp == "blocked":
        return False
    return True


def _score_protocol(pid, form, ikev2_on):
    """Deterministic 0–100 heuristic. Documented scores; ranking runs with no API key.

    - telegram OS → MTProto first if enabled
    - udp=ok + hy + cert (caller already required cert) → Hysteria2 very high,
      especially net=mobile
    - VLESS Reality high when path is extra_ok or unknown (no LE, anti-probe)
    - VMess only with cert (caller) and path extra_ok/unknown; downrank vs VLESS
    - SS similar extra TCP/UDP; downrank only443 (caller skips only443)
    - IKEv2 high if native or os in windows/ios/android/mac and UDP not blocked
    - L2TP lower than IKEv2 (easy DPI) unless native and IKEv2 off and UDP ok
    - HTTP last; extra TCP; never first unless everything else is impossible
    """
    os_ = form.get("os") or "unknown"
    net = form.get("net") or "unknown"
    udp = form.get("udp") or "unknown"
    path = form.get("path") or "unknown"
    native = bool(form.get("native"))
    reason = "generic"
    score = 40

    if pid == "mtg":
        score = 58
        if path == "extra_ok":
            score += 6
        if os_ == "telegram":
            score = 96
            reason = "telegram_mtg"
        else:
            reason = "generic"
    elif pid == "hy":
        if udp == "ok":
            score = 90
            reason = "hy_udp"
            if net == "mobile":
                score = 97
                reason = "hy_mobile"
        else:
            score = 56
            reason = "hy_udp_unk"
            if net == "mobile":
                score += 6
    elif pid == "vless":
        if path == "extra_ok":
            score = 86
            reason = "vless_extra"
        else:
            score = 78
            reason = "vless_unk"
        if os_ == "telegram":
            score -= 18
    elif pid == "vmess":
        if path == "extra_ok":
            score = 68
            reason = "vmess_extra"
        else:
            score = 58
            reason = "vmess_unk"
        if os_ == "telegram":
            score -= 12
    elif pid == "ss":
        if path == "extra_ok":
            score = 70
            reason = "ss_extra"
        else:
            score = 60
            reason = "ss_unk"
        if udp == "ok":
            score += 4
        elif udp == "blocked":
            score -= 8
        if os_ == "telegram":
            score -= 10
    elif pid == "ikev2":
        native_os = os_ in ("windows", "ios", "android", "mac")
        if native or native_os:
            score = 82 if native else 74
            reason = "ike_native" if native else "ike_os"
        elif os_ == "linux":
            score = 58
            reason = "ike_other"
        else:
            score = 42
            reason = "ike_other"
        if udp == "ok":
            score += 6
        if os_ == "telegram":
            score = 22
            reason = "ike_other"
    elif pid == "l2tp":
        if native and not ikev2_on:
            score = 76
            reason = "l2_native_noike"
        else:
            score = 40
            reason = "l2_low"
            if native:
                score = 52
        if udp == "ok":
            score += 3
        if os_ == "telegram":
            score = 18
            reason = "l2_low"
    elif pid == "http":
        score = 24 if path == "extra_ok" else 20
        reason = "http_last"
    score = max(0, min(100, int(score) + _filter_bias(pid, form)))
    return score, reason


def _filter_bias(pid, form):
    """Country snapshot bias. Explicit form answers (udp=ok, extra_ok) override."""
    if (form.get("filter") or "iran") != "iran":
        return 0
    snap = FILTER_SNAPSHOT.get("iran") or {}
    bias = int((snap.get("bias") or {}).get(pid) or 0)
    udp = form.get("udp") or "unknown"
    path = form.get("path") or "unknown"
    if pid in ("ikev2", "l2tp") and udp == "ok":
        return 0
    if pid in ("vmess", "ss", "http") and path == "extra_ok":
        return 0
    if pid == "hy" and udp == "blocked":
        return 0
    return bias


def _smart_uri_and_link(pid, name, u, cfg):
    uri = ""
    host = (cfg.get("domain") or cfg.get("public_ip") or "").strip()
    endpoint = ""
    client_url = ""
    try:
        if pid == "ss" and u.get("ss_key") and u.get("ss_port"):
            uri = ss_uri(name, u, cfg)
            client_url = "/clients/ss/%s" % urllib.parse.quote(name)
        elif pid == "hy" and u.get("password"):
            uri = hy_uri(name, u, cfg)
            client_url = "/clients/hysteria/%s" % urllib.parse.quote(name)
        elif pid == "vless" and u.get("vless_uuid"):
            uri = vless_uri(name, u, cfg)
            client_url = "/clients/vless/%s" % urllib.parse.quote(name)
        elif pid == "vmess" and u.get("vmess_uuid"):
            uri = vmess_uri(name, u, cfg)
            client_url = "/clients/vmess/%s" % urllib.parse.quote(name)
        elif pid == "http" and u.get("password"):
            uri = http_proxy_uri(name, u, cfg)
            client_url = "/clients/http/%s" % urllib.parse.quote(name)
        elif pid == "mtg":
            uri = mtg_uri(cfg)
            client_url = "/clients/mtg/%s" % urllib.parse.quote(name)
        elif pid in ("ikev2", "l2tp"):
            endpoint = "%s  ·  %s" % (host, name)
            client_url = "/clients"
    except Exception:
        uri = ""
    return uri, endpoint, client_url


def rank_smart_connect(name, u, cfg, form, lang="fa"):
    """Rank up to 3 protocols from inventory + form. Works with no LLM key."""
    inv = smart_vps_inventory(name, u, cfg)
    skipped = []
    ranked = []
    ikev2_on = _proto_enabled_for_user("ikev2", u) and _port_class_allowed("ikev2", form)
    for pid in ("mtg", "hy", "vless", "vmess", "ss", "ikev2", "l2tp", "http"):
        if not _proto_enabled_for_user(pid, u):
            skipped.append({"id": pid, "why": "user_disabled"})
            continue
        if not _proto_inventory_ok(pid, inv):
            skipped.append({"id": pid, "why": "inventory"})
            continue
        if not _port_class_allowed(pid, form):
            skipped.append({"id": pid, "why": "port_class"})
            continue
        score, rkey = _score_protocol(pid, form, ikev2_on)
        uri, endpoint, client_url = _smart_uri_and_link(pid, name, u, cfg)
        ranked.append(
            {
                "id": pid,
                "label": PROTO_LABELS_SMART[pid],
                "score": int(score),
                "reason_key": rkey,
                "reason": _smart_reason(rkey, lang),
                "reason_fa": _smart_reason(rkey, "fa"),
                "reason_en": _smart_reason(rkey, "en"),
                "uri": uri,
                "endpoint": endpoint,
                "client_url": client_url,
            }
        )
    ranked.sort(key=lambda r: (-r["score"], r["id"]))
    # HTTP never first unless everything else is impossible.
    if ranked and ranked[0]["id"] == "http" and len(ranked) > 1:
        http_row = ranked.pop(0)
        ranked.append(http_row)
    candidates = [dict(r) for r in ranked]
    top = [dict(r) for r in ranked[:3]]
    for i, row in enumerate(top, 1):
        row["rank"] = i
    honest = (form.get("path") == "only443" and form.get("udp") == "blocked")
    return {
        "inventory": inv,
        "form": {
            "user": name,
            "os": form.get("os"),
            "net": form.get("net"),
            "udp": form.get("udp"),
            "path": form.get("path"),
            "native": bool(form.get("native")),
            "filter": form.get("filter") or "iran",
        },
        "filter_snapshot": FILTER_SNAPSHOT.get(form.get("filter") or "iran") if (form.get("filter") or "iran") != "none" else None,
        "ranked": top,
        "candidates": candidates,
        "skipped": skipped,
        "honest_443": honest,
    }


def parse_smart_form(src):
    name = (src.get("user") or "").strip()
    os_ = (src.get("os") or "").strip()
    net = (src.get("net") or "unknown").strip()
    udp = (src.get("udp") or "unknown").strip()
    path = (src.get("path") or "unknown").strip()
    native_raw = src.get("native")
    native = str(native_raw or "").strip() in ("1", "on", "true", "yes")
    filt = (src.get("filter") or "iran").strip()
    if os_ not in SMART_OS:
        os_ = "android"
    if net not in SMART_NET:
        net = "mobile"
    if udp not in SMART_UDP:
        udp = "unknown"
    if path not in SMART_PATH:
        path = "unknown"
    if filt not in SMART_FILTER:
        filt = "iran"
    return {
        "user": name,
        "os": os_,
        "net": net,
        "udp": udp,
        "path": path,
        "native": native,
        "filter": filt,
    }


def _ai_chat_url(base):
    base = (base or "").strip().rstrip("/")
    if not base:
        return ""
    low = base.lower()
    if low.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def _ip_blocked(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_unspecified:
        return True
    if ip.version == 4:
        n = int(ip)
        if 0x64400000 <= n <= 0x647FFFFF:  # 100.64.0.0/10 shared address space
            return True
    return False


def _host_blocked(host):
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in ("napi.arvancloud.ir", "napi.arvancloud.com"):
        return True
    if host in (
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
        "internal",
    ):
        return True
    if host.endswith((".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".localdomain")):
        return True
    if host.startswith("metadata."):
        return True
    if host.isdigit() or host.startswith("0x"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        if _ip_blocked(ip):
            return True
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, ValueError):
        return True
    if not infos:
        return True
    saw_ip = False
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return True
        saw_ip = True
        if _ip_blocked(ip):
            return True
    return not saw_ip


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        if self._tunnel_host:
            raise OSError("Proxy tunneling is not permitted")
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses or any(_ip_blocked(ipaddress.ip_address(row[4][0])) for row in addresses):
            raise OSError("Non-public destination")
        # Connect to the checked numeric address; preserve the hostname for
        # certificate verification and SNI. No second hostname resolution.
        last_error = None
        for family, socktype, proto, _, address in addresses:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                sock.connect(address)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as error:
                sock.close()
                last_error = error
        raise last_error or OSError("Connection failed")


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PublicHTTPSConnection, req, context=self._context)


def _ai_base_ok(base):
    base = (base or "").strip()
    if not base:
        return True
    try:
        u = urllib.parse.urlparse(base)
    except ValueError:
        return False
    if u.scheme != "https" or not u.netloc:
        return False
    if u.username or u.password:
        return False
    host = (u.hostname or "").lower()
    if not host:
        return False
    try:
        port = u.port
    except ValueError:
        return False
    if port is not None and not (1 <= port <= 65535):
        return False
    if _host_blocked(host):
        return False
    return True


def _extract_json_object(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text, flags=re.I).strip()
        text = re.sub(r"```\s*$", "", text).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _ai_reason_ok(text):
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text or "")).strip()
    return text[:400]


def _apply_ai_ranked(result, payload):
    """Keep URIs/labels from candidates. Drop invented or skipped protocol ids."""
    by_id = {}
    for row in (result.get("candidates") or result.get("ranked") or []):
        pid = row.get("id")
        if pid:
            by_id[pid] = row
    skipped = {s.get("id") for s in (result.get("skipped") or []) if s.get("id")}
    raw = payload.get("ranked") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return None
    out = []
    seen = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        pid = str(item.get("id") or "").strip()
        if pid not in by_id or pid in skipped or pid in seen:
            continue
        try:
            score = int(item.get("score"))
        except (TypeError, ValueError):
            score = int(by_id[pid].get("score") or 0)
        score = max(0, min(100, score))
        row = dict(by_id[pid])
        row["score"] = score
        reason = _ai_reason_ok(item.get("reason"))
        if reason:
            row["reason"] = reason
        out.append(row)
        seen.add(pid)
        if len(out) >= 3:
            break
    if not out:
        return None
    if out[0]["id"] == "http" and len(out) > 1:
        http_row = out.pop(0)
        out.append(http_row)
    for i, row in enumerate(out, 1):
        row["rank"] = i
    return out


def smart_ai_review(result, lang):
    """Optional OpenAI-compatible chat. Never logs the key. 12s timeout.

    Ranker runs first. Model may reorder/rescore candidates from inventory.
    Must not invent protocols/ports. On failure, keep the rules ranking.
    Returns (explain_text, status, new_ranked_or_None).
    """
    cfg = load_config()
    key = (cfg.get("ai_api_key") or "").strip()
    base = (cfg.get("ai_base") or "").strip()
    model = (cfg.get("ai_model") or "").strip()
    if not key or not base or not model:
        return None, "none", None
    if not _ai_base_ok(base):
        return None, "fail", None
    candidates = result.get("candidates") or result.get("ranked") or []
    if not candidates:
        return None, "none", None
    url = _ai_chat_url(base)
    payload = {
        "inventory": result.get("inventory"),
        "form": result.get("form"),
        "candidates": [
            {
                "id": r.get("id"),
                "score": r.get("score"),
                "reason": r.get("reason"),
            }
            for r in candidates
        ],
        "ranked_now": [
            {"id": r.get("id"), "score": r.get("score")}
            for r in (result.get("ranked") or [])
        ],
        "skipped": result.get("skipped") or [],
        "honest_443": result.get("honest_443"),
        "filter_snapshot": result.get("filter_snapshot"),
    }
    lang_name = "Persian" if lang == "fa" else "English"
    system = (
        "You review a VPN protocol ranking and MAY change order, scores, or drop items. "
        "filter_snapshot is a shipped country-filtering bias, not a live ISP probe. "
        "Use ONLY protocol ids from candidates. Never invent protocols, ports, or ISP reachability. "
        "Do not pick skipped ids. Inventory is server-side (listening/configured), not a client probe. "
        "HTTP must not be rank 1 unless it is the only item. "
        "Reply with JSON only, no markdown: "
        '{"ranked":[{"id":"hy","score":95,"reason":"..."}],"explain":"..."} '
        "ranked has 1 to 3 unique candidate ids, score 0-100. "
        "explain is short %s (max 8 sentences) saying whether you kept or changed the order and why."
        % lang_name
    )
    body = json.dumps(
        {
            "model": model,
            "temperature": 0.2,
            "max_tokens": 500,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
        }
    ).encode("utf-8")
    chat_base = url.rsplit("/chat/completions", 1)[0] if url.endswith("/chat/completions") else url
    if not _ai_base_ok(chat_base):
        return None, "fail", None
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + key,
        },
    )
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect, _PublicHTTPSHandler)
        with opener.open(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = (
            (((data.get("choices") or [{}])[0]).get("message") or {}).get("content") or ""
        ).strip()
        parsed = _extract_json_object(text)
        if not parsed:
            return None, "fail", None
        new_ranked = _apply_ai_ranked(result, parsed)
        explain = _ai_reason_ok(parsed.get("explain") or "")
        if not explain and new_ranked:
            explain = text[:400]
        if not new_ranked:
            return (explain or None), "fail", None
        return (explain or None), "ok", new_ranked
    except Exception:
        return None, "fail", None


def smart_ai_explain(result, lang):
    text, status, _ranked = smart_ai_review(result, lang)
    return text, status



def ss_uri(name, u, cfg):
    key = u.get("ss_key") or ""
    port = int(u.get("ss_port") or 0)
    host = (cfg.get("domain") or cfg.get("public_ip") or "").strip()
    plain = "%s:%s" % (SS_METHOD, key)
    userinfo = base64.urlsafe_b64encode(plain.encode()).decode().rstrip("=")
    return "ss://%s@%s:%d#%s" % (userinfo, host, port, urllib.parse.quote(name))


def hy_uri(name, u, cfg):
    pw = u.get("password") or ""
    port = int(cfg.get("hy_port") or 443)
    domain = (cfg.get("domain") or "").strip()
    host = domain or (cfg.get("public_ip") or "").strip()
    auth = "%s:%s" % (urllib.parse.quote(name), urllib.parse.quote(pw))
    q = {"sni": domain, "insecure": "0"} if domain else {"insecure": "1"}
    obfs_pw = cfg.get("hy_obfs_password") or ""
    if obfs_pw:
        q["obfs"] = "salamander"
        q["obfs-password"] = obfs_pw
    return "hysteria2://%s@%s:%d/?%s#%s" % (
        auth,
        host,
        port,
        urllib.parse.urlencode(q),
        urllib.parse.quote(name),
    )


def vless_uri(name, u, cfg):
    uid = u.get("vless_uuid") or ""
    port = int(cfg.get("vless_port") or 8443)
    host = (cfg.get("domain") or cfg.get("public_ip") or "").strip()
    names = cfg.get("reality_server_names") or ["www.microsoft.com"]
    dest = (cfg.get("reality_dest") or "www.microsoft.com:443").strip()
    sni = names[0] if names else dest.split(":")[0]
    q = {
        "type": "tcp",
        "encryption": "none",
        "security": "reality",
        "flow": "xtls-rprx-vision",
        "sni": sni,
        "fp": "chrome",
        "pbk": (cfg.get("reality_public") or "").strip(),
        "sid": (cfg.get("reality_short_id") or "").strip(),
    }
    return "vless://%s@%s:%d?%s#%s" % (
        uid,
        host,
        port,
        urllib.parse.urlencode(q),
        urllib.parse.quote(name),
    )


def vmess_uri(name, u, cfg):
    uid = u.get("vmess_uuid") or ""
    port = int(cfg.get("vmess_port") or 2053)
    domain = (cfg.get("domain") or "").strip()
    host = domain or (cfg.get("public_ip") or "").strip()
    obj = {
        "add": host,
        "ps": name,
        "port": str(port),
        "id": uid,
        "aid": 0,
        "net": "ws",
        "tls": "tls",
        "host": domain or host,
        "path": VMESS_PATH,
        "sni": domain or host,
        "v": "2",
        "type": "none",
    }
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
    return "vmess://" + base64.b64encode(raw.encode("utf-8")).decode("ascii")


def http_proxy_uri(name, u, cfg):
    port = int(u.get("http_port") or cfg.get("http_port") or 10809)
    host = (cfg.get("domain") or cfg.get("public_ip") or "").strip()
    pw = u.get("password") or ""
    return "https://%s:%s@%s:%d" % (
        urllib.parse.quote(name, safe=""),
        urllib.parse.quote(pw, safe=""),
        host,
        port,
    )


def mtg_uri(cfg):
    host = (cfg.get("domain") or cfg.get("public_ip") or "").strip()
    port = int(cfg.get("mtg_port") or 3128)
    secret = (cfg.get("mtg_secret") or "").strip()
    return "tg://proxy?server=%s&port=%d&secret=%s" % (
        urllib.parse.quote(host, safe=""),
        port,
        urllib.parse.quote(secret, safe=""),
    )


def sub_uris(name, u, cfg):
    uris = []
    if u.get("ss_enabled") and u.get("ss_key") and u.get("ss_port"):
        uris.append(ss_uri(name, u, cfg))
    if u.get("hy_enabled") and u.get("password"):
        uris.append(hy_uri(name, u, cfg))
    if u.get("vless_enabled") and u.get("vless_uuid"):
        uris.append(vless_uri(name, u, cfg))
    if u.get("vmess_enabled") and u.get("vmess_uuid"):
        uris.append(vmess_uri(name, u, cfg))
    if u.get("http_enabled") and u.get("password"):
        uris.append(http_proxy_uri(name, u, cfg))
    if mtg_allowed(u) and (cfg.get("mtg_secret") or ""):
        uris.append(mtg_uri(cfg))
    return uris


def ensure_sub_token(users, name):
    token = users[name].get("sub_token")
    if token:
        return token
    token = new_sub_token()
    users[name]["sub_token"] = token
    save_users(users)
    return token


def qr_png(data):
    p = subprocess.run(
        ["qrencode", "-o", "-", "-t", "PNG", "-s", "6", "-m", "2", data],
        capture_output=True,
        timeout=5,
    )
    return p.stdout


@app.route("/clients/ss/<name>")
@login_required
def clients_ss(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("ss_enabled"):
        flash_t("ss_off")
        return redirect(url_for("clients_page"))
    cfg = load_config()
    uri = ss_uri(name, u, cfg)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="Shadowsocks — %s" % name,
        page_subtitle="کانفیگ اتصال Shadowsocks (2022) این کاربر",
        proto_name="Shadowsocks",
        uri=uri,
        qr_url=url_for("clients_ss_qr", name=name),
        method=SS_METHOD,
        server_key="",
        user_key=u.get("ss_key") or "",
        port=u.get("ss_port"),
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/ss/<name>/qr.png")
@login_required
def clients_ss_qr(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("ss_enabled"):
        return ("", 404)
    png = qr_png(ss_uri(name, u, load_config()))
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})


@app.route("/clients/hysteria/<name>")
@login_required
def clients_hysteria(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("hy_enabled"):
        flash("Hysteria2 برای این کاربر فعال نیست.")
        return redirect(url_for("clients_page"))
    cfg = load_config()
    uri = hy_uri(name, u, cfg)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="Hysteria2 — %s" % name,
        page_subtitle="کانفیگ اتصال Hysteria2 این کاربر",
        proto_name="Hysteria2",
        uri=uri,
        qr_url=url_for("clients_hysteria_qr", name=name),
        method="",
        server_key="",
        user_key="",
        port=cfg.get("hy_port"),
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/hysteria/<name>/qr.png")
@login_required
def clients_hysteria_qr(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("hy_enabled"):
        return ("", 404)
    png = qr_png(hy_uri(name, u, load_config()))
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})


@app.route("/clients/vless/<name>")
@login_required
def clients_vless(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("vless_enabled"):
        flash("VLESS برای این کاربر فعال نیست.")
        return redirect(url_for("clients_page"))
    cfg = load_config()
    uri = vless_uri(name, u, cfg)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="VLESS — %s" % name,
        page_subtitle="کانفیگ اتصال VLESS Reality (Vision) این کاربر",
        proto_name="VLESS",
        uri=uri,
        qr_url=url_for("clients_vless_qr", name=name),
        method="",
        server_key="",
        user_key=u.get("vless_uuid") or "",
        port=cfg.get("vless_port"),
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/vless/<name>/qr.png")
@login_required
def clients_vless_qr(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("vless_enabled"):
        return ("", 404)
    png = qr_png(vless_uri(name, u, load_config()))
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})


@app.route("/clients/vmess/<name>")
@login_required
def clients_vmess(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("vmess_enabled"):
        flash("VMess برای این کاربر فعال نیست.")
        return redirect(url_for("clients_page"))
    cfg = load_config()
    uri = vmess_uri(name, u, cfg)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="VMess — %s" % name,
        page_subtitle="کانفیگ اتصال VMess (WebSocket + TLS) این کاربر",
        proto_name="VMess",
        uri=uri,
        qr_url=url_for("clients_vmess_qr", name=name),
        method="ws+tls",
        server_key="",
        user_key=u.get("vmess_uuid") or "",
        port=cfg.get("vmess_port") or 2053,
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/vmess/<name>/qr.png")
@login_required
def clients_vmess_qr(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("vmess_enabled"):
        return ("", 404)
    png = qr_png(vmess_uri(name, u, load_config()))
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})


@app.route("/clients/http/<name>")
@login_required
def clients_http(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("http_enabled"):
        flash("پروکسی HTTP برای این کاربر فعال نیست.")
        return redirect(url_for("clients_page"))
    cfg = load_config()
    uri = http_proxy_uri(name, u, cfg)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="HTTPS Proxy — %s" % name,
        page_subtitle="پروکسی HTTP این کاربر (host:port + نام کاربری / رمز)",
        proto_name="HTTPS Proxy",
        uri=uri,
        qr_url=url_for("clients_http_qr", name=name),
        method="https",
        server_key=u.get("password") or "",
        user_key=name,
        port=u.get("http_port") or cfg.get("http_port") or 10809,
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/http/<name>/qr.png")
@login_required
def clients_http_qr(name):
    users = load_users()
    u = users.get(name)
    if not u or not u.get("http_enabled"):
        return ("", 404)
    png = qr_png(http_proxy_uri(name, u, load_config()))
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})


@app.route("/clients/mtg/<name>")
@login_required
def clients_mtg(name):
    users = load_users()
    u = users.get(name)
    if not u or not mtg_allowed(u):
        flash("MTProto برای این کاربر فعال نیست.")
        return redirect(url_for("clients_page"))
    cfg = load_config()
    if not (cfg.get("mtg_secret") or "").strip():
        with _lock:
            write_mtg_config(users)
            cfg = load_config()
    uri = mtg_uri(cfg)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="MTProto — %s" % name,
        page_subtitle="لینک پروکسی تلگرام (یک secret مشترک برای همهٔ کاربران فعال)",
        proto_name="MTProto",
        uri=uri,
        qr_url=url_for("clients_mtg_qr", name=name),
        method="FakeTLS",
        server_key=cfg.get("mtg_secret") or "",
        user_key="",
        port=cfg.get("mtg_port") or 3128,
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/mtg/<name>/qr.png")
@login_required
def clients_mtg_qr(name):
    users = load_users()
    u = users.get(name)
    if not u or not mtg_allowed(u):
        return ("", 404)
    png = qr_png(mtg_uri(load_config()))
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})


@app.route("/sub/<name>/<token>")
def subscription(name, token):
    # Public by design — this is what proxy client apps auto-refresh from,
    # they can't hold a panel login session. The per-user token is the
    # only guard, so it must be checked with a constant-time comparison.
    if not USER_RE.match(name or ""):
        return ("", 404)
    users = load_users()
    u = users.get(name)
    expected = (u or {}).get("sub_token") or ""
    token = token or ""
    if not u or user_blocked(u) or not expected or len(token) != len(expected):
        return ("", 404)
    if not secrets.compare_digest(token, expected):
        return ("", 404)
    cfg = load_config()
    body = "\n".join(sub_uris(name, u, cfg))
    encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
    return (
        encoded,
        200,
        {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "Subscription-Userinfo": sub_userinfo(u),
            "Content-Disposition": 'attachment; filename="%s.txt"' % name,
        },
    )


def sub_userinfo(u):
    # Standard header most subscription-aware clients (sing-box, NekoBox,
    # Shadowrocket, Clash...) read to show remaining quota/expiry without
    # any extra API call. total=0 means unlimited, expire=0 means never.
    used = int(float(u.get("used_bytes") or 0))
    q = float(u.get("quota_gb") or 0)
    total = int(q * (1024 ** 3)) if q > 0 else 0
    expire = 0
    exp = (u.get("expires") or "").strip()
    if exp:
        try:
            d = date.fromisoformat(exp)
            expire = int(datetime(d.year, d.month, d.day, 23, 59, 59, tzinfo=TZ).timestamp())
        except ValueError:
            pass
    return "upload=0; download=%d; total=%d; expire=%d" % (used, total, expire)


@app.route("/clients/sub/<name>")
@login_required
def clients_sub(name):
    with _lock:
        users = load_users()
        u = users.get(name)
        if not u:
            flash_t("user_missing")
            return redirect(url_for("clients_page"))
        token = ensure_sub_token(users, name)
    cfg = load_config()
    url = "https://" + request.host + url_for("subscription", name=name, token=token)
    d = dashboard_payload()
    d["admin_user"] = load_admin().get("user") or ""
    d.update(
        page="clients",
        page_title="لینک Sub — %s" % name,
        page_subtitle="لینک اشتراک به‌روزشونده؛ هر تغییری در پروتکل‌های این کاربر خودکار توش منعکس می‌شه",
        proto_name="Subscription",
        uri=url,
        qr_url=url_for("clients_sub_qr", name=name),
        method="",
        server_key="",
        user_key="",
        port="",
    )
    return render_template("client_proto.html", **d)


@app.route("/clients/sub/<name>/qr.png")
@login_required
def clients_sub_qr(name):
    with _lock:
        users = load_users()
        u = users.get(name)
        if not u:
            return ("", 404)
        token = ensure_sub_token(users, name)
    url = "https://" + request.host + url_for("subscription", name=name, token=token)
    png = qr_png(url)
    return (png, 200, {"Content-Type": "image/png", "Cache-Control": "no-store"})



_SPEED_HOSTS = frozenset(("speed.cloudflare.com", "cachefly.cachefly.net", "proof.ovh.net"))
_SPEED_DOWN_URLS = (
    "https://speed.cloudflare.com/__down?bytes=8000000",
    "https://cachefly.cachefly.net/10mb.test",
    "https://proof.ovh.net/files/10Mb.dat",
)
_SPEED_UP_URL = "https://speed.cloudflare.com/__up"
_speed_lock = threading.Lock()


def load_speed_last():
    data = load_json(SPEED_FILE, {})
    return data if isinstance(data, dict) else {}


def save_speed_last(data):
    try:
        save_json(SPEED_FILE, data)
    except OSError:
        pass


def _speed_url_ok(url):
    try:
        u = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if u.scheme != "https" or u.username or u.password:
        return False
    host = (u.hostname or "").lower()
    if host not in _SPEED_HOSTS:
        return False
    if _host_blocked(host):
        return False
    return True


def _speed_opener():
    return urllib.request.build_opener(_NoRedirect)


def _tcp_ping_ms(host, port=443, timeout=4):
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
    except OSError:
        return None
    return round((time.perf_counter() - t0) * 1000.0, 1)


def _speed_download():
    opener = _speed_opener()
    headers = {"User-Agent": "NH-MultiVPN-speedtest", "Accept": "*/*"}
    for url in _SPEED_DOWN_URLS:
        if not _speed_url_ok(url):
            continue
        host = urllib.parse.urlparse(url).hostname
        req = urllib.request.Request(url, headers=headers, method="GET")
        t0 = time.perf_counter()
        n = 0
        try:
            with opener.open(req, timeout=12) as resp:
                while n < 12 * 1024 * 1024:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    n += len(chunk)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
            continue
        dt = time.perf_counter() - t0
        if n < 64 * 1024 or dt <= 0:
            continue
        mbps = (n * 8.0) / dt / 1_000_000.0
        return {"ok": True, "mbps": round(mbps, 2), "bytes": n, "sec": round(dt, 2), "host": host}
    return {"ok": False}


def _speed_upload():
    if not _speed_url_ok(_SPEED_UP_URL):
        return {"ok": False}
    payload = b"\x00" * (4 * 1024 * 1024)
    req = urllib.request.Request(
        _SPEED_UP_URL,
        data=payload,
        method="POST",
        headers={
            "User-Agent": "NH-MultiVPN-speedtest",
            "Content-Type": "application/octet-stream",
        },
    )
    t0 = time.perf_counter()
    try:
        with _speed_opener().open(req, timeout=12) as resp:
            resp.read(4096)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError):
        return {"ok": False}
    dt = time.perf_counter() - t0
    if dt <= 0:
        return {"ok": False}
    mbps = (len(payload) * 8.0) / dt / 1_000_000.0
    return {"ok": True, "mbps": round(mbps, 2), "bytes": len(payload), "sec": round(dt, 2)}


def run_speed_test():
    started_dt = now_tehran()
    ping = _tcp_ping_ms("speed.cloudflare.com")
    if ping is None:
        ping = _tcp_ping_ms("1.0.0.1")
    down = _speed_download()
    up = _speed_upload() if down.get("ok") else {"ok": False}
    ended_dt = now_tehran()
    result = {
        "ok": bool(down.get("ok")),
        "at": ended_dt.strftime("%Y/%m/%d %H:%M:%S"),
        "started": started_dt.strftime("%H:%M:%S"),
        "ended": ended_dt.strftime("%H:%M:%S"),
        "ping_ms": ping,
        "down_mbps": down.get("mbps") if down.get("ok") else None,
        "up_mbps": up.get("mbps") if up.get("ok") else None,
    }
    if result["ok"]:
        save_speed_last(result)
    return result


@app.route("/health/ready")
def health_ready():
    if request.remote_addr not in ("127.0.0.1", "::1") or request.headers.get("X-Real-IP"):
        return ("", 404)
    ready = bool(getattr(app, "_accounts_ready", False))
    return jsonify({"ready": ready}), 200 if ready else 503


@app.route("/api/status")
@login_required
def api_status():
    d = dashboard_payload()
    return jsonify(
        {
            "online": d["online"],
            "online_count": d["online_count"],
            "total": d["total"],
            "sessions": [
                {
                    "user": s.get("user"),
                    "proto": s.get("proto"),
                    "vip": s.get("vip"),
                    "remote": s.get("remote"),
                    "uptime": s.get("uptime"),
                    "bytes_h": s.get("bytes_h"),
                }
                for s in d["sessions"]
            ],
            "cpu": d["stats"]["cpu"],
            "mem_pct": d["stats"]["mem_pct"],
            "load1": d["stats"]["load1"],
            "net_rx_h": d["net_rx_h"],
            "net_tx_h": d["net_tx_h"],
            "net_down_h": d["net_down_h"],
            "net_up_h": d["net_up_h"],
            "now_fa": d["now_fa"],
            "now": d["now"],
            "public_ip": d.get("public_ip") or d.get("host") or "",
        }
    )



@app.route("/api/speedtest", methods=["POST"])
@login_required
@csrf_required
def api_speedtest():
    if not _speed_lock.acquire(blocking=False):
        return jsonify({"ok": False, "error": "busy"}), 429
    try:
        result = run_speed_test()
    finally:
        _speed_lock.release()
    if not result.get("ok"):
        return jsonify(result), 502
    return jsonify(result)


@app.route("/users/add", methods=["POST"])
@login_required
@csrf_required

def users_add():
    name = (request.form.get("name") or "").strip()
    password = (request.form.get("password") or "").strip()
    expires = (request.form.get("expires") or "").strip()
    quota = (request.form.get("quota_gb") or "0").strip() or "0"
    ikev2_enabled = request.form.get("ikev2_enabled") == "1"
    l2tp_enabled = request.form.get("l2tp_enabled") == "1"
    ss_enabled = request.form.get("ss_enabled") == "1"
    hy_enabled = request.form.get("hy_enabled") == "1"
    vless_enabled = request.form.get("vless_enabled") == "1"
    vmess_enabled = request.form.get("vmess_enabled") == "1"
    http_enabled = request.form.get("http_enabled") == "1"
    mtg_enabled = request.form.get("mtg_enabled") == "1" or request.form.get("mtp") == "1"
    if not USER_RE.match(name):
        flash_t("user_name_bad")
        return redirect(url_for("users_page"))
    if not vpn_password_ok(password):
        flash_t("vpn_pass_bad")
        return redirect(url_for("users_page"))
    if expires:
        try:
            date.fromisoformat(expires)
        except ValueError:
            flash_t("expires_bad")
            return redirect(url_for("users_page"))
    try:
        q = float(quota)
        if not math.isfinite(q) or q < 0:
            raise ValueError()
    except ValueError:
        flash_t("quota_bad")
        return redirect(url_for("users_page"))
    with _lock:
        users = load_users()
        if name in users:
            flash_t("user_exists")
            return redirect(url_for("users_page"))
        users[name] = {
            "password": password,
            "expires": expires,
            "quota_gb": q,
            "used_bytes": 0,
            "created": today_iso(),
            "enabled": True,
            "ikev2_enabled": ikev2_enabled,
            "l2tp_enabled": l2tp_enabled,
            "ss_enabled": ss_enabled,
            "hy_enabled": hy_enabled,
            "vless_enabled": vless_enabled,
            "vmess_enabled": vmess_enabled,
            "http_enabled": http_enabled,
            "mtg_enabled": mtg_enabled,
            "ss_key": new_ss_key() if ss_enabled else "",
            "ss_port": allocate_ss_port() if ss_enabled else None,
            "vless_uuid": new_vless_uuid() if vless_enabled else "",
            "vmess_uuid": new_vmess_uuid() if vmess_enabled else "",
            "sub_token": new_sub_token(),
        }
        forget_deleted_user(name)
        save_users(users)
        sync_accounts(users)
    proto_note = []
    if ikev2_enabled:
        proto_note.append("IKEv2")
    if l2tp_enabled:
        proto_note.append("L2TP")
    if ss_enabled:
        proto_note.append("Shadowsocks")
    if vless_enabled:
        proto_note.append("VLESS")
    if hy_enabled:
        proto_note.append("Hysteria2")
    if vmess_enabled:
        proto_note.append("VMess")
    if http_enabled:
        proto_note.append("HTTP")
    if mtg_enabled:
        proto_note.append("MTProto")
    label = " + ".join(proto_note) if proto_note else "—"
    flash_t("user_added", name=name, label=label)
    return redirect(url_for("users_page"))



@app.route("/users/update", methods=["POST"])
@login_required
@csrf_required
def users_update():
    name = (request.form.get("name") or "").strip()
    password = (request.form.get("password") or "").strip()
    expires = (request.form.get("expires") or "").strip()
    quota = (request.form.get("quota_gb") or "").strip()
    reset = request.form.get("reset_traffic") == "1"
    ikev2_enabled = request.form.get("ikev2_enabled") == "1"
    l2tp_enabled = request.form.get("l2tp_enabled") == "1"
    ss_enabled = request.form.get("ss_enabled") == "1"
    hy_enabled = request.form.get("hy_enabled") == "1"
    vless_enabled = request.form.get("vless_enabled") == "1"
    vmess_enabled = request.form.get("vmess_enabled") == "1"
    http_enabled = request.form.get("http_enabled") == "1"
    mtg_enabled = request.form.get("mtg_enabled") == "1" or request.form.get("mtp") == "1"
    if not USER_RE.match(name):
        flash_t("user_bad")
        return redirect(url_for("users_page"))
    with _lock:
        users = load_users()
        if name not in users:
            flash_t("user_missing")
            return redirect(url_for("users_page"))
        if password:
            if not vpn_password_ok(password):
                flash_t("vpn_pass_bad")
                return redirect(url_for("users_page"))
            users[name]["password"] = password
        if expires:
            try:
                date.fromisoformat(expires)
            except ValueError:
                flash_t("expires_bad")
                return redirect(url_for("users_page"))
        users[name]["expires"] = expires
        if quota != "":
            try:
                q = float(quota)
                if not math.isfinite(q) or q < 0:
                    raise ValueError()
                users[name]["quota_gb"] = q
            except ValueError:
                flash_t("quota_invalid")
                return redirect(url_for("users_page"))
        if reset:
            users[name]["used_bytes"] = 0
        users[name]["ikev2_enabled"] = ikev2_enabled
        users[name]["l2tp_enabled"] = l2tp_enabled
        users[name]["ss_enabled"] = ss_enabled
        users[name]["hy_enabled"] = hy_enabled
        users[name]["vless_enabled"] = vless_enabled
        users[name]["vmess_enabled"] = vmess_enabled
        users[name]["http_enabled"] = http_enabled
        users[name]["mtg_enabled"] = mtg_enabled
        if ss_enabled and not users[name].get("ss_key"):
            users[name]["ss_key"] = new_ss_key()
        if ss_enabled and not users[name].get("ss_port"):
            users[name]["ss_port"] = allocate_ss_port()
        if vless_enabled and not users[name].get("vless_uuid"):
            users[name]["vless_uuid"] = new_vless_uuid()
        if vmess_enabled and not users[name].get("vmess_uuid"):
            users[name]["vmess_uuid"] = new_vmess_uuid()
        save_users(users)
        sync_accounts(users)
    flash_t("user_saved", name=name)
    return redirect(url_for("users_page"))


@app.route("/users/delete", methods=["POST"])
@login_required
@csrf_required
def users_delete():
    name = (request.form.get("name") or "").strip()
    if not USER_RE.match(name):
        flash_t("user_bad")
        return redirect(url_for("users_page"))
    with _lock:
        users = load_users()
        if name not in users:
            flash("کاربر پیدا نشد.")
            return redirect(url_for("users_page"))
        users.pop(name)
        remember_deleted_user(name)
        save_users(users)
        sync_accounts(users)
    flash_t("user_deleted", name=name)
    return redirect(url_for("users_page"))


@app.route("/sessions/cleanup", methods=["POST"])
@login_required
@csrf_required
def sessions_cleanup():
    terminated = cleanup_excess_sessions()
    if terminated:
        flash_t("old_marked", n=fa(len(terminated)) if current_lang()=="fa" else len(terminated))
    else:
        flash_t("no_extra_sess")
    return redirect(url_for("sessions_page"))


@app.route("/sessions/delete", methods=["POST"])
@login_required
@csrf_required
def sessions_delete():
    session_id = (request.form.get("id") or "").strip()
    if not session_id.isdigit():
        flash_t("sess_id_bad")
        return redirect(url_for("sessions_page"))
    selected = next(
        (
            item
            for item in parse_sessions()
            if item.get("proto") == "IKEv2" and str(item.get("id")) == session_id
        ),
        None,
    )
    if not selected:
        flash_t("sess_missing")
        return redirect(url_for("sessions_page"))
    terminate_ike_session(selected)
    flash_t("sess_marked", id=fa(session_id) if current_lang()=="fa" else session_id)
    return redirect(url_for("sessions_page"))


@app.route("/settings/domain", methods=["POST"])
@login_required
@csrf_required
def settings_domain():
    domain = (request.form.get("domain") or "").strip().lower()
    if not DOMAIN_RE.match(domain):
        flash_t("domain_bad")
        return redirect(url_for("settings"))
    try:
        process = subprocess.run([
            "systemd-run", "--unit=multivpn-domain", "--collect", "--property=Type=exec",
            "--setenv=IKEGUI_COLLECTOR=0", "--setenv=IKEGUI_APP=" + str(APP_DIR),
            "--setenv=IKEGUI_CFG=" + str(CFG_DIR), "--setenv=IKEGUI_DATA=" + str(DATA_DIR),
            "/usr/bin/python3", str(APP_DIR / "domain_worker.py"), domain,
        ], capture_output=True, text=True, timeout=10)
        if process.returncode != 0:
            raise OSError("Domain operation could not start or is already running")
        flash("Certificate update started. Check Settings for its result.")
    except (OSError, subprocess.SubprocessError) as error:
        flash(_public_flash_detail(str(error)))
    return redirect(url_for("settings"))


@app.route("/settings/psk", methods=["POST"])
@login_required
@csrf_required
def settings_psk():
    psk = (request.form.get("psk") or "").strip()
    if not safe_secret(psk, 16, 128):
        flash_t("psk_bad")
        return redirect(url_for("settings"))
    with _lock:
        cfg = load_config()
        cfg["psk"] = psk
        save_config(cfg)
        write_secrets(load_users(), psk=psk)
    flash_t("psk_ok")
    return redirect(url_for("settings"))


@app.route("/settings/dns", methods=["POST"])
@login_required
@csrf_required
def settings_dns():
    raw = (request.form.get("dns") or "").strip()
    parts = [p.strip() for p in re.split(r"[, ]+", raw) if p.strip()]
    if not parts or len(parts) > 4:
        flash_t("dns_count")
        return redirect(url_for("settings"))
    try:
        parts = [str(ipaddress.ip_address(p)) for p in parts]
    except ValueError:
        flash_t("dns_bad")
        return redirect(url_for("settings"))
    cfg = load_config()
    cfg["dns"] = parts
    save_config(cfg)
    apply_tunnel_dns(parts)
    flash_t("dns_ok")
    return redirect(url_for("settings"))


@app.route("/settings/admin", methods=["POST"])
@login_required
@csrf_required
@state_transaction
def settings_admin():
    pw = (request.form.get("password") or "").strip()
    if len(pw) < 12 or len(pw) > 128:
        flash_t("admin_len")
        return redirect(url_for("settings"))
    data = load_admin()
    data["password"] = generate_password_hash(pw)
    data["auth_version"] = int(data.get("auth_version", 0)) + 1
    save_admin(data)
    session.clear()
    flash_t("admin_ok")
    return redirect(url_for("settings"))



@app.route("/settings/totp/start", methods=["POST"])
@login_required
@csrf_required
def settings_totp_start():
    admin = load_admin()
    if admin.get("totp_enabled") and admin.get("totp_secret"):
        return redirect(url_for("settings"))
    session["totp_pending"] = totp_new_secret()
    return redirect(url_for("settings"))


@app.route("/settings/totp/confirm", methods=["POST"])
@login_required
@csrf_required
@state_transaction
def settings_totp_confirm():
    pending = session.get("totp_pending") or ""
    if not pending:
        return redirect(url_for("settings"))
    if not totp_ok(pending, request.form.get("totp") or ""):
        flash_t("totp_bad")
        return redirect(url_for("settings"))
    data = load_admin()
    data["totp_secret"] = pending
    data["auth_version"] = int(data.get("auth_version", 0)) + 1
    data["totp_enabled"] = True
    save_admin(data)
    session.pop("totp_pending", None)
    flash_t("totp_ok")
    return redirect(url_for("settings"))


@app.route("/settings/totp/off", methods=["POST"])
@login_required
@csrf_required
@state_transaction
def settings_totp_off():
    data = load_admin()
    secret = data.get("totp_secret") or ""
    if not totp_ok(secret, request.form.get("totp") or ""):
        flash_t("totp_bad")
        return redirect(url_for("settings"))
    data["totp_enabled"] = False
    data["totp_secret"] = ""
    data["auth_version"] = int(data.get("auth_version", 0)) + 1
    save_admin(data)
    session.pop("totp_pending", None)
    flash_t("totp_disabled")
    return redirect(url_for("settings"))


@app.route("/settings/profile", methods=["POST"])
@login_required
@csrf_required
@state_transaction
def settings_profile():
    display_name = (request.form.get("display_name") or "").strip()[:64]
    contact = (request.form.get("contact") or "").strip()[:128]
    data = load_admin()
    data["display_name"] = display_name
    data["contact"] = contact
    save_admin(data)
    flash_t("profile_ok")
    return redirect(url_for("settings"))


@app.route("/settings/sessions", methods=["POST"])
@login_required
@csrf_required
def settings_sessions():
    raw = (request.form.get("max_sessions_per_user") or "").strip()
    try:
        limit = int(raw)
        if not 1 <= limit <= 10:
            raise ValueError()
    except ValueError:
        flash_t("sess_limit_bad")
        return redirect(url_for("settings"))
    with _lock:
        cfg = load_config()
        cfg["max_sessions_per_user"] = limit
        save_config(cfg)
        terminated = cleanup_excess_sessions()
    if terminated:
        flash_t("sess_limit_cut", n=fa(len(terminated)) if current_lang()=="fa" else len(terminated))
    else:
        flash_t("sess_limit_ok")
    return redirect(url_for("settings"))



@app.route("/settings/ai", methods=["POST"])
@login_required
@csrf_required
def settings_ai():
    base = (request.form.get("ai_base") or "").strip()
    model = (request.form.get("ai_model") or "").strip()[:128]
    new_key = (request.form.get("ai_api_key") or "").strip()
    clear = (request.form.get("ai_api_key_clear") or "") in ("1", "on")
    if not _ai_base_ok(base):
        flash_t("ai_base_bad")
        return redirect(url_for("settings"))
    with _lock:
        cfg = load_config()
        cfg["ai_base"] = base
        cfg["ai_model"] = model
        if clear:
            cfg["ai_api_key"] = ""
        elif new_key:
            cfg["ai_api_key"] = new_key
        save_config(cfg)
    flash_t("ai_ok")
    return redirect(url_for("settings"))


@app.route("/settings/telegram", methods=["POST"])
@login_required
@csrf_required
def settings_telegram():
    token = (request.form.get("telegram_bot_token") or "").strip()
    ids_raw = (request.form.get("telegram_admin_ids") or "").strip()
    if token and not re.fullmatch(r"\d+:[A-Za-z0-9_-]{30,50}", token):
        flash_t("tg_token_bad")
        return redirect(url_for("settings"))
    admin_ids = []
    for part in re.split(r"[,\s]+", ids_raw):
        if not part:
            continue
        if not part.isdigit():
            flash_t("tg_id_bad", part=part)
            return redirect(url_for("settings"))
        admin_ids.append(int(part))
    if token and not admin_ids:
        flash_t("tg_need_admin")
        return redirect(url_for("settings"))
    with _lock:
        cfg = load_config()
        cfg["telegram_bot_token"] = token
        cfg["telegram_admin_ids"] = admin_ids
        save_config(cfg)
    if token:
        run(["systemctl", "enable", "--now", "panel-telegram-bot"], timeout=15)
        flash_t("tg_ok")
    else:
        run(["systemctl", "disable", "--now", "panel-telegram-bot"], timeout=15)
        flash_t("tg_off")
    return redirect(url_for("settings"))


def update_status():
    if not (REPO_DIR / ".git").is_dir():
        return None
    run(["git", "-C", str(REPO_DIR), "fetch", "origin", REPO_BRANCH], timeout=20)
    cur = run(["git", "-C", str(REPO_DIR), "log", "-1", "--format=%h %ad", "--date=short", "HEAD"], timeout=10).strip()
    latest = run(
        ["git", "-C", str(REPO_DIR), "log", "-1", "--format=%h %ad", "--date=short", "origin/%s" % REPO_BRANCH], timeout=10
    ).strip()
    behind_raw = run(
        ["git", "-C", str(REPO_DIR), "rev-list", "--count", "HEAD..origin/%s" % REPO_BRANCH], timeout=10
    ).strip()
    try:
        behind = int(behind_raw)
    except ValueError:
        behind = None
    return {"current": cur, "latest": latest, "behind": behind}


def _public_flash_detail(text, limit=180):
    text = re.sub(r"https?://\S+", "[url]", text or "")
    text = re.sub(
        r"(?i)(token|key|secret|password|bearer|authorization)\s*[=:]\s*\S+",
        r"\1=[redacted]",
        text,
    )
    text = re.sub(r"[^\w\s.:,()/%+-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[-limit:] if text else ""


def apply_update():
    deploy_script = REPO_DIR / "scripts" / "deploy.sh"
    if not deploy_script.is_file():
        return False, "Update source not found."
    try:
        process = subprocess.run(["bash", str(deploy_script), REPO_BRANCH],
                                 capture_output=True, text=True, timeout=10)
        output = (process.stdout or "") + (process.stderr or "")
        return process.returncode == 0 and "panel update queued" in output, output
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)



def read_unit_log(unit, lines=200):
    if unit not in LOG_UNITS:
        return ""
    try:
        n = max(1, min(int(lines), 500))
    except (TypeError, ValueError):
        n = 200
    try:
        proc = subprocess.run(
            ["journalctl", "-u", unit, "-n", str(n), "--no-pager", "--output=short-iso"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return out[-80000:]
    except Exception as e:
        return str(e)


def _backup_ok_name(name):
    name = (name or "").replace("\\", "/").lstrip("/")
    if not name or ".." in name.split("/"):
        return False
    base = Path(name).name
    if base in ("users.json", "config.json", "traffic-snap.json"):
        return True
    return bool(re.fullmatch(r"traffic[-_][A-Za-z0-9._-]+\.json", base))


@app.route("/settings/theme", methods=["POST"])
@csrf_required
def settings_theme():
    theme = (request.form.get("theme") or "").strip()
    if theme not in ("dark", "light"):
        theme = "light" if current_theme() == "dark" else "dark"
    if session.get("ok"):
        with _lock:
            cfg = load_config()
            cfg["theme"] = theme
            save_config(cfg)
    fallback = url_for("index") if session.get("ok") else url_for("login")
    resp = _same_host_redirect(fallback)
    return set_ui_cookies(resp, theme=theme)


@app.route("/settings/lang", methods=["POST"])
@csrf_required
def settings_lang():
    lang = (request.form.get("lang") or "").strip()
    if lang not in ("fa", "en"):
        lang = "en" if current_lang() == "fa" else "fa"
    if session.get("ok"):
        with _lock:
            cfg = load_config()
            cfg["lang"] = lang
            save_config(cfg)
    fallback = url_for("index") if session.get("ok") else url_for("login")
    resp = _same_host_redirect(fallback)
    return set_ui_cookies(resp, lang=lang)


@app.route("/settings/restart", methods=["POST"])
@login_required
@csrf_required
def settings_restart():
    def later():
        time.sleep(1)
        run(["systemctl", "restart", "ikev2-l2tp-gui"], timeout=30)

    threading.Thread(target=later, daemon=True).start()
    flash_t("restart_ok")
    return _same_host_redirect(url_for("settings"))


@app.route("/logs")
@login_required
def logs_page():
    d = page_chrome("logs", "logs_title", "logs_sub")
    d["log_blocks"] = [{"unit": unit, "text": read_unit_log(unit)} for unit in LOG_UNITS]
    return render_template("logs.html", **d)


@app.route("/settings/backup")
@login_required
def settings_backup():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        if USERS_FILE.is_file():
            z.write(USERS_FILE, arcname="users.json")
        seen = {"users.json"}
        if DATA_DIR.is_dir():
            for path in sorted(DATA_DIR.glob("traffic*.json")):
                if path.name in seen:
                    continue
                z.write(path, arcname=path.name)
                seen.add(path.name)
        if CONFIG_FILE.is_file():
            z.write(CONFIG_FILE, arcname="config.json")
    buf.seek(0)
    stamp = now_tehran().strftime("%Y%m%d")
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name="nh-multivpn-backup-%s.zip" % stamp,
    )


def validate_restored_user(name, u):
    if not USER_RE.fullmatch(name) or not isinstance(u, dict):
        raise ValueError("user")
    for field in ("quota_gb", "used_bytes"):
        value = float(u.get(field) or 0)
        if not math.isfinite(value) or value < 0:
            raise ValueError(field)
    for field in ("ss_port", "http_port"):
        if u.get(field) and not 1 <= int(u[field]) <= 65535:
            raise ValueError(field)
    if u.get("expires"):
        date.fromisoformat(u["expires"])
    for field in ("enabled", "ikev2_enabled", "l2tp_enabled", "ss_enabled",
                  "hy_enabled", "vless_enabled", "vmess_enabled", "http_enabled", "mtg_enabled"):
        if field in u and not isinstance(u[field], bool):
            raise ValueError(field)
    if u.get("password") and (not isinstance(u["password"], str) or not vpn_password_ok(u["password"])):
        raise ValueError("password")
    for field in ("vless_uuid", "vmess_uuid"):
        if u.get(field):
            uuid.UUID(u[field])


def validate_restored_config(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("config")
    domain = cfg.get("domain") or ""
    if domain and (not isinstance(domain, str) or not DOMAIN_RE.fullmatch(domain)):
        raise ValueError("domain")
    if domain != (load_config().get("domain") or ""):
        raise ValueError("Change domain through Settings before restoring this backup")
    if cfg.get("psk") and not safe_secret(cfg["psk"], 16, 128):
        raise ValueError("psk")
    for field in ("http_port", "hy_port", "mtg_port", "vless_port", "vmess_port", "ss_next_port"):
        if cfg.get(field) is not None and not 1 <= int(cfg[field]) <= 65535:
            raise ValueError(field)
    if not 1 <= int(cfg.get("max_sessions_per_user", 1)) <= 10:
        raise ValueError("sessions")
    dns = cfg.get("dns", [])
    if not isinstance(dns, list) or len(dns) > 2:
        raise ValueError("dns")
    for value in dns:
        ipaddress.ip_address(value)
    for field in ("reality_server_names",):
        if field in cfg and (not isinstance(cfg[field], list) or
                             any(not DOMAIN_RE.fullmatch(value) for value in cfg[field])):
            raise ValueError(field)


@app.route("/settings/restore", methods=["POST"])
@login_required
@csrf_required
def settings_restore():
    upload = request.files.get("backup")
    if not upload or not upload.filename:
        flash_t("backup_missing")
        return redirect(url_for("settings"))
    raw = upload.read()
    if len(raw) > 4 * 1024 * 1024:
        flash_t("backup_bad")
        return redirect(url_for("settings"))
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        flash_t("backup_bad")
        return redirect(url_for("settings"))
    names = zf.namelist()
    infos = zf.infolist()
    if not names or len(names) > 32 or any(not _backup_ok_name(n) for n in names):
        flash_t("backup_bad")
        return redirect(url_for("settings"))
    total_unc = 0
    for info in infos:
        if info.file_size > 2 * 1024 * 1024:
            flash_t("backup_bad")
            return redirect(url_for("settings"))
        total_unc += max(0, int(info.file_size or 0))
        if total_unc > 4 * 1024 * 1024:
            flash_t("backup_bad")
            return redirect(url_for("settings"))
    extracted = {}
    try:
        for n in names:
            base = Path(n.replace("\\", "/")).name
            data = zf.read(n)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError("size")
            extracted[base] = data
        if "users.json" in extracted:
            users = json.loads(extracted["users.json"].decode("utf-8"))
            if not isinstance(users, dict):
                raise ValueError("users")
            for k, v in users.items():
                validate_restored_user(k, v)
        if "config.json" in extracted:
            cfg = json.loads(extracted["config.json"].decode("utf-8"))
            validate_restored_config(cfg)
            if cfg.get("ai_base") and not _ai_base_ok(str(cfg.get("ai_base") or "")):
                cfg["ai_base"] = ""
                extracted["config.json"] = (json.dumps(cfg, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, TypeError, AttributeError):
        flash_t("backup_bad")
        return redirect(url_for("settings"))
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CFG_DIR.mkdir(parents=True, exist_ok=True)
        if "users.json" in extracted:
            USERS_FILE.write_bytes(extracted["users.json"])
            os.chmod(USERS_FILE, 0o600)
        for base, data in extracted.items():
            if base in ("users.json", "config.json"):
                continue
            dest = DATA_DIR / base
            dest.write_bytes(data)
            os.chmod(dest, 0o600)
        if "config.json" in extracted:
            CONFIG_FILE.write_bytes(extracted["config.json"])
            os.chmod(CONFIG_FILE, 0o600)
        apply_tunnel_dns(load_config().get("dns") or [])
        sync_accounts()
    flash_t("backup_ok")
    return redirect(url_for("settings"))


@app.route("/settings/update/apply", methods=["POST"])
@login_required
@csrf_required
def settings_update_apply():
    ok, out = apply_update()
    if ok:
        flash("Update started. Wait for the panel to reconnect, then check Settings.")
    else:
        flash_t("upd_fail", out=_public_flash_detail(out))
    return redirect(url_for("settings"))


def collector_loop():
    while True:
        try:
            sample_traffic()
        except Exception:
            app.logger.exception("Traffic collection failed")
        time.sleep(20)


def start_background():
    if getattr(app, "_collector", False):
        return
    app._collector = True
    t = threading.Thread(target=initialize_collector, daemon=True)
    t.start()


def initialize_collector():
    # Bootstrap installations whose old updater copied only application files.
    # The detached worker completes provisioning without dying on web restart.
    version_file = DATA_DIR / "deployment-version"
    version = version_file.read_text().strip() if version_file.exists() else ""
    job = load_json(DATA_DIR / "update-status.json", {})
    if version != "2" and job.get("state") not in ("running", "failed"):
        # Stop an old bot's independent collector during first migration.
        run(["systemctl", "stop", "panel-telegram-bot"], timeout=15)
        apply_update()
    try:
        sync_accounts()
        domain = load_config().get("domain") or ""
        if DOMAIN_RE.fullmatch(domain):
            _write_certbot_hook(domain)
    except Exception:
        app.logger.exception("Account reconciliation failed")
    collector_loop()


if ADMIN_FILE.exists():
    load_admin()
if os.environ.get("IKEGUI_COLLECTOR", "1") == "1":
    start_background()

if __name__ == "__main__":
    load_admin()
    app.run(host="127.0.0.1", port=8765)


