#!/usr/bin/env python3
"""Telegram admin bot for the multi-VPN panel.

Reuses panel/app.py's user-management functions directly so behavior stays
identical to the web panel (same validation, same config writers). Admin-only:
every update is checked against config.json's telegram_admin_ids before any
command runs.
"""
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["IKEGUI_COLLECTOR"] = "0"
import app as panel  # noqa: E402

API_BASE = ""
# Per-chat in-progress "add user" flow. Lost on restart — acceptable for an
# admin operational tool; the admin just restarts the flow with /add.
FLOWS = {}
TOGGLE_FIELDS = {
    "ss",
    "hy",
    "vless",
    "vmess",
    "http",
    "mtg",
    "ikev2",
    "l2tp",
    "enabled",
}
SMART_OS = {"android", "ios", "windows", "mac", "linux", "telegram"}
SMART_UDP = {"ok", "blocked", "unknown"}


def api_call(method, **params):
    url = "%s/%s" % (API_BASE, method)
    data = json.dumps(params).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send(chat_id, text, reply_markup=None, message_id=None):
    params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup is not None:
        params["reply_markup"] = reply_markup
    try:
        if message_id:
            params["message_id"] = message_id
            return api_call("editMessageText", **params)
        return api_call("sendMessage", **params)
    except urllib.error.HTTPError:
        params.pop("message_id", None)
        return api_call("sendMessage", **params)
    except (urllib.error.URLError, OSError):
        return None


def answer_callback(callback_id, text=""):
    try:
        api_call("answerCallbackQuery", callback_query_id=callback_id, text=text)
    except (urllib.error.URLError, OSError):
        pass


def hx(value):
    return html.escape(str(value or ""), quote=True)


def is_admin(user_id):
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        return False
    ids = panel.load_config().get("telegram_admin_ids") or []
    allowed = set()
    for i in ids:
        try:
            allowed.add(int(i))
        except (TypeError, ValueError):
            continue
    return uid in allowed


def kb(rows):
    return {"inline_keyboard": rows}


def status_emoji(u):
    block = panel.user_blocked(u)
    if block:
        return "🔴"
    return "🟢"


def main_menu():
    return kb(
        [
            [{"text": "👥 کاربران", "callback_data": "users:0"}],
            [{"text": "➕ افزودن کاربر", "callback_data": "add:start"}],
            [{"text": "⚡ اتصال هوشمند", "callback_data": "smart"}],
            [{"text": "📊 وضعیت سرور", "callback_data": "status"}],
        ]
    )


def fmt_status():
    hs = panel.host_stats()
    sessions = panel.parse_sessions()
    online = len({s["user"] for s in sessions if s.get("user")})
    users = panel.load_users()
    return (
        "📊 <b>وضعیت سرور</b>\n"
        "کاربران: %d (آنلاین: %d)\n"
        "CPU: %.1f%%  |  RAM: %.1f%%  |  دیسک: %.1f%%\n"
        "Load: %.2f"
        % (
            len(users),
            online,
            hs["cpu"],
            hs["mem_pct"],
            hs["disk_pct"],
            hs["load1"],
        )
    )


def users_page(page=0, per_page=8):
    users = panel.load_users()
    names = sorted(users.keys())
    total = len(names)
    start = page * per_page
    chunk = names[start : start + per_page]
    rows = []
    for name in chunk:
        u = users[name]
        rows.append([{"text": "%s %s" % (status_emoji(u), name), "callback_data": "user:%s" % name}])
    nav = []
    if page > 0:
        nav.append({"text": "◀ قبلی", "callback_data": "users:%d" % (page - 1)})
    if start + per_page < total:
        nav.append({"text": "بعدی ▶", "callback_data": "users:%d" % (page + 1)})
    if nav:
        rows.append(nav)
    rows.append([{"text": "🔙 منو", "callback_data": "menu"}])
    text = "👥 <b>کاربران</b> (%d نفر)" % total
    return text, kb(rows)



def fmt_user_detail(name, u):
    block = panel.user_blocked(u)
    status = ("مسدود: " + block) if block else "فعال"
    q = float(u.get("quota_gb") or 0)
    used = float(u.get("used_bytes") or 0)
    quota_h = "نامحدود" if q <= 0 else "%.1f GB" % q

    def on(key, default=False):
        if key in ("ikev2_enabled", "l2tp_enabled"):
            return panel.flag_on(u, key, True)
        return bool(u.get(key))

    lines = [
        "👤 <b>%s</b>" % hx(name),
        "وضعیت: %s" % hx(status),
        "انقضا: %s" % hx(u.get("expires") or "نامحدود"),
        "مصرف: %s از %s" % (panel.human(used), quota_h),
        "IKEv2: %s" % ("فعال" if on("ikev2_enabled") else "غیرفعال"),
        "L2TP: %s" % ("فعال" if on("l2tp_enabled") else "غیرفعال"),
        "Shadowsocks: %s" % ("فعال (پورت %s)" % u.get("ss_port") if u.get("ss_enabled") else "غیرفعال"),
        "Hysteria2: %s" % ("فعال" if u.get("hy_enabled") else "غیرفعال"),
        "VLESS: %s" % ("فعال" if u.get("vless_enabled") else "غیرفعال"),
        "VMess: %s" % ("فعال" if u.get("vmess_enabled") else "غیرفعال"),
        "HTTP: %s" % ("فعال" if u.get("http_enabled") else "غیرفعال"),
        "MTProto: %s" % ("فعال" if u.get("mtg_enabled") else "غیرفعال"),
    ]
    return "\n".join(lines)



def user_detail_kb(name, u):
    def lab(key, label, default=False):
        if key in ("ikev2_enabled", "l2tp_enabled"):
            on = panel.flag_on(u, key, True)
        else:
            on = bool(u.get(key)) if key != "enabled" else u.get("enabled", True)
        if key == "enabled":
            return "⛔ غیرفعال‌کردن" if on else "✅ فعال‌کردن"
        return ("🔴 خاموش‌کردن " if on else "🟢 روشن‌کردن ") + label

    return kb(
        [
            [{"text": "🔄 صفرکردن مصرف", "callback_data": "reset:%s" % name}],
            [
                {"text": lab("ikev2_enabled", "IKEv2"), "callback_data": "toggle:%s:ikev2" % name},
                {"text": lab("l2tp_enabled", "L2TP"), "callback_data": "toggle:%s:l2tp" % name},
            ],
            [
                {"text": lab("ss_enabled", "SS"), "callback_data": "toggle:%s:ss" % name},
                {"text": lab("hy_enabled", "Hysteria2"), "callback_data": "toggle:%s:hy" % name},
            ],
            [
                {"text": lab("vless_enabled", "VLESS"), "callback_data": "toggle:%s:vless" % name},
                {"text": lab("vmess_enabled", "VMess"), "callback_data": "toggle:%s:vmess" % name},
            ],
            [
                {"text": lab("http_enabled", "HTTP"), "callback_data": "toggle:%s:http" % name},
                {"text": lab("mtg_enabled", "MTProto"), "callback_data": "toggle:%s:mtg" % name},
            ],
            [{"text": lab("enabled", "", True), "callback_data": "toggle:%s:enabled" % name}],
            [{"text": "❌ حذف کاربر", "callback_data": "del:%s:ask" % name}],
            [{"text": "🔙 لیست کاربران", "callback_data": "users:0"}],
        ]
    )





def smart_users_kb():
    users = panel.load_users()
    names = sorted(users.keys())[:12]
    rows = [[{"text": n, "callback_data": "smartu:%s" % n}] for n in names]
    rows.append([{"text": "🔙 منو", "callback_data": "menu"}])
    return names, kb(rows)


def smart_os_kb(name):
    rows = [
        [
            {"text": "Android", "callback_data": "smarto:%s:android" % name},
            {"text": "iOS", "callback_data": "smarto:%s:ios" % name},
        ],
        [
            {"text": "Windows", "callback_data": "smarto:%s:windows" % name},
            {"text": "macOS", "callback_data": "smarto:%s:mac" % name},
        ],
        [
            {"text": "Linux", "callback_data": "smarto:%s:linux" % name},
            {"text": "Telegram", "callback_data": "smarto:%s:telegram" % name},
        ],
        [{"text": "🔙 منو", "callback_data": "menu"}],
    ]
    return kb(rows)


def smart_udp_kb(name, os_):
    return kb(
        [
            [
                {"text": "UDP باز", "callback_data": "smartq:%s:%s:ok" % (name, os_)},
                {"text": "UDP مسدود", "callback_data": "smartq:%s:%s:blocked" % (name, os_)},
            ],
            [{"text": "نمی‌دانم", "callback_data": "smartq:%s:%s:unknown" % (name, os_)}],
            [{"text": "🔙 منو", "callback_data": "menu"}],
        ]
    )


def handle_smart_pick(chat_id, message_id, name, os_, udp):
    users = panel.load_users()
    u = users.get(name)
    if not u:
        send(chat_id, "کاربر پیدا نشد.", main_menu(), message_id)
        return
    form = {"os": os_, "net": "mobile", "udp": udp, "path": "unknown", "native": False, "filter": "iran"}
    result = panel.rank_smart_connect(name, u, panel.load_config(), form, "fa")
    _text, _st, ai_ranked = panel.smart_ai_review(result, "fa")
    if ai_ranked:
        result["ranked"] = ai_ranked
    ranked = result.get("ranked") or []
    if not ranked:
        text = "برای %s با OS=%s UDP=%s پروتکل مناسبی نماند." % (hx(name), hx(os_), hx(udp))
        send(chat_id, text, main_menu(), message_id)
        return
    top = ranked[0]
    lines = [
        "⚡ <b>اتصال هوشمند</b> — %s" % hx(name),
        "شرایط: OS=%s  UDP=%s  فیلترینگ=ایران  (موجودی سرور، نه پروب ISP)" % (hx(os_), hx(udp)),
        "",
        "پیشنهاد: <b>%s</b> (امتیاز %s)" % (hx(top.get("label")), hx(top.get("score"))),
        hx(top.get("reason") or ""),
    ]
    if _st == "ok":
        lines.append("بازبینی مدل: انجام شد.")
    elif _st == "fail":
        lines.append("بازبینی مدل ناموفق؛ رتبهٔ قاعده‌ای.")
    if top.get("uri"):
        lines.append("URI:\n<code>%s</code>" % hx(top["uri"]))
    elif top.get("endpoint"):
        lines.append("میزبان / کاربر: <code>%s</code>" % hx(top["endpoint"]))
    send(chat_id, "\n".join(lines), main_menu(), message_id)


def apply_user_change(name, users):
    with panel._lock:
        panel.save_users(users)
        panel.sync_accounts(users)


def handle_users(chat_id, message_id, page):
    text, markup = users_page(page)
    send(chat_id, text, markup, message_id)


def handle_user_detail(chat_id, message_id, name):
    users = panel.load_users()
    u = users.get(name)
    if not u:
        send(chat_id, "کاربر پیدا نشد.", main_menu(), message_id)
        return
    send(chat_id, fmt_user_detail(name, u), user_detail_kb(name, u), message_id)



def handle_toggle(chat_id, message_id, name, field):
    with panel._lock:
        users = panel.load_users()
        u = users.get(name)
        if not u:
            send(chat_id, "کاربر پیدا نشد.", main_menu(), message_id)
            return
        if field not in TOGGLE_FIELDS:
            send(chat_id, "فیلد نامعتبر.", main_menu(), message_id)
            return
        if field == "ss":
            u["ss_enabled"] = not u.get("ss_enabled")
            if u["ss_enabled"] and not u.get("ss_key"):
                u["ss_key"] = panel.new_ss_key()
            if u["ss_enabled"] and not u.get("ss_port"):
                u["ss_port"] = panel.allocate_ss_port()
        elif field == "hy":
            u["hy_enabled"] = not u.get("hy_enabled")
        elif field == "vless":
            u["vless_enabled"] = not u.get("vless_enabled")
            if u["vless_enabled"] and not u.get("vless_uuid"):
                u["vless_uuid"] = panel.new_vless_uuid()
        elif field == "vmess":
            u["vmess_enabled"] = not u.get("vmess_enabled")
            if u["vmess_enabled"] and not u.get("vmess_uuid"):
                u["vmess_uuid"] = panel.new_vmess_uuid()
        elif field == "http":
            u["http_enabled"] = not u.get("http_enabled")
        elif field == "mtg":
            u["mtg_enabled"] = not u.get("mtg_enabled")
        elif field == "ikev2":
            u["ikev2_enabled"] = not panel.flag_on(u, "ikev2_enabled", True)
        elif field == "l2tp":
            u["l2tp_enabled"] = not panel.flag_on(u, "l2tp_enabled", True)
        elif field == "enabled":
            u["enabled"] = not u.get("enabled", True)
        apply_user_change(name, users)
    send(chat_id, fmt_user_detail(name, u), user_detail_kb(name, u), message_id)


def handle_reset(chat_id, message_id, name):
    with panel._lock:
        users = panel.load_users()
        u = users.get(name)
        if not u:
            send(chat_id, "کاربر پیدا نشد.", main_menu(), message_id)
            return
        u["used_bytes"] = 0
        apply_user_change(name, users)
    send(chat_id, "مصرف %s صفر شد.\n\n" % hx(name) + fmt_user_detail(name, u), user_detail_kb(name, u), message_id)


def handle_delete_ask(chat_id, message_id, name):
    send(
        chat_id,
        "❗ حذف کاربر <b>%s</b> برگشت‌ناپذیر است. مطمئنید؟" % hx(name),
        kb(
            [
                [{"text": "بله، حذف شود", "callback_data": "del:%s:confirm" % name}],
                [{"text": "انصراف", "callback_data": "user:%s" % name}],
            ]
        ),
        message_id,
    )


def handle_delete_confirm(chat_id, message_id, name):
    with panel._lock:
        users = panel.load_users()
        if name in users:
            users.pop(name)
            panel.save_users(users)
            panel.sync_accounts(users)
    text, markup = users_page(0)
    send(chat_id, "کاربر %s حذف شد.\n\n%s" % (hx(name), text), markup, message_id)


def start_add_flow(chat_id, message_id):
    FLOWS[chat_id] = {"step": "name", "data": {}}
    send(chat_id, "نام کاربری جدید را بفرستید (فقط حروف/عدد انگلیسی، ۲ تا ۳۲ نویسه):", None, message_id)


def continue_add_flow(chat_id, text):
    flow = FLOWS.get(chat_id)
    if not flow:
        return False
    step = flow["step"]
    data = flow["data"]
    if step == "name":
        name = text.strip()
        if not panel.USER_RE.match(name):
            send(chat_id, "نام نامعتبر است، دوباره بفرستید.")
            return True
        if name in panel.load_users():
            send(chat_id, "این کاربر از قبل وجود دارد. نام دیگری بفرستید.")
            return True
        data["name"] = name
        flow["step"] = "password"
        send(chat_id, "هر رمزی می‌خواهید بفرستید (۱ تا ۱۲۸ نویسه؛ \" و خط جدید ممنوع) یا - برای ساخت خودکار")
        return True
    if step == "password":
        pw = text.strip()
        if pw == "-":
            import secrets as _secrets

            pw = _secrets.token_urlsafe(12)[:16]
        if not panel.vpn_password_ok(pw):
            send(chat_id, "رمز نامعتبر است. هر رمزی می‌خواهید بفرستید (۱ تا ۱۲۸ نویسه؛ \" و خط جدید ممنوع) یا - برای ساخت خودکار")
            return True
        data["password"] = pw
        flow["step"] = "quota"
        send(chat_id, "سهمیه به گیگابایت را بفرستید (۰ یعنی نامحدود):")
        return True
    if step == "quota":
        try:
            q = float(text.strip())
            if q < 0:
                raise ValueError()
        except ValueError:
            send(chat_id, "عدد نامعتبر است. سهمیه به گیگابایت را بفرستید (۰ یعنی نامحدود):")
            return True
        data["quota_gb"] = q
        data["protocols"] = {"ikev2", "l2tp"}
        flow["step"] = "protocols"
        send(chat_id, protocols_pick_text(), protocols_pick_kb(data["protocols"]))
        return True
    return True


PROTO_LABELS = {
    "ikev2": "IKEv2",
    "l2tp": "L2TP",
    "ss": "Shadowsocks",
    "hy": "Hysteria2",
    "vless": "VLESS",
    "vmess": "VMess",
    "http": "HTTP",
    "mtg": "MTProto",
}


def protocols_pick_text():
    return "پروتکل‌های این کاربر را انتخاب کنید (پیش‌فرض: IKEv2 و L2TP) و بعد تأیید کنید:"


def protocols_pick_kb(selected):
    rows = []
    items = list(PROTO_LABELS.items())
    for i in range(0, len(items), 2):
        row = []
        for key, label in items[i : i + 2]:
            mark = "✅" if key in selected else "◻️"
            row.append({"text": "%s %s" % (mark, label), "callback_data": "addtoggle:%s" % key})
        rows.append(row)
    rows.append([{"text": "✔️ تأیید و ساخت کاربر", "callback_data": "addconfirm"}])
    return kb(rows)


def handle_addtoggle(chat_id, message_id, key):
    flow = FLOWS.get(chat_id)
    if not flow or flow.get("step") != "protocols":
        return
    selected = flow["data"]["protocols"]
    if key in selected:
        selected.discard(key)
    else:
        selected.add(key)
    send(chat_id, protocols_pick_text(), protocols_pick_kb(selected), message_id)



def finish_add_flow(chat_id, message_id):
    flow = FLOWS.pop(chat_id, None)
    if not flow:
        return
    data = flow["data"]
    name = data["name"]
    selected = data.get("protocols") or set()
    ikev2_enabled = "ikev2" in selected
    l2tp_enabled = "l2tp" in selected
    ss_enabled = "ss" in selected
    hy_enabled = "hy" in selected
    vless_enabled = "vless" in selected
    vmess_enabled = "vmess" in selected
    http_enabled = "http" in selected
    mtg_enabled = "mtg" in selected
    with panel._lock:
        users = panel.load_users()
        if name in users:
            send(chat_id, "این کاربر همین حین توسط جای دیگه‌ای ساخته شد.", main_menu(), message_id)
            return
        users[name] = {
            "password": data["password"],
            "expires": "",
            "quota_gb": data["quota_gb"],
            "used_bytes": 0,
            "created": panel.today_iso(),
            "enabled": True,
            "ikev2_enabled": ikev2_enabled,
            "l2tp_enabled": l2tp_enabled,
            "ss_enabled": ss_enabled,
            "hy_enabled": hy_enabled,
            "vless_enabled": vless_enabled,
            "vmess_enabled": vmess_enabled,
            "http_enabled": http_enabled,
            "mtg_enabled": mtg_enabled,
            "ss_key": panel.new_ss_key() if ss_enabled else "",
            "ss_port": panel.allocate_ss_port() if ss_enabled else None,
            "vless_uuid": panel.new_vless_uuid() if vless_enabled else "",
            "vmess_uuid": panel.new_vmess_uuid() if vmess_enabled else "",
            "sub_token": panel.new_sub_token(),
        }
        panel.save_users(users)
        panel.sync_accounts(users)
    send(
        chat_id,
        "✅ کاربر ساخته شد.\n\nنام: <code>%s</code>\nرمز: <code>%s</code>\n\n%s"
        % (hx(name), hx(data["password"]), fmt_user_detail(name, users[name])),
        user_detail_kb(name, users[name]),
        message_id,
    )


def process_message(msg):
    chat_id = msg["chat"]["id"]
    user_id = msg.get("from", {}).get("id")
    if not is_admin(user_id):
        return
    text = (msg.get("text") or "").strip()
    if chat_id in FLOWS and text and not text.startswith("/"):
        continue_add_flow(chat_id, text)
        return
    if text in ("/start", "/help"):
        send(chat_id, "🤖 پنل مدیریت VPN — از منو استفاده کنید.", main_menu())
    elif text == "/users":
        t, m = users_page(0)
        send(chat_id, t, m)
    elif text == "/add":
        start_add_flow(chat_id, None)
    elif text == "/status":
        send(chat_id, fmt_status(), main_menu())


def process_callback(cq):
    chat_id = cq["message"]["chat"]["id"]
    message_id = cq["message"]["message_id"]
    user_id = cq.get("from", {}).get("id")
    data = cq.get("data") or ""
    answer_callback(cq["id"])
    if not is_admin(user_id):
        return
    try:
        if data == "menu":
            send(chat_id, "🤖 پنل مدیریت VPN", main_menu(), message_id)
        elif data == "status":
            send(chat_id, fmt_status(), main_menu(), message_id)
        elif data == "smart":
            names, markup = smart_users_kb()
            if not names:
                send(chat_id, "ابتدا یک کاربر بسازید.", main_menu(), message_id)
            else:
                send(chat_id, "کاربر را برای اتصال هوشمند انتخاب کنید:", markup, message_id)
        elif data.startswith("smartu:"):
            name = data.split(":", 1)[1]
            if not panel.USER_RE.match(name):
                return
            send(chat_id, "سیستم‌عامل / کلاینت %s؟" % hx(name), smart_os_kb(name), message_id)
        elif data.startswith("smarto:"):
            _, name, os_ = data.split(":", 2)
            if not panel.USER_RE.match(name) or os_ not in SMART_OS:
                return
            send(chat_id, "وضعیت UDP برای %s؟" % hx(name), smart_udp_kb(name, os_), message_id)
        elif data.startswith("smartq:"):
            _, name, os_, udp = data.split(":", 3)
            if not panel.USER_RE.match(name) or os_ not in SMART_OS or udp not in SMART_UDP:
                return
            handle_smart_pick(chat_id, message_id, name, os_, udp)
        elif data.startswith("users:"):
            try:
                page = int(data.split(":", 1)[1])
            except ValueError:
                page = 0
            page = max(0, min(page, 10000))
            handle_users(chat_id, message_id, page)
        elif data.startswith("user:"):
            name = data.split(":", 1)[1]
            if not panel.USER_RE.match(name):
                return
            handle_user_detail(chat_id, message_id, name)
        elif data.startswith("toggle:"):
            _, name, field = data.split(":", 2)
            if not panel.USER_RE.match(name) or field not in TOGGLE_FIELDS:
                return
            handle_toggle(chat_id, message_id, name, field)
        elif data.startswith("reset:"):
            name = data.split(":", 1)[1]
            if not panel.USER_RE.match(name):
                return
            handle_reset(chat_id, message_id, name)
        elif data.startswith("del:"):
            _, name, action = data.split(":", 2)
            if not panel.USER_RE.match(name):
                return
            if action == "ask":
                handle_delete_ask(chat_id, message_id, name)
            elif action == "confirm":
                handle_delete_confirm(chat_id, message_id, name)
        elif data == "add:start":
            start_add_flow(chat_id, message_id)
        elif data.startswith("addtoggle:"):
            key = data.split(":", 1)[1]
            if key in PROTO_LABELS:
                handle_addtoggle(chat_id, message_id, key)
        elif data == "addconfirm":
            finish_add_flow(chat_id, message_id)
    except Exception:
        send(chat_id, "خطا در انجام عملیات.", main_menu())


def process_update(update):
    if "message" in update:
        process_message(update["message"])
    elif "callback_query" in update:
        process_callback(update["callback_query"])


def main():
    global API_BASE
    cfg = panel.load_config()
    token = cfg.get("telegram_bot_token") or ""
    if not token:
        print("no telegram_bot_token configured, exiting")
        return
    API_BASE = "https://api.telegram.org/bot%s" % token
    offset = 0
    while True:
        try:
            resp = api_call("getUpdates", offset=offset, timeout=30)
        except (urllib.error.URLError, OSError):
            time.sleep(3)
            continue
        for update in resp.get("result", []):
            offset = update["update_id"] + 1
            try:
                process_update(update)
            except Exception:
                time.sleep(1)


if __name__ == "__main__":
    main()
