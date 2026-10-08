#!/usr/bin/env python3
"""Flask e2e smoke: login, chrome pages, POSTs, corrupt users.json must not 500."""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"


def _hash(pw: str) -> str:
    from werkzeug.security import generate_password_hash

    return generate_password_hash(pw)


def _seed(cfg: Path, data: Path, users_payload) -> None:
    cfg.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)
    (cfg / "admin.json").write_text(
        json.dumps(
            {
                "user": "admin",
                "password": _hash("adminpass"),
                "secret": secrets.token_hex(32),
                "display_name": "Admin",
                "contact": "",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (cfg / "config.json").write_text(
        json.dumps(
            {
                "domain": "vpn.example.com",
                "public_ip": "203.0.113.10",
                "psk": "ExamplePskValue",
                "dns": ["9.9.9.9"],
                "interface": "eth0",
                "max_sessions_per_user": 1,
                "theme": "dark",
                "lang": "fa",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    payload = users_payload
    if not isinstance(payload, str):
        payload = json.dumps(payload, indent=2) + "\n"
    (data / "users.json").write_text(payload, encoding="utf-8")


def _import_app(app_dir: Path, cfg: Path, data: Path, sysdir: Path):
    os.environ["IKEGUI_COLLECTOR"] = "0"
    os.environ["IKEGUI_APP"] = str(app_dir)
    os.environ["IKEGUI_CFG"] = str(cfg)
    os.environ["IKEGUI_DATA"] = str(data)
    os.environ["IKEGUI_REPO"] = str(app_dir.parent / "repo")
    sys.path.insert(0, str(app_dir))
    # Fresh module each scenario.
    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            del sys.modules[name]
    import app as A

    sysdir.mkdir(parents=True, exist_ok=True)
    A.IPSEC_SECRETS = sysdir / "ipsec.secrets"
    A.CHAP_SECRETS = sysdir / "chap-secrets"
    A.IPSEC_CONF = sysdir / "ipsec.conf"
    A.PPP_OPTS = sysdir / "options.xl2tpd"
    A.XRAY_SS_CONFIG = sysdir / "xray.json"
    A.HYSTERIA_CONFIG = sysdir / "hy.yaml"
    A.MTG_CONFIG = sysdir / "mtg.toml"
    A.NGINX_SITE = sysdir / "nginx"
    A.PPP_ONLINE = sysdir / "ppp-online"
    A.PPP_ONLINE.mkdir(exist_ok=True)
    # Config and route tests must never invoke host VPN/systemd operations.
    A.run = lambda cmd, timeout=10: ""
    A.app.config["TESTING"] = True
    A.app.config["SESSION_COOKIE_SECURE"] = False
    A.load_admin()
    return A


def _client(A):
    c = A.app.test_client()
    c.environ_base["wsgi.url_scheme"] = "https"
    c.environ_base["HTTP_X_FORWARDED_PROTO"] = "https"
    return c


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not m:
        raise AssertionError("csrf token missing")
    return m.group(1)


def _login(c) -> str:
    html = c.get("/login").get_data(as_text=True)
    assert c.get("/login").status_code == 200
    csrf = _csrf(html)
    r = c.post(
        "/login",
        data={"user": "admin", "password": "adminpass", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.status_code
    return csrf


def _expect(c, method, path, expect=200, data=None):
    fn = c.get if method == "GET" else c.post
    kw = {}
    if data is not None:
        kw["data"] = data
    resp = fn(path, follow_redirects=False, **kw)
    if resp.status_code != expect:
        body = resp.get_data(as_text=True)
        i = body.find("Traceback")
        snip = body[i : i + 800] if i >= 0 else body[:400]
        raise AssertionError("%s %s -> %s want %s\n%s" % (method, path, resp.status_code, expect, snip))
    return resp


def scenario_happy(tmp: Path) -> None:
    app_dir = tmp / "app"
    cfg, data, sysdir = tmp / "cfg", tmp / "data", tmp / "sys"
    import shutil

    shutil.copytree(PANEL, app_dir, dirs_exist_ok=True)
    _seed(
        cfg,
        data,
        {
            "alice": {
                "password": "alicepass",
                "expires": "",
                "quota_gb": 0,
                "used_bytes": 0,
                "created": "2026-09-01",
                "ikev2_enabled": True,
                "l2tp_enabled": True,
                "ss_enabled": True,
                "ss_key": "AAAAAAAAAAAAAAAAAAAAAA==",
                "ss_port": 8388,
                "vless_enabled": True,
                "vless_uuid": "11111111-1111-1111-1111-111111111111",
                "vmess_enabled": True,
                "vmess_uuid": "22222222-2222-2222-2222-222222222222",
                "hy_enabled": True,
                "http_enabled": True,
                "mtg_enabled": True,
            }
        },
    )
    A = _import_app(app_dir, cfg, data, sysdir)
    from markupsafe import escape

    try:
        escape(A.I18NView(A.I18N["fa"]))
    except TypeError as e:
        raise AssertionError("I18NView is not MarkupSafe-safe: %s" % e) from e
    c = _client(A)
    _login(c)
    for path in ("/", "/users", "/sessions", "/clients", "/smart", "/settings", "/logs", "/api/status"):
        _expect(c, "GET", path, 200)
    home = c.get("/").get_data(as_text=True)
    if home.find("machine-strip") < 0 or home.find("speed-form") < 0:
        raise AssertionError("dashboard missing resources or speed test")
    if "recent_sessions" in home or "نشست‌های اخیر" in home:
        raise AssertionError("recent sessions still on dashboard home")
    grid = home.find("dashboard-grid")
    if grid >= 0 and home.find("machine-strip") > grid:
        raise AssertionError("resources not at top of dashboard")
    if "203.0.113.10" not in home:
        raise AssertionError("server IP missing on dashboard")
    for path in (
        "/clients/ss/alice",
        "/clients/hysteria/alice",
        "/clients/vless/alice",
        "/clients/vmess/alice",
        "/clients/http/alice",
        "/clients/mtg/alice",
        "/clients/sub/alice",
    ):
        _expect(c, "GET", path, 200)
    html = c.get("/users").get_data(as_text=True)
    csrf = _csrf(html)
    _expect(c, "POST", "/settings/theme", 302, {"csrf_token": csrf, "theme": "light"})
    _expect(c, "POST", "/settings/lang", 302, {"csrf_token": csrf, "lang": "en"})
    _expect(
        c,
        "POST",
        "/users/add",
        302,
        {
            "csrf_token": csrf,
            "name": "bob",
            "password": "bobpass1",
            "expires": "",
            "quota_gb": "0",
            "ikev2_enabled": "1",
            "l2tp_enabled": "1",
        },
    )
    _expect(
        c,
        "POST",
        "/users/update",
        302,
        {"csrf_token": csrf, "name": "bob", "password": "", "quota_gb": "5", "ikev2_enabled": "1"},
    )
    _expect(c, "POST", "/users/delete", 302, {"csrf_token": csrf, "name": "bob"})
    print("  OK  smoke happy path")


def scenario_corrupt(tmp: Path, label: str, users_payload, config_payload=None) -> None:
    app_dir = tmp / "app"
    cfg, data, sysdir = tmp / "cfg", tmp / "data", tmp / "sys"
    import shutil

    shutil.copytree(PANEL, app_dir, dirs_exist_ok=True)
    _seed(cfg, data, users_payload)
    if config_payload is not None:
        (cfg / "config.json").write_text(
            config_payload if isinstance(config_payload, str) else json.dumps(config_payload),
            encoding="utf-8",
        )
    A = _import_app(app_dir, cfg, data, sysdir)
    c = _client(A)
    login = c.get("/login")
    assert login.status_code == 200, login.status_code
    _login(c)
    for path in ("/", "/users", "/sessions", "/clients", "/smart", "/settings", "/logs"):
        _expect(c, "GET", path, 200)
    print("  OK  smoke %s" % label)


def main() -> int:
    try:
        import flask  # noqa: F401
        from werkzeug.security import generate_password_hash  # noqa: F401
    except ImportError:
        print("  skip flask/werkzeug not installed")
        return 0
    fails = 0
    cases = [
        ("happy", scenario_happy, {}),
        ("users list", lambda t: scenario_corrupt(t, "users=[]", "[]\n"), {}),
        ("users null", lambda t: scenario_corrupt(t, "users=null", "null\n"), {}),
        (
            "bad quota",
            lambda t: scenario_corrupt(
                t,
                "bad quota",
                {"alice": {"password": "x", "quota_gb": "nope", "used_bytes": {"x": 1}}},
            ),
            {},
        ),
        ("config list", lambda t: scenario_corrupt(t, "config=[]", {"alice": {"password": "x"}}, "[]\n"), {}),
    ]
    for name, fn, _ in cases:
        tmp = Path(tempfile.mkdtemp(prefix="mvp-smoke-"))
        try:
            fn(tmp)
        except Exception as e:
            print("  FAIL  %s: %s" % (name, e))
            fails += 1
        finally:
            import shutil

            shutil.rmtree(tmp, ignore_errors=True)
    if fails:
        print("SMOKE FAILED (%s)" % fails)
        return 1
    print("SMOKE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
