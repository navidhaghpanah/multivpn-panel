#!/usr/bin/env python3
"""Run one mtg process per personal (or legacy) MTProto instance.

mtg 2.2.8 has a single secret per process. This supervisor is the
ExecStart of panel-mtg.service. If mtg.toml is newer than instances.json,
that toml is used instead — so an older panel build can still publish the
shared secret after a rolled-back update. A missing mtg binary keeps this
process alive and idle so systemd does not crash-loop.
"""
import json
import os
import signal
import subprocess
import time
from pathlib import Path

INSTANCES = Path(os.environ.get("MTG_INSTANCES", "/etc/panel-mtg/instances.json"))
TOML = Path(os.environ.get("MTG_TOML", "/etc/panel-mtg/mtg.toml"))
BIN = Path(os.environ.get("MTG_BIN", "/opt/panel-mtg/mtg"))
WORKDIR = Path(os.environ.get("MTG_WORKDIR", "/tmp/panel-mtg-instances"))

children = {}
stopping = False


def _stop(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def stop_all():
    for proc in list(children.values()):
        try:
            _stop(proc)
        except Exception:
            pass
    children.clear()


def _handle(signum, frame):
    global stopping
    stopping = True


def load_desired():
    inst_mtime = INSTANCES.stat().st_mtime if INSTANCES.is_file() else -1
    toml_mtime = TOML.stat().st_mtime if TOML.is_file() else -1
    if TOML.is_file() and toml_mtime >= inst_mtime:
        return [{"id": "toml", "toml": str(TOML)}]
    if not INSTANCES.is_file():
        return []
    try:
        data = json.loads(INSTANCES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [{"id": "toml", "toml": str(TOML)}] if TOML.is_file() else []
    if not isinstance(data, list):
        return []
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("toml"):
            out.append({"id": "toml", "toml": str(item["toml"])})
            continue
        ident = str(item.get("id") or "")
        secret = str(item.get("secret") or "")
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not ident or not secret or '"' in secret or "\n" in secret or not 1 <= port <= 65535:
            continue
        stats_port = 0
        try:
            stats_port = int(item.get("stats_port") or 0)
        except (TypeError, ValueError):
            stats_port = 0
        if stats_port and not 1 <= stats_port <= 65535:
            stats_port = 0
        out.append({
            "id": ident,
            "secret": secret,
            "port": port,
            "stats_port": stats_port,
        })
    return out


def reconcile():
    desired = load_desired()
    wanted = {}
    for item in desired:
        key = "%s:%s:%s:%s" % (
            item.get("id"),
            item.get("port", ""),
            item.get("secret", "") or item.get("toml", ""),
            item.get("stats_port", ""),
        )
        wanted[key] = item
    for key in list(children):
        proc = children[key]
        if key not in wanted or proc.poll() is not None:
            try:
                _stop(proc)
            except Exception:
                pass
            children.pop(key, None)
    if not BIN.is_file():
        return
    try:
        WORKDIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    for key, item in wanted.items():
        if key in children:
            continue
        if item.get("toml"):
            toml_path = item["toml"]
        else:
            safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in item["id"]) or "user"
            toml_path = WORKDIR / (safe + ".toml")
            try:
                text = 'secret = "%s"\nbind-to = "0.0.0.0:%d"\n' % (item["secret"], item["port"])
                stats_port = int(item.get("stats_port") or 0)
                if 1 <= stats_port <= 65535:
                    text += (
                        "\n[stats.prometheus]\nenabled = true\n"
                        'bind-to = "127.0.0.1:%d"\nhttp-path = "/"\nmetric-prefix = "mtg"\n'
                    ) % stats_port
                toml_path.write_text(text, encoding="utf-8")
                os.chmod(toml_path, 0o600)
            except OSError:
                continue
        try:
            children[key] = subprocess.Popen(
                [str(BIN), "run", str(toml_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            continue


def main():
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    while not stopping:
        try:
            reconcile()
        except Exception:
            pass
        for _ in range(4):
            if stopping:
                break
            time.sleep(0.5)
    stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
