"""SQLite recovery copy of users.json plus traffic cursors.

users.json stays the compatible mirror (backups, the Telegram bot, restore,
and anything that reads the file directly). save_users writes this database
first, then replaces users.json. The database is stamped one second newer
than the JSON it was copied from, so a crash before the JSON replace still
recovers both the balance and the counters. After JSON is replaced it is
newer again and the next load prefers it.

Load prefers valid JSON when its mtime is greater than or equal to the SQLite
file. A restore writes JSON bytes and then calls prefer_json(), which makes
JSON newer than SQLite so the restored copy wins. Cursors are always read
from SQLite; a missing cursors table means this install has not sampled yet.
"""
import json
import os
import sqlite3
import time
from pathlib import Path


def sqlite_path(users_file):
    return Path(users_file).with_name("users.sqlite")


def load_sqlite(users_file):
    path = sqlite_path(users_file)
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % path.as_posix(), uri=True, timeout=5)
    except sqlite3.Error:
        return None
    try:
        rows = conn.execute("SELECT name, payload FROM users").fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    out = {}
    for name, payload in rows:
        if not isinstance(name, str):
            continue
        try:
            obj = json.loads(payload)
        except (TypeError, json.JSONDecodeError):
            return None
        if isinstance(obj, dict):
            out[name] = obj
    return out


def load_cursors(users_file):
    """Return {key: {value, epoch}} or None when this database has no ledger yet."""
    path = sqlite_path(users_file)
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % path.as_posix(), uri=True, timeout=5)
    except sqlite3.Error:
        return None
    try:
        rows = conn.execute("SELECT key, value, epoch FROM cursors").fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    out = {}
    for key, value, epoch in rows:
        if not isinstance(key, str):
            continue
        try:
            number = int(value or 0)
        except (TypeError, ValueError):
            number = 0
        out[key] = {"value": number, "epoch": str(epoch or "")}
    return out


def save_sqlite(users_file, users, cursors=None):
    path = sqlite_path(users_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    if cursors is None:
        cursors = load_cursors(users_file) or {}
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists():
        tmp.unlink()
    conn = sqlite3.connect(str(tmp), timeout=5)
    try:
        conn.execute("CREATE TABLE users (name TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        conn.execute(
            "CREATE TABLE cursors (key TEXT PRIMARY KEY, value INTEGER NOT NULL, epoch TEXT NOT NULL)"
        )
        rows = []
        for name, payload in (users or {}).items():
            if isinstance(name, str) and isinstance(payload, dict):
                rows.append((name, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))))
        conn.executemany("INSERT INTO users (name, payload) VALUES (?, ?)", rows)
        cursor_rows = []
        for key, row in (cursors or {}).items():
            if not isinstance(key, str) or key.startswith("__"):
                continue
            if isinstance(row, dict):
                try:
                    value = int(row.get("value") or 0)
                except (TypeError, ValueError):
                    value = 0
                epoch = str(row.get("epoch") or "")
            else:
                try:
                    value = int(row or 0)
                except (TypeError, ValueError):
                    value = 0
                epoch = ""
            cursor_rows.append((key, value, epoch))
        conn.executemany("INSERT INTO cursors (key, value, epoch) VALUES (?, ?, ?)", cursor_rows)
        conn.commit()
    finally:
        conn.close()
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    for suffix in ("-wal", "-shm"):
        extra = Path(str(path) + suffix)
        if extra.exists():
            try:
                extra.unlink()
            except OSError:
                pass
    json_path = Path(users_file)
    try:
        jm = json_path.stat().st_mtime
    except OSError:
        jm = time.time()
    stamp = jm + 1
    os.utime(path, (stamp, stamp))


def prefer_json(users_file):
    """Make a freshly restored users.json win the next load."""
    path = sqlite_path(users_file)
    json_path = Path(users_file)
    if not path.is_file() or not json_path.is_file():
        return
    sm = path.stat().st_mtime
    if json_path.stat().st_mtime <= sm:
        os.utime(json_path, (sm + 1, sm + 1))
