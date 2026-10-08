#!/usr/bin/env python3
"""Account revocation, persistence, quota, and update regression tests."""
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "panel"))
from state_lock import StateLock
import smoke_panel as smoke


def increment(path, count):
    path = Path(path)
    lock = StateLock(path.with_suffix(".lock"))
    for _ in range(count):
        with lock:
            value = json.loads(path.read_text())
            path.write_text(json.dumps(value + 1))


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        appdir = self.root / "app"
        shutil.copytree(ROOT / "panel", appdir)
        smoke._seed(self.root / "cfg", self.root / "data", {
            "alice": {"password": "alicepass", "quota_gb": 0,
                      "used_bytes": 0, "expires": "", "enabled": True},
            "bob": {"password": "bobpass", "quota_gb": 0,
                    "used_bytes": 0, "expires": "", "enabled": True},
        })
        self.A = smoke._import_app(appdir, self.root / "cfg", self.root / "data", self.root / "sys")
        self.commands = []
        self.A.run = lambda cmd, timeout=10: self.commands.append(cmd) or ""
        # Service operations are simulated, so their queried state must also
        # be simulated rather than inherited from the CI runner's systemd.
        self.A._systemctl_active = lambda unit: True
        self.A.parse_sessions = lambda: []
        self.A.xray_ss_stats = lambda: {}
        self.A.hysteria_stats = lambda: {}
        self.A.write_xray_ss_config = lambda users=None: None
        self.A.write_hysteria_config = lambda users=None: None
        self.A.write_mtg_config = lambda users=None: None

    def tearDown(self):
        self.tmp.cleanup()

    def client(self):
        c = smoke._client(self.A)
        smoke._login(c)
        return c

    def test_deleted_users_are_not_imported_again(self):
        self.A.IPSEC_SECRETS.write_text('deleted : EAP "oldpass"\n')
        self.assertNotIn("deleted", self.A.import_secrets_if_needed())

    def test_disk_password_is_authoritative(self):
        self.A.IPSEC_SECRETS.write_text('alice : EAP "stale"\n')
        self.assertEqual(self.A.import_secrets_if_needed()["alice"]["password"], "alicepass")

    def test_delete_revokes_active_session_and_credentials(self):
        c = self.client()
        csrf = smoke._csrf(c.get("/users").get_data(as_text=True))
        self.A.parse_sessions = lambda: [{"user": "alice", "proto": "IKEv2", "id": "7", "conn": "IKEv2-EAP"}]
        self.assertEqual(c.post("/users/delete", data={"name": "alice", "csrf_token": csrf}).status_code, 302)
        self.assertNotIn("alice", self.A.load_users())
        self.assertNotIn("alice", self.A.IPSEC_SECRETS.read_text())
        self.assertTrue(any("IKEv2-EAP[7]" in cmd for cmd in self.commands))
        self.assertIn("bob", self.A.load_users())

    def test_quota_revokes_existing_ike_session(self):
        users = self.A.load_users()
        users["alice"].update(quota_gb=1, used_bytes=2_000_000_000)
        self.A.save_users(users)
        self.A.parse_sessions = lambda: [{"user": "alice", "proto": "IKEv2", "id": "7", "conn": "IKEv2-EAP", "bytes_total": 0}]
        self.A.sample_traffic()
        self.assertTrue(any("IKEv2-EAP[7]" in cmd for cmd in self.commands))

    def test_disabled_protocol_is_revoked(self):
        users = self.A.load_users()
        users["alice"]["ikev2_enabled"] = False
        self.A.revoke_invalid_sessions(users, [{"user": "alice", "proto": "IKEv2", "id": "7"}])
        self.assertTrue(any("IKEv2-EAP[7]" in cmd for cmd in self.commands))

    def test_ppp_termination_checks_process_identity(self):
        with patch.object(Path, "read_text", side_effect=["123", "pppd"]), patch.object(os, "kill") as kill:
            self.A.terminate_user_session({"conn": "L2TP-PPP", "id": "ppp0"})
            kill.assert_called_once()
        with patch.object(Path, "read_text", side_effect=["123", "unrelated"]), patch.object(os, "kill") as kill:
            self.A.terminate_user_session({"conn": "L2TP-PPP", "id": "ppp0"})
            kill.assert_not_called()

    def test_traffic_failure_does_not_double_charge(self):
        values = iter([{"alice": 100}, {}, {"alice": 150}])
        self.A.xray_ss_stats = lambda: next(values)
        for _ in range(3):
            self.A.sample_traffic()
        self.assertEqual(self.A.load_users()["alice"]["used_bytes"], 150)

    def test_restart_accounts_new_epoch(self):
        self.A.xray_ss_stats = lambda: {"alice": 100}
        self.A.run = lambda cmd, timeout=10: "1000" if "show" in cmd else ""
        self.A.sample_traffic()
        self.A.xray_ss_stats = lambda: {"alice": 120}
        self.A.run = lambda cmd, timeout=10: "2000" if "show" in cmd else ""
        self.A.sample_traffic()
        self.assertEqual(self.A.load_users()["alice"]["used_bytes"], 220)

    def test_ppp_final_traffic_is_consumed_once(self):
        (self.A.DATA_DIR / "ppp-acct.log").write_text("alice 10.8.3.1 100 50 200 ppp0 100\n")
        for _ in range(2):
            self.A.sample_traffic()
        self.assertEqual(self.A.load_users()["alice"]["used_bytes"], 150)

    def test_ppp_final_traffic_subtracts_live_sample(self):
        self.A.save_json(self.A.SNAP_FILE, {"alice:L2TP:ppp0:100": 100})
        (self.A.DATA_DIR / "ppp-acct.log").write_text("alice 10.8.3.1 100 50 200 ppp0 100\n")
        self.A.sample_traffic()
        self.assertEqual(self.A.load_users()["alice"]["used_bytes"], 50)

    def test_password_rotation_revokes_other_browser(self):
        c1, c2 = self.client(), self.client()
        csrf = smoke._csrf(c1.get("/settings").get_data(as_text=True))
        self.assertEqual(c1.post("/settings/admin", data={"password": "newSecurePassword123", "csrf_token": csrf}).status_code, 302)
        self.assertEqual(c2.get("/api/status").status_code, 401)

    def test_update_failure_is_not_reported_as_success(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(self.A.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = "HEAD is now at abc"
            run.return_value.stderr = "failed"
            self.assertFalse(self.A.apply_update()[0])

    def test_update_queue_is_reported_as_started(self):
        with patch.object(Path, "is_file", return_value=True), patch.object(self.A.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "panel update queued"
            run.return_value.stderr = ""
            self.assertTrue(self.A.apply_update()[0])

    def test_https_proxy_link(self):
        self.assertTrue(self.A.http_proxy_uri("alice", self.A.load_users()["alice"], self.A.load_config()).startswith("https://"))

    def test_mtg_rotation_and_unchanged_config(self):
        source = (ROOT / "panel/app.py").read_text(encoding="utf-8")
        import ast
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == "write_mtg_config")
        exec(compile(ast.Module(body=[node], type_ignores=[]), "app.py", "exec"), self.A.__dict__)
        users = self.A.load_users()
        for user in users.values():
            user["mtg_enabled"] = True
        self.A.write_mtg_config(users)
        first = self.A.load_config()["mtg_secret"]
        count = len(self.commands)
        self.A.write_mtg_config(users)
        self.assertEqual(count, len(self.commands))
        users.pop("alice")
        self.A.write_mtg_config(users)
        self.assertNotEqual(first, self.A.load_config()["mtg_secret"])

    def test_metered_accounts_cannot_use_shared_mtg(self):
        self.assertFalse(self.A.mtg_allowed({"mtg_enabled": True, "quota_gb": 5}))
        self.assertTrue(self.A.mtg_allowed({"mtg_enabled": True, "quota_gb": 0}))

    def test_restore_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            self.A.validate_restored_user("alice", {"ss_port": 70000})

    def test_restore_rejects_unsafe_psk(self):
        cfg = self.A.load_config()
        cfg["psk"] = 'invalid"psk'
        with self.assertRaises(ValueError):
            self.A.validate_restored_config(cfg)

    def test_private_destination_is_rejected_at_connect(self):
        with patch.object(self.A.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]), patch.object(self.A.socket, "socket") as socket:
            with self.assertRaises(OSError):
                self.A._PublicHTTPSConnection("example.com").connect()
            socket.assert_not_called()

    def test_failed_sync_is_not_ready(self):
        self.A.write_xray_ss_config = lambda users=None: (_ for _ in ()).throw(RuntimeError("unavailable"))
        with self.assertRaises(RuntimeError):
            self.A.sync_accounts()
        self.assertFalse(self.A.app._accounts_ready)

    def test_legacy_updater_bootstrap(self):
        called = []
        self.A.apply_update = lambda: called.append("update") or (True, "queued")
        self.A._write_certbot_hook = lambda domain: None
        self.A.collector_loop = lambda: called.append("collector")
        self.A.initialize_collector()
        self.assertEqual(called, ["update", "collector"])

    def test_completed_install_does_not_bootstrap_again(self):
        (self.A.DATA_DIR / "deployment-version").write_text("2\n")
        self.A.apply_update = lambda: self.fail("unexpected update")
        self.A._write_certbot_hook = lambda domain: None
        self.A.collector_loop = lambda: None
        self.A.initialize_collector()


class ProcessTests(unittest.TestCase):
    def test_processes_do_not_lose_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "counter.json"
            path.write_text("0")
            processes = [multiprocessing.Process(target=increment, args=(str(path), 30)) for _ in range(3)]
            for process in processes:
                process.start()
            for process in processes:
                process.join(30)
                self.assertEqual(process.exitcode, 0)
            self.assertEqual(json.loads(path.read_text()), 90)


if __name__ == "__main__":
    unittest.main(verbosity=2)
