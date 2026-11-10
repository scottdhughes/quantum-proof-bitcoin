#!/usr/bin/env python3
"""Public-test custody, floor durability and local HTTP boundary controls."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "contrib/ml-dsa-console"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


control = load("test_public_controller", HERE / "public_controller.py")
app = load("test_public_app", HERE / "public_app.py")
runtime = load("test_public_runtime", HERE / "public_runtime.py")


class PublicConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"
        self.c = control.PublicController(self.state, container="pqbtc-mldsa-public-unit")
        self.addCleanup(self.c.close)
        self.point = {"wallet_id": "11" * 16, "generation": 9, "next_receive": 4, "next_change": 3}
        key = bytes([17]) * 1312
        self.manifest = {"schema": control.wallet.SCHEMA, "spec_sha256": control.wallet.SPEC,
                         "network_binding": control.wallet.protocol.binding("test").hex(), "wallet_id": self.point["wallet_id"],
                         "next_receive": 4, "next_change": 3, "entries": [{"branch": 0, "index": 0, "public_key": key.hex(),
                         "program": control.wallet.protocol.key_commitment("test", key).hex()}]}

    def backup(self, point=None, manifest=None):
        value = {"schema": "PQBTC-MLDSA44-PUBLIC-BACKUP-1", "compatibility": control.COMPATIBILITY,
                 "created_at": "2026-11-10T12:00:00Z", "checkpoint": point or self.point,
                 "manifest": manifest or self.manifest, "ciphertext": "42" * 167}
        value["sha256"] = hashlib.sha256(control.canonical(value)).hexdigest()
        return value

    def test_public_backup_is_bound_to_profile_and_contains_no_chain_or_binary_pin(self):
        value = self.backup()
        self.assertEqual(control.validate_backup(value), value)
        self.assertNotIn("chain", value)
        self.assertNotIn("image", value)
        for field, wrong in (("profile_sha256", "00" * 32), ("network", "regtest"), ("wallet_format", 2)):
            bad = copy.deepcopy(value)
            bad["compatibility"][field] = wrong
            payload = {key: item for key, item in bad.items() if key != "sha256"}
            bad["sha256"] = hashlib.sha256(control.canonical(payload)).hexdigest()
            with self.subTest(field=field), self.assertRaises(ValueError):
                control.validate_backup(bad)

    def test_backup_tampering_and_foreign_network_manifest_refuse(self):
        for field, wrong in (("ciphertext", "41" * 167), ("checkpoint", {**self.point, "next_receive": 0})):
            bad = self.backup()
            bad[field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                control.validate_backup(bad)
        bad = copy.deepcopy(self.manifest)
        bad["network_binding"] = control.wallet.protocol.binding("regtest").hex()
        with self.assertRaises(ValueError):
            control.validate_manifest(bad)

    def test_floor_intent_is_durable_before_native_request_and_survives_restart(self):
        self.c._retain(point=self.point, manifest=self.manifest)
        self.c._signer = SimpleNamespace(poll=lambda: None)
        observed = []

        def request(action, params=None):
            saved = json.loads((self.state / "public-wallet.json").read_text())
            observed.append((action, saved["checkpoint"]["next_receive"]))
            return {"index": 4, "address": "tq1fixture"}

        with patch.object(self.c, "_request", request), patch.object(self.c, "status", return_value={"phase": "running"}):
            result = self.c.action("receive")
        self.c._signer = None
        self.assertEqual(result["result"]["index"], 4)
        self.assertEqual(observed, [("receive", 5)])
        self.c.close()
        reopened = control.PublicController(self.state, container="pqbtc-mldsa-public-unit")
        try:
            self.assertEqual(reopened.journal["checkpoint"]["next_receive"], 5)
            self.assertEqual((self.state / "public-wallet.json").stat().st_mode & 0o777, 0o600)
        finally:
            reopened.close()

    def test_failed_issuance_keeps_burned_floor_and_locks_before_retry(self):
        self.c._retain(point=self.point, manifest=self.manifest)
        self.c._signer = SimpleNamespace(poll=lambda: None)

        def stop():
            self.c._signer = None

        with patch.object(self.c, "_request", side_effect=ValueError("interrupted transport")), patch.object(self.c, "_stop_signer", side_effect=stop):
            with self.assertRaises(ValueError):
                self.c.action("receive")
        self.assertIsNone(self.c._signer)
        self.assertEqual(json.loads((self.state / "public-wallet.json").read_text())["checkpoint"]["next_receive"], 5)
        with self.assertRaisesRegex(ValueError, "Unlock"):
            self.c.action("receive")

    def test_old_backup_recovery_uses_latest_independent_public_floors(self):
        self.c._retain(point={**self.point, "next_receive": 39, "next_change": 12}, manifest=self.manifest)
        backup_id = "ab" * 16
        self.c._write_json("backups/" + backup_id + ".json", self.backup())
        calls, unlocks = [], []

        def unlock(password, **kwargs):
            unlocks.append((password, kwargs))
            return {**kwargs["point"], "generation": 10}

        with patch.object(self.c, "_invoke", side_effect=lambda *args, **kwargs: calls.append((args, kwargs))), \
             patch.object(self.c, "_start_signer", side_effect=unlock), patch.object(self.c, "_start_worker"), \
             patch.object(self.c, "_request"):
            result = self.c._recover(backup_id, "ephemeral-unit-secret")
        self.assertEqual((result["next_receive"], result["next_change"]), (39, 12))
        self.assertEqual(unlocks[0][1]["point"]["next_receive"], 39)
        self.assertEqual(unlocks[0][1]["point"]["next_change"], 12)
        self.assertFalse(result["chain_snapshot_restored"])
        self.assertNotIn("ephemeral-unit-secret", (self.state / "public-wallet.json").read_text())
        self.assertNotIn("ephemeral-unit-secret", json.dumps(calls, default=lambda value: "[bytes]"))

    def test_wrong_password_never_replaces_selected_custody(self):
        self.c._retain(point=self.point, manifest=self.manifest)
        backup_id = "ab" * 16
        self.c._write_json("backups/" + backup_id + ".json", self.backup())
        calls = []
        with patch.object(self.c, "_invoke", side_effect=lambda *args, **kwargs: calls.append((args, kwargs))), \
             patch.object(self.c, "_start_signer", side_effect=ValueError("wrong password")):
            with self.assertRaisesRegex(ValueError, "wrong password"):
                self.c._recover(backup_id, "wrong-unit-secret")
        self.assertEqual(len(calls), 1)
        self.assertIn("/signer/recovery-", calls[0][0][-1])
        self.assertNotIn("os.rename", calls[0][0][3])
        self.assertEqual(self.c.journal["checkpoint"]["next_receive"], 4)

    def test_recovery_refuses_without_independent_floor_journal(self):
        backup_id = "ab" * 16
        self.c._write_json("backups/" + backup_id + ".json", self.backup())
        with patch.object(self.c, "_invoke", side_effect=AssertionError("custody must remain untouched")):
            with self.assertRaisesRegex(ValueError, "independent retained floor journal"):
                self.c._recover(backup_id, "unit-secret")

    def test_native_operator_secret_uses_stdin_fd_and_never_argv(self):
        self.c._retain(point=self.point, manifest=self.manifest)
        secret = "unit-only-secret-THROUGH-FD"

        class Input(io.BytesIO):
            def close(inner):
                inner.saved = inner.getvalue()

        class Process:
            def __init__(inner):
                inner.stdin = Input()

            def poll(inner):
                return None

        process = Process()
        stream = process.stdin
        lines = [b'{"pid":123,"start":"456"}',
                 ("MLDSA_WALLET_STATUS_V1 " + self.point["wallet_id"] + " 10 4 3").encode()]
        commands = []

        def popen(command, **kwargs):
            commands.append(command)
            return process

        with patch.object(control.subprocess, "Popen", side_effect=popen), patch.object(self.c, "_invoke", return_value=b"1"), \
             patch.object(self.c, "_line", side_effect=lines):
            self.c._start_signer(secret)
        self.c._signer = self.c._signer_info = None
        self.assertNotIn(secret, json.dumps(commands))
        entry = self.manifest["entries"][0]
        public_frame = ((1).to_bytes(4, "little") + bytes([entry["branch"]]) + entry["index"].to_bytes(4, "little") +
                        bytes.fromhex(entry["public_key"]) + bytes.fromhex(entry["program"]))
        self.assertEqual(stream.saved, len(secret).to_bytes(2, "little") + secret.encode() + public_frame)
        self.assertIn("--network", commands[0])
        self.assertIn("test", commands[0])
        self.assertIn("--operator-fd", commands[0])
        self.assertIn("--recovery-public-input", commands[0])
        self.assertNotIn(secret, (self.state / "public-wallet.json").read_text())

    def test_public_manager_cannot_target_original_offline_container(self):
        for name in ("pqbtc-mldsa-local", "pqbtc-mldsa-demo", "unrelated"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                control.PublicManager(self.state, container=name)

    def test_browser_schema_excludes_fault_and_binary_replacement_controls(self):
        for action, params in (("crash", {}), ("upgrade", {"descriptor": {}}), ("adverse", {}),
                               ("unlock", {"password": "unit", "shell": "rm"}), ("receive", {"password": "unit"})):
            with self.subTest(action=action), self.assertRaises(ValueError):
                app.validate_action({"action": action, "params": params, "request_id": "unit-browser-request"})
        self.assertEqual(app.validate_action({"action": "unlock", "params": {"password": "unit"},
                                             "request_id": "unit-browser-request"})[:2], ("unlock", {"password": "unit"}))

    def test_scoped_cookie_refuses_symlink_and_nonprivate_file(self):
        state = Path(self.temp.name) / "node"
        state.mkdir(mode=0o700)
        node = runtime.PublicNode("/unused/binary", state, lambda url, timeout: url)
        subdir = state / "mldsa44-test-v1"
        subdir.mkdir(mode=0o700)
        cookie = subdir / ".cookie"
        cookie.write_text("__cookie__:" + "ab" * 32)
        cookie.chmod(0o644)
        with self.assertRaises(ValueError):
            node.rpc()
        cookie.chmod(0o600)
        self.assertTrue(node.rpc().startswith("http://__cookie__:"))
        cookie.rename(subdir / "retained-cookie")
        cookie.symlink_to(subdir / "retained-cookie")
        with self.assertRaises(OSError):
            node.rpc()

    def test_public_orphan_is_retained_and_next_floor_write_succeeds(self):
        public = Path(self.temp.name) / "public"
        public.mkdir(mode=0o700)
        current = public / "public-wallet.json"
        current.write_text(json.dumps(self.manifest))
        current.chmod(0o600)
        orphan = public / "public-wallet.tmp"
        orphan.write_bytes(b"interrupted PUBLIC metadata")
        orphan.chmod(0o600)
        with runtime.offline.open_public_store(control.wallet, public, network="test") as store:
            payload = b"\0" + bytes.fromhex(self.point["wallet_id"]) + (5).to_bytes(4, "little") + (3).to_bytes(4, "little")
            store.observe_status(payload)
            self.assertEqual(store.export()["next_receive"], 5)
        retained = list(public.glob("public-wallet.orphan-*/public-wallet.tmp"))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), b"interrupted PUBLIC metadata")
        self.assertFalse(orphan.exists())
        self.assertEqual(json.loads(current.read_text())["network_binding"], control.wallet.protocol.binding("test").hex())

    def test_live_process_cannot_override_authenticated_locked_or_disconnected_state(self):
        self.c._worker = self.c._signer = SimpleNamespace(poll=lambda: None)
        try:
            for connected, locked, expected in ((True, True, True), (False, False, True), (True, False, False)):
                value = control.legacy.Controller._empty()
                value["phase"] = "running"
                value["wallet"].update(signer_connected=connected, locked=locked)
                with self.subTest(connected=connected, locked=locked), patch.object(self.c, "_request", return_value=value):
                    self.assertEqual(self.c.status()["wallet"]["locked"], expected)
        finally:
            self.c._worker = self.c._signer = None

    def test_lost_docker_handles_report_restart_without_reusing_signer(self):
        self.c._retain(point=self.point, manifest=self.manifest)
        dead = SimpleNamespace(poll=lambda: 137, stdin=None, communicate=lambda timeout: (b"", b""))
        self.c._worker = self.c._signer = dead
        status = self.c.status()
        self.assertEqual(status["phase"], "stopped")
        self.assertTrue(status["wallet"]["locked"])
        self.assertTrue(status["restart_required"])
        self.assertIsNone(self.c._worker)
        self.assertIsNone(self.c._signer)
        self.assertEqual(status["wallet"]["next_receive"], 4)

    def test_typed_private_action_parameters_refuse_before_docker(self):
        with patch.object(self.c.manager, "run", side_effect=AssertionError("Docker must not execute")):
            for params in ([], "", 0, False):
                with self.subTest(params=params), self.assertRaises(ValueError):
                    self.c.action("start", params)

    def test_one_lost_child_restart_discards_both_handles_before_respawn(self):
        for lost in ("worker", "signer"):
            with self.subTest(lost=lost):
                processes = {}
                for role in ("worker", "signer"):
                    process = SimpleNamespace(code=1 if role == lost else None, stdin=None, communicate=lambda timeout: (b"", b""))
                    process.poll = lambda p=process: p.code
                    processes[role] = process
                    setattr(self.c, "_" + role, process)
                spawned = []

                def restart(args):
                    self.assertEqual(args[:2], ["restart", "--time"])
                    for process in processes.values():
                        process.code = 137

                def spawn():
                    self.assertIsNone(self.c._worker)
                    self.assertIsNone(self.c._signer)
                    spawned.append(True)
                    self.c._worker = SimpleNamespace(poll=lambda: None)

                with patch.object(self.c.manager, "ensure"), patch.object(self.c.manager, "inspect", return_value={}), \
                     patch.object(self.c.manager, "layout"), patch.object(self.c.manager, "run", side_effect=restart), \
                     patch.object(self.c, "_start_worker", side_effect=spawn), patch.object(self.c, "_request", return_value={"started": True}):
                    self.assertEqual(self.c._start(), {"started": True})
                self.c._worker = self.c._signer = None
                self.assertEqual(spawned, [True])


if __name__ == "__main__":
    unittest.main()
