#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""PUBLIC metadata and actual filesystem behavior, not private-key tests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only experimental wallet persistence")
class PublicWalletTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("mldsa_node_wallet", ROOT / "contrib/ml-dsa-signer/node_wallet.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory(prefix="mldsa-public-wallet-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        fixture = json.loads((ROOT / "src/test/data/mldsa44_node.json").read_text(encoding="utf8"))
        self.public_key = bytes.fromhex(fixture["public_key"])
        self.program = bytes.fromhex(fixture["script"])[2:]
        self.identity = b"\x11" * 16

    def status(self, receive=0, change=0, identity=None):
        return b"\0" + (identity or self.identity) + receive.to_bytes(4, "little") + change.to_bytes(4, "little")

    def address(self, branch=0, index=0):
        return bytes([branch]) + index.to_bytes(4, "little") + self.public_key + self.program

    def store(self):
        value = self.module.PublicStore(self.directory)
        self.addCleanup(value.close)
        return value

    def test_durable_public_address_survives_reopen(self):
        store = self.store()
        store.observe_status(self.status())
        entry = store.accept_address(self.address(), 0)
        self.assertEqual(entry["index"], 0)
        self.assertEqual(entry["program"], self.program.hex())
        expected = store.export()
        self.assertEqual(expected["next_receive"], 1)
        self.assertEqual(expected["wallet_id"], "11" * 16)
        store.close()
        reopened = self.store()
        self.assertEqual(reopened.export(), expected)
        self.assertEqual((self.directory / "public-wallet.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("root", expected)

    def test_wrong_program_branch_replay_and_oversized_address_refused(self):
        store = self.store()
        store.observe_status(self.status())
        wrong = bytearray(self.address()); wrong[-1] ^= 1
        for payload in (bytes(wrong), self.address(1), self.address() + b"x", self.address()[:-1]):
            with self.subTest(size=len(payload)), self.assertRaises(self.module.WalletError):
                store.accept_address(payload, 0)
        store.accept_address(self.address(), 0)
        with self.assertRaises(self.module.WalletError):
            store.accept_address(self.address(), 0)

    def test_signer_identity_and_high_water_cannot_go_backwards(self):
        store = self.store()
        store.observe_status(self.status())
        store.accept_address(self.address(), 0)
        before = store.export()
        for status in (self.status(), self.status(1, identity=b"\x22" * 16), self.status(2**31 + 1)):
            with self.assertRaises(self.module.WalletError):
                store.observe_status(status)
            self.assertEqual(store.export(), before)
        store.observe_status(self.status(5, 3))
        self.assertEqual(store.export()["next_receive"], 5)
        self.assertEqual(len(store.export()["entries"]), 1)

    def test_import_binds_network_spec_key_counter_and_server_floor(self):
        store = self.store(); store.observe_status(self.status()); store.accept_address(self.address(), 0)
        manifest = store.export(); store.close()
        second = self.directory / "restored"; second.mkdir(mode=0o700)
        with self.module.PublicStore(second) as target:
            for field, value in (("network_binding", "00" * 36), ("spec_sha256", "00" * 32),
                                 ("next_receive", 0), ("next_change", True)):
                bad = copy.deepcopy(manifest); bad[field] = value
                with self.subTest(field=field), self.assertRaises(self.module.WalletError):
                    target.import_manifest(bad, self.status(1))
            bad = copy.deepcopy(manifest); bad["entries"][0]["public_key"] = "00" * 1312
            with self.assertRaises(self.module.WalletError): target.import_manifest(bad, self.status(1))
            with self.assertRaises(self.module.WalletError): target.import_manifest(manifest, self.status(0))
            target.import_manifest(manifest, self.status(1))
            self.assertEqual(target.export(), manifest)
            with self.assertRaises(self.module.WalletError): target.import_manifest(manifest, self.status(1))

    def test_single_writer_and_insecure_public_files_refused(self):
        store = self.store(); store.observe_status(self.status())
        with self.assertRaises(self.module.WalletError): self.module.PublicStore(self.directory)
        store.close()
        state = self.directory / "public-wallet.json"; state.chmod(0o644)
        with self.assertRaises(self.module.WalletError): self.module.PublicStore(self.directory)
        state.chmod(0o600)
        os.link(state, self.directory / "alias")
        with self.assertRaises(self.module.WalletError): self.module.PublicStore(self.directory)

    def test_duplicate_json_members_and_symlink_refused(self):
        state = self.directory / "public-wallet.json"
        state.write_text('{"schema":"a","schema":"b"}', encoding="utf8"); state.chmod(0o600)
        with self.assertRaises(self.module.WalletError): self.module.PublicStore(self.directory)
        state.rename(self.directory / "retained-bad-json")
        state.symlink_to(self.directory / "retained-bad-json")
        with self.assertRaises(self.module.WalletError): self.module.PublicStore(self.directory)

    def test_failed_durable_write_returns_no_address_and_poisons_instance(self):
        store = self.store(); store.observe_status(self.status())
        with patch.object(self.module.os, "fsync", side_effect=OSError("fixture fsync failure")):
            with self.assertRaises(self.module.WalletError): store.accept_address(self.address(), 0)
        with self.assertRaises(self.module.WalletError): store.export()
        self.assertTrue((self.directory / "public-wallet.tmp").exists())
        data = json.loads((self.directory / "public-wallet.json").read_text(encoding="utf8"))
        self.assertEqual(data["next_receive"], 0)

    def test_deployment_is_full_binding_and_active_not_a_network_label(self):
        info = {"chain": "regtest", "blocks": 1, "valueless_mldsa44_demo": {
            "scope": "VALUELESS_EXPERIMENTAL_REGTEST_ONLY", "active": True, "activation_height": 1,
            "network_binding": "96bd879ee215bd6baf48facc1f79c9be57bcee375d3b1d7afb6c1255d0759ab57211cc36",
            "spec_sha256": "c7993d7f2ae72623cf3b9e2f45c021885f610ef3169dbf176e0c2dd1a619d126"}}
        self.module.validate_deployment(info)
        for field, value in (("active", False), ("active", 1), ("activation_height", 2),
                             ("network_binding", "00" * 36), ("spec_sha256", "00" * 32)):
            bad = copy.deepcopy(info); bad["valueless_mldsa44_demo"][field] = value
            with self.subTest(field=field), self.assertRaises(self.module.WalletError):
                self.module.validate_deployment(bad)
        for bad in ({"chain": "regtest", "blocks": 1}, {**info, "blocks": 0}, {**info, "chain": "main"}):
            with self.assertRaises(self.module.WalletError): self.module.validate_deployment(bad)

    def test_demo_evidence_tools_refuse_optimized_python(self):
        for relative in ("contrib/ml-dsa-signer/run_node_demo.py", "contrib/ml-dsa-signer/test_node_client.py",
                         "test/functional/feature_mldsa44_demo.py"):
            with self.subTest(script=relative):
                result = subprocess.run([sys.executable, "-O", ROOT / relative, "--help"], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("optimized Python", result.stderr)


if __name__ == "__main__":
    unittest.main()
