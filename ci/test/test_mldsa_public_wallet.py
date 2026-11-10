#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Explicit TEST binding through real public metadata and transaction codecs."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = "c7993d7f2ae72623cf3b9e2f45c021885f610ef3169dbf176e0c2dd1a619d126"
PROFILE = "78f5f1024d8276a49acbf54c5026f3e4c7e1c9ba3b901c102a0ac4e1311fa933"
TEST_BINDING = "a7e29cf779a947a9a6b549d08f256effeebbbcc0790868ee192d960a84aa48a0c639692b"
TEST_PROGRAM = "de94a99ca0ce01edcc47ac22a039fc9abe708765fbec4f69c0fdaed95652f60e"


class PublicNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("public_network_wallet", ROOT / "contrib/ml-dsa-signer/node_wallet.py")
        cls.wallet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.wallet)
        cls.fixture = json.loads((ROOT / "src/test/data/mldsa44_node.json").read_text())
        cls.key = bytes.fromhex(cls.fixture["public_key"])

    def manifest(self):
        return {"schema": self.wallet.SCHEMA, "spec_sha256": SPEC, "network_binding": TEST_BINDING,
                "wallet_id": "11" * 16, "next_receive": 1, "next_change": 0,
                "entries": [{"branch": 0, "index": 0, "public_key": self.key.hex(), "program": TEST_PROGRAM}]}

    def info(self):
        return {"chain": "test", "blocks": 1, "valueless_mldsa44_test": {
            "scope": "VALUELESS_EXPERIMENTAL_PUBLIC_TEST_ONLY", "active": True, "activation_height": 1,
            "network_binding": TEST_BINDING, "spec_sha256": SPEC, "profile_sha256": PROFILE,
            "verification_cost": 625, "max_block_verifications": 128, "max_standard_tx_verifications": 25}}

    def test_test_manifest_is_explicit_and_cannot_be_relabelled(self):
        value = self.manifest()
        self.assertEqual(self.wallet.validate_manifest(value, network="test"), value)
        with self.assertRaises(self.wallet.WalletError):
            self.wallet.validate_manifest(value)
        for network in ("main", "signet", "TEST", None):
            with self.subTest(network=network), self.assertRaises(self.wallet.WalletError):
                self.wallet.validate_manifest(value, network=network)
        value["network_binding"] = self.wallet.protocol.binding("regtest").hex()
        with self.assertRaises(self.wallet.WalletError):
            self.wallet.validate_manifest(value, network="test")
        # A TEST label with a genuine regtest program is also a substitution.
        value = self.manifest()
        value["entries"][0]["program"] = self.fixture["script"][4:]
        with self.assertRaises(self.wallet.WalletError):
            self.wallet.validate_manifest(value, network="test")

    def test_test_context_requires_activation_complete_identity_and_limits(self):
        self.wallet.validate_deployment(self.info(), network="test")
        for field, value in (("active", False), ("active", 1), ("activation_height", True),
                             ("network_binding", self.wallet.protocol.binding("regtest").hex()),
                             ("spec_sha256", "00" * 32), ("profile_sha256", "00" * 32),
                             ("verification_cost", 624), ("max_block_verifications", 129),
                             ("max_standard_tx_verifications", 26), ("max_standard_tx_verifications", True),
                             ("scope", "VALUELESS_EXPERIMENTAL_REGTEST_ONLY"), ("extra", 1)):
            bad = self.info()
            bad["valueless_mldsa44_test"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(self.wallet.WalletError):
                self.wallet.validate_deployment(bad, network="test")
        for info in ({"chain": "test", "blocks": 2}, {**self.info(), "blocks": 0},
                     {**self.info(), "chain": "regtest"}):
            with self.assertRaises(self.wallet.WalletError):
                self.wallet.validate_deployment(info, network="test")
        with self.assertRaises(self.wallet.WalletError):
            self.wallet.validate_deployment(self.info())

    def test_witness_attachment_uses_selected_key_commitment(self):
        model = {"version": 2, "lock_time": 0,
                 "inputs": [{"prev_txid": "22" * 32, "prev_index": 0, "sequence": 4294967295,
                             "amount": 100000, "script_pubkey": "5220" + TEST_PROGRAM}],
                 "outputs": [{"amount": 99000, "script_pubkey": "5220" + TEST_PROGRAM}]}
        payload = b"\x01" + bytes(2420) + self.key
        wire = self.wallet.attach_witnesses(model, [(0, 0)], self.manifest(), payload, network="test")
        suffix = b"\x02\xfd\x74\x09" + bytes(2420) + b"\xfd\x20\x05" + self.key + bytes(4)
        self.assertTrue(wire.endswith(suffix))
        self.assertEqual(wire[:6], b"\x02\x00\x00\x00\x00\x01")
        with self.assertRaises(self.wallet.WalletError):
            self.wallet.attach_witnesses(model, [(0, 0)], self.manifest(), payload)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux public persistence")
    def test_test_store_preserves_floors_and_wrong_network_reopen_refuses(self):
        with tempfile.TemporaryDirectory(prefix="public-test-network-") as directory:
            status = b"\0" + bytes.fromhex("11" * 16) + bytes(8)
            with self.wallet.PublicStore(directory, network="test") as store:
                store.observe_status(status)
                payload = b"\0" + bytes(4) + self.key + bytes.fromhex(TEST_PROGRAM)
                address = store.accept_address(payload, 0)
                self.assertTrue(address["address"].startswith("tq1z"))
                retained = store.export()
                self.assertEqual(retained, self.manifest())
                with self.assertRaises(self.wallet.WalletError):
                    store.observe_status(status)
            with self.assertRaises(self.wallet.WalletError):
                self.wallet.PublicStore(directory)
            with self.wallet.PublicStore(directory, network="test") as store:
                self.assertEqual(store.export(), retained)
                with self.assertRaises(self.wallet.WalletError):
                    store.accept_address(payload, 0)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux public persistence")
    def test_node_context_refuses_before_signer_call_and_component_mismatch(self):
        class Signer:
            network = "test"
            def call(self, *args):
                raise AssertionError("signer must remain untouched before deployment validation")
        class RPC:
            def getblockchaininfo(inner):
                return {**self.info(), "blocks": 0}
        with tempfile.TemporaryDirectory(prefix="public-test-context-") as directory:
            with self.wallet.PublicStore(directory, network="test") as store:
                wallet = self.wallet.NodeWallet(RPC(), Signer(), store, network="test")
                with self.assertRaises(self.wallet.WalletError):
                    wallet.status()
                with self.assertRaises(self.wallet.WalletError):
                    self.wallet.NodeWallet(RPC(), Signer(), store)


if __name__ == "__main__":
    unittest.main()
