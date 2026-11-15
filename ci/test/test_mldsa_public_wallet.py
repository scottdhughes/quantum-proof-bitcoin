# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Explicit TEST binding through real public metadata and transaction codecs."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
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
        spec = importlib.util.spec_from_file_location("public_network_runtime", ROOT / "contrib/ml-dsa-console/public_runtime.py")
        cls.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runtime)
        spec = importlib.util.spec_from_file_location("public_network_controller", ROOT / "contrib/ml-dsa-console/public_controller.py")
        cls.controller = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.controller)
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

    def status_runtime(self, *, initialized=True):
        """Exercise the real wallet paths without native processes or custody files."""
        test = self
        manifest = self.manifest() if initialized else None
        script = "5220" + TEST_PROGRAM

        class RPC:
            expired = False

            def getblockchaininfo(inner):
                if inner.expired:
                    raise BrokenPipeError("idle HTTP connection closed")
                return {**test.info(), "bestblockhash": "aa" * 32}

            def gettxoutsetinfo(inner):
                return {"hash_serialized_3": "bb" * 32, "txouts": 1}

            def getpeerinfo(inner):
                return [{"id": 1}]

            def scantxoutset(inner, action, descriptors):
                test.assertEqual((action, descriptors), ("start", [{"desc": "raw(" + script + ")"}]))
                return {"success": True, "unspents": [{"txid": "22" * 32, "vout": 0, "scriptPubKey": script}]}

            def getrawmempool(inner):
                return []

            def gettxout(inner, txid, vout, include_mempool):
                test.assertEqual((txid, vout, include_mempool), ("22" * 32, 0, True))
                return {"scriptPubKey": {"hex": script}, "coinbase": False, "confirmations": 2, "value": 1}

        class Store:
            network = "test"

            def export(inner):
                if manifest is None:
                    raise test.wallet.WalletError("public wallet not initialized")
                return test.wallet.validate_manifest(manifest, network="test")

            def observe_status(inner, payload):
                return test.wallet.parse_status(payload)

        class Signer:
            network = "test"

            def call(inner, operation):
                test.assertEqual(operation, 5)
                if not initialized:
                    raise test.wallet.WalletError("authenticated signer transport refused")
                return b"\0" + bytes.fromhex("11" * 16) + (1).to_bytes(4, "little") + bytes(4)

        value = self.runtime.PublicRuntime.__new__(self.runtime.PublicRuntime)
        value._emitted_manifest = None
        value.module, value.protocol, value.running = self.wallet, self.wallet.protocol, True
        value.node, value.store = SimpleNamespace(rpc=RPC), Store()
        value.wallet = self.wallet.NodeWallet(RPC(), Signer(), value.store, network="test")
        return value

    def test_status_after_idle_rpc_expiry_preserves_wallet_status_and_coin_scan(self):
        # Removing the status refresh must break both the signer-observation
        # path and the coin scan used when signer observation is disabled.
        for observe in (True, False):
            with self.subTest(observe=observe):
                runtime = self.status_runtime()
                runtime.status(observe=observe)
                runtime.wallet.rpc.expired = True
                try:
                    status = runtime.dispatch("status", {}) if observe else runtime.status(observe=False)
                except BrokenPipeError as error:
                    self.fail("Status reused an idle-closed wallet RPC connection: " + str(error))
                self.assertEqual(status["wallet"]["wallet_id"], "11" * 16)
                self.assertEqual(status["wallet"]["balance_sats"], 100000000)
                self.assertEqual(status["wallet"]["next_receive"], 1)
                self.assertEqual(status["wallet"]["next_change"], 0)
                self.assertEqual(status["wallet"]["locked"], not observe)
                self.assertEqual(status["wallet"]["utxos"][0]["txid"], "22" * 32)

    def test_status_before_wallet_setup_reports_running_and_uninitialized(self):
        status = self.status_runtime(initialized=False).dispatch("status", {})
        self.assertEqual(status["phase"], "running")
        self.assertFalse(status["ready"])
        self.assertIsNone(status["wallet"]["wallet_id"])
        self.assertTrue(status["wallet"]["locked"])
        self.assertEqual(status["wallet"]["utxos"], [])

    def test_stopped_status_needs_no_wallet_or_rpc_connection(self):
        runtime = self.status_runtime(initialized=False)
        runtime.running, runtime.wallet, runtime.node = False, None, None
        status = runtime.dispatch("status", {})
        self.assertEqual(status["phase"], "stopped")
        self.assertEqual(status["nodes"], [])
        self.assertTrue(status["wallet"]["locked"])

    def response_runtime(self):
        """Real transaction dispatch and response framing over public fixtures."""
        runtime = self.runtime.PublicRuntime.__new__(self.runtime.PublicRuntime)
        runtime._emitted_manifest = None
        runtime.module, runtime.running = self.wallet, True
        runtime.store = SimpleNamespace(record=self.manifest())

        def export():
            if runtime.store.record is None:
                raise self.wallet.WalletError("public wallet not initialized")
            return copy.deepcopy(runtime.store.record)

        runtime.store.export = export
        runtime.wallet = SimpleNamespace(rpc=None)
        runtime.node = SimpleNamespace(rpc=lambda: SimpleNamespace(getrawmempool=lambda: ["22" * 32]))
        return runtime

    def transaction_response(self, runtime):
        value = runtime.response({"action": "transaction", "params": {"txid": "22" * 32}})
        self.assertEqual(set(value), {"ok", "result", "manifest"})
        self.assertTrue(value["ok"])
        self.assertTrue(value["result"]["in_mempool"])
        return value

    def test_unchanged_transaction_and_status_responses_omit_manifest(self):
        runtime = self.response_runtime()
        first = self.transaction_response(runtime)
        self.assertEqual(first["manifest"], self.manifest())
        for _ in range(3):
            response = self.transaction_response(runtime)
            self.assertIsNone(response["manifest"])
            self.assertEqual(response["result"], first["result"])
        status_runtime = self.status_runtime()
        initial = status_runtime.response({"action": "status"})
        repeated = status_runtime.response({"action": "status"})
        self.assertEqual(repeated["result"], initial["result"])
        self.assertIsNone(repeated["manifest"])

    def test_manifest_initialization_change_and_restart_resend_complete_record(self):
        runtime = self.response_runtime()
        runtime.store.record = None
        self.assertIsNone(self.transaction_response(runtime)["manifest"])
        runtime.store.record = self.manifest()
        self.assertEqual(self.transaction_response(runtime)["manifest"], self.manifest())
        self.assertIsNone(self.transaction_response(runtime)["manifest"])
        runtime.store.record["next_receive"] = 3
        changed = self.transaction_response(runtime)
        self.assertEqual(changed["manifest"], runtime.store.record)
        self.assertIsNone(self.transaction_response(runtime)["manifest"])
        # Comparing only identity/floors would hide a changed retained path.
        replacement_key = bytes([23]) * 1312
        runtime.store.record["entries"][0].update(
            public_key=replacement_key.hex(),
            program=self.wallet.protocol.key_commitment("test", replacement_key).hex())
        self.assertEqual(self.transaction_response(runtime)["manifest"], runtime.store.record)
        self.assertIsNone(self.transaction_response(runtime)["manifest"])
        restarted = self.response_runtime()
        restarted.store.record = copy.deepcopy(runtime.store.record)
        self.assertEqual(self.transaction_response(restarted)["manifest"], runtime.store.record)

    def test_failed_request_does_not_acknowledge_changed_manifest(self):
        runtime = self.response_runtime()
        self.transaction_response(runtime)
        self.assertIsNone(self.transaction_response(runtime)["manifest"])
        runtime.store.record["next_receive"] = 2
        refused = runtime.response({"action": "unknown"})
        self.assertEqual(set(refused), {"ok", "error"})
        self.assertFalse(refused["ok"])
        self.assertEqual(self.transaction_response(runtime)["manifest"], runtime.store.record)
        self.assertIsNone(self.transaction_response(runtime)["manifest"])

    def test_manifest_snapshot_distinguishes_json_types_and_returned_mutation(self):
        runtime = self.response_runtime()
        first = self.transaction_response(runtime)
        first["manifest"]["entries"].clear()
        self.assertIsNone(self.transaction_response(runtime)["manifest"])
        # Python equality equates True and 1; the wire manifest must not.
        runtime.store.record["next_receive"] = True
        response = self.transaction_response(runtime)
        self.assertIs(response["manifest"]["next_receive"], True)
        runtime.store.record["next_receive"] = 1
        self.assertIs(type(self.transaction_response(runtime)["manifest"]["next_receive"]), int)
        explicit = runtime.response({"action": "manifest"})
        self.assertEqual(explicit["result"], runtime.store.record)
        self.assertIsNone(explicit["manifest"])

    def test_delta_response_skips_unchanged_journal_writes_and_validates_changes(self):
        runtime = self.response_runtime()
        controller = self.controller.PublicController.__new__(self.controller.PublicController)
        controller._tainted = False
        controller._worker = SimpleNamespace(poll=lambda: None, stdin=io.BytesIO())
        controller.journal = {"checkpoint": {"wallet_id": "11" * 16, "generation": 1,
                              "next_receive": 1, "next_change": 0}, "manifest": None}
        saved = []
        controller._save = lambda: saved.append(copy.deepcopy(controller.journal))

        def line(*_args):
            request = json.loads(controller._worker.stdin.getvalue().splitlines()[-1])
            return json.dumps(runtime.response(request)).encode()

        controller._line = line
        params = {"txid": "22" * 32}
        first = controller._request("transaction", params)
        self.assertEqual(len(saved), 1)
        self.assertEqual(controller._request("transaction", params), first)
        self.assertEqual(len(saved), 1)
        runtime.store.record["next_receive"] = 2
        controller._request("transaction", params)
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[-1]["checkpoint"]["next_receive"], 2)
        retained = copy.deepcopy(controller.journal)
        runtime.store.record["entries"][0]["program"] = "00" * 32
        with self.assertRaisesRegex(self.controller.legacy.ConsoleError, "Public worker transport failed"):
            controller._request("transaction", params)
        self.assertTrue(controller._tainted)
        self.assertEqual(controller.journal, retained)
        self.assertEqual(len(saved), 2)

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
