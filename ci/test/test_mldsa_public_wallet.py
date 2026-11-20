# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Explicit TEST binding through real public metadata and transaction codecs."""
import copy
from decimal import Decimal
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
        value.peer_policy = None
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

    def test_status_exposes_only_validated_cached_network_active(self):
        runtime = self.status_runtime()
        runtime.peer_policy = object()
        for active in (False, True):
            with patch.object(runtime, "_maintain_peers", return_value={"network_active": active}):
                self.assertIs(runtime.status()["nodes"][0].get("network_active"), active)
        with patch.object(runtime, "_maintain_peers", return_value={"network_active": 1}):
            with self.assertRaisesRegex(ValueError, "network-active"):
                runtime.status()

    def test_fixture_without_peer_policy_reports_unknown_network_state(self):
        node = self.status_runtime().status()["nodes"][0]
        self.assertIn("network_active", node)
        self.assertIsNone(node["network_active"])

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
        runtime.peer_policy = None
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

    def test_peer_action_registers_a_maintained_exact_endpoint(self):
        calls = []

        class RPC:
            def addnode(inner, endpoint, command):
                calls.append((endpoint, command))

            def getnetworkinfo(inner):
                return {"networkactive": True}

            def getpeerinfo(inner):
                return []

            def getaddednodeinfo(inner, endpoint):
                if (endpoint, "add") not in calls:
                    from test_framework.authproxy import JSONRPCException
                    raise JSONRPCException({"code": -24, "message": "not added"})
                return [{"addednode": endpoint, "connected": False}]

        sys.path.insert(0, str(ROOT / "test/functional"))
        runtime = self.response_runtime()
        runtime.peer_policy = None
        runtime.node = SimpleNamespace(rpc=lambda **_kwargs: RPC())
        with tempfile.TemporaryDirectory(prefix="public-peer-policy-") as directory:
            runtime.state = Path(directory)
            value = runtime.dispatch("peer", {"endpoint": "127.0.0.1:23834"})
            self.assertIn(("127.0.0.1:23834", "add"), calls)
            self.assertEqual(value["peer"], "127.0.0.1:23834")

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


class PeerRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PublicNetworkTests.setUpClass()
        cls.runtime, cls.wallet, cls.key = PublicNetworkTests.runtime, PublicNetworkTests.wallet, PublicNetworkTests.key
        sys.path.insert(0, str(ROOT / "test/functional"))
        from test_framework.authproxy import JSONRPCException
        cls.RPCError = JSONRPCException

    manifest = PublicNetworkTests.manifest

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-peer-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.clock = [100.0]
        self.endpoint = "127.0.0.1:23834"
        self.calls, self.timeouts, self.added, self.peers = [], [], set(), []
        self.active, self.missing_once, self.add_error, self.onetry_timeout = True, False, None, False
        self.added_override = None
        self.raw, self.decoded_txid, self.sent_txid = "0100", "22" * 32, "22" * 32
        self.known, self.send_timeout = True, False
        test = self

        class RPC:
            def getnetworkinfo(inner):
                test.calls.append(("getnetworkinfo",))
                return {"networkactive": test.active}

            def getpeerinfo(inner):
                test.calls.append(("getpeerinfo",))
                return copy.deepcopy(test.peers)

            def getaddednodeinfo(inner, endpoint):
                test.calls.append(("getaddednodeinfo", endpoint))
                if test.added_override is not None:
                    return copy.deepcopy(test.added_override)
                if test.missing_once:
                    test.missing_once = False
                    raise test.RPCError({"code": -24, "message": "not added"})
                if endpoint not in test.added:
                    raise test.RPCError({"code": -24, "message": "not added"})
                connected = any(p["addr"] == endpoint for p in test.peers)
                value = {"addednode": endpoint, "connected": connected}
                if connected:
                    value["addresses"] = [{"address": endpoint, "connected": "outbound"}]
                return [value]

            def addnode(inner, endpoint, command):
                test.calls.append(("addnode", endpoint, command))
                if command == "add":
                    if test.add_error is not None:
                        raise test.RPCError({"code": test.add_error, "message": "registration refused"})
                    if endpoint in test.added:
                        raise test.RPCError({"code": -23, "message": "already added"})
                    test.added.add(endpoint)
                elif test.onetry_timeout:
                    # AuthServiceProxy wraps read-timeouts with code -344.
                    raise test.RPCError({"code": -344, "message": "known peer attempt may be underway"})

            def setnetworkactive(inner, value):
                test.calls.append(("setnetworkactive", value))
                test.active = value
                if not value:
                    test.peers.clear()
                return value

            def getmempoolentry(inner, txid):
                test.calls.append(("getmempoolentry", txid))
                if not test.known:
                    raise test.RPCError({"code": -5, "message": "not in mempool"})
                return {"vsize": 2}

            def getrawtransaction(inner, txid, verbose):
                test.calls.append(("getrawtransaction", txid, verbose))
                return test.raw

            def decoderawtransaction(inner, raw):
                test.calls.append(("decoderawtransaction", raw))
                return {"txid": test.decoded_txid}

            def sendrawtransaction(inner, raw):
                test.calls.append(("sendrawtransaction", raw))
                if test.send_timeout:
                    raise TimeoutError("broadcast acknowledgment uncertain")
                return test.sent_txid

        self.rpc = RPC()
        self.value = self.new_runtime()

    def new_runtime(self):
        value = PublicNetworkTests.response_runtime(self)
        value.state, value.bootstrap = self.state, False
        value.signer = SimpleNamespace(network="test")
        value.store.network = "test"

        def rpc(*, timeout=90):
            self.timeouts.append(timeout)
            return self.rpc

        def start(reindex=False, *, network_active=True):
            self.calls.append(("node_start", reindex, network_active))
            self.added.clear()
            self.active = network_active

        value.node = SimpleNamespace(rpc=rpc, start=start, stop=lambda: self.calls.append(("node_stop",)))
        return value

    def ready_peer(self, *, relay=True, version=70016):
        return {"addr": self.endpoint, "version": version, "relaytxes": relay, "connection_type": "manual", "pingtime": Decimal("0.001")}

    def test_policy_persists_exact_endpoints_and_network_partition(self):
        policy = self.runtime.PeerPolicy(self.state)
        policy.save(endpoint=self.endpoint, network_active=False)
        self.assertEqual((self.state / "peer-policy.json").stat().st_mode & 0o777, 0o600)
        self.assertFalse((self.state / "peer-policy.tmp").exists())
        reopened = self.runtime.PeerPolicy(self.state)
        self.assertEqual(reopened.record["endpoints"], [self.endpoint])
        self.assertIs(reopened.record["network_active"], False)
        reopened.save(endpoint=self.endpoint)
        self.assertEqual(reopened.record, policy.record)

    def test_endpoint_policy_rejects_credentials_aliases_duplicates_and_bounds(self):
        for endpoint in ("http://127.0.0.1:23834", "user:pass@host:23834", "127.0.0.1:023834", "127.00.0.1:23834",
                         "localhost:443", "HOST:23834", "host:23834/path", "host:23834?token=x", "-host:23834", "host:65536"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.runtime.peer_endpoint(endpoint)
        policy = self.runtime.PeerPolicy(self.state)
        for port in range(23834, 23838):
            policy.save(endpoint="127.0.0.1:" + str(port))
        with self.assertRaisesRegex(ValueError, "bounds"):
            policy.save(endpoint="127.0.0.1:23838")
        bad = copy.deepcopy(policy.record)
        bad["endpoints"] = [self.endpoint, self.endpoint]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            policy.validate(bad)
        for field, value in (("network_active", 0), ("network", "regtest"), ("endpoints", {}), ("profile_sha256", "00" * 32)):
            bad = {**policy.record, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.validate(bad)

    def test_policy_refuses_symlink_wrong_mode_duplicate_json_and_interrupted_write(self):
        path = self.state / "peer-policy.json"
        path.symlink_to(self.state / "missing")
        with self.assertRaises(OSError):
            self.runtime.PeerPolicy(self.state)
        path.unlink()
        path.write_text("{}", encoding="utf8")
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.runtime.PeerPolicy(self.state)
        path.chmod(0o600)
        path.write_text('{"schema":1,"schema":2}', encoding="utf8")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.runtime.PeerPolicy(self.state)
        path.unlink()
        policy = self.runtime.PeerPolicy(self.state)
        with patch.object(self.runtime.os, "fsync", side_effect=OSError("fixture durable-write failure")):
            with self.assertRaises(OSError):
                policy.save(endpoint=self.endpoint)
        self.assertTrue(policy.poisoned)
        self.assertTrue((self.state / "peer-policy.tmp").exists())
        with self.assertRaisesRegex(ValueError, "requires recovery"):
            policy.save(endpoint=self.endpoint)
        reopened = self.runtime.PeerPolicy(self.state)
        self.assertIs(reopened.record["network_active"], False)
        self.assertEqual(reopened.record["endpoints"], [])
        self.assertFalse((self.state / "peer-policy.tmp").exists())

    def test_partial_peer_orphan_preserves_bytes_and_only_canonical_endpoints(self):
        for active in (None, True, False):
            with self.subTest(canonical_network_active=active), tempfile.TemporaryDirectory(prefix="peer-orphan-") as state:
                directory = Path(state)
                if active is not None:
                    policy = self.runtime.PeerPolicy(directory)
                    policy.save(endpoint=self.endpoint, network_active=active)
                canonical = directory / "peer-policy.json"
                prior = canonical.read_bytes() if canonical.exists() else None
                partial = b'{"endpoints":["127.0.0.1:29999"],"uncertain":'
                marker = directory / "peer-policy.tmp"
                marker.write_bytes(partial)
                marker.chmod(0o600)
                recovered = self.runtime.PeerPolicy(directory)
                self.assertIs(recovered.record["network_active"], False)
                self.assertEqual(recovered.record["endpoints"], [self.endpoint] if active is not None else [])
                self.assertFalse(marker.exists())
                evidence = list(directory.glob("peer-policy.orphan-*"))
                self.assertEqual(len(evidence), 1)
                self.assertEqual(evidence[0].stat().st_mode & 0o777, 0o700)
                self.assertEqual((evidence[0] / "peer-policy.tmp").read_bytes(), partial)
                if prior is not None:
                    self.assertEqual((evidence[0] / "peer-policy.json").read_bytes(), prior)
                self.assertEqual(self.runtime.PeerPolicy(directory).record, recovered.record)
                self.assertEqual(len(list(directory.glob("peer-policy.orphan-*"))), 1)

    def test_peer_orphan_recovery_requires_off_fsync_before_marker_quarantine(self):
        policy = self.runtime.PeerPolicy(self.state)
        policy.save(endpoint=self.endpoint)
        marker = self.state / "peer-policy.tmp"
        marker.write_bytes(b"partial public endpoint intent")
        marker.chmod(0o600)
        replaced, synced = [False], [False]
        replace, rename, sync = self.runtime.os.replace, self.runtime.os.rename, self.runtime.os.fsync
        def observe_replace(source, destination, *args, **kwargs):
            result = replace(source, destination, *args, **kwargs)
            if Path(destination) == policy.path:
                replaced[0] = True
            return result
        def observe_sync(fd):
            result = sync(fd)
            if replaced[0] and os.fstat(fd).st_ino == self.state.stat().st_ino:
                synced[0] = True
            return result
        def observe_rename(source, destination, *args, **kwargs):
            if Path(source) == marker:
                self.assertTrue(replaced[0] and synced[0], "Marker archived before durable network-off")
                self.assertIs(json.loads(policy.path.read_bytes())["network_active"], False)
            return rename(source, destination, *args, **kwargs)
        with patch.object(self.runtime.os, "replace", side_effect=observe_replace), \
                patch.object(self.runtime.os, "fsync", side_effect=observe_sync), \
                patch.object(self.runtime.os, "rename", side_effect=observe_rename):
            self.runtime.PeerPolicy(self.state)
        self.assertTrue(synced[0])

    def test_peer_orphan_unsafe_canonical_or_temp_and_recovery_failure_retain_marker(self):
        policy = self.runtime.PeerPolicy(self.state)
        policy.save(endpoint=self.endpoint)
        original = policy.path.read_bytes()
        marker = self.state / "peer-policy.tmp"
        marker.write_bytes(b"partial public peer intent")
        marker.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.runtime.PeerPolicy(self.state)
        marker.chmod(0o600)
        policy.path.write_bytes(b"malformed canonical policy")
        with self.assertRaises(ValueError):
            self.runtime.PeerPolicy(self.state)
        self.assertTrue(marker.exists())
        policy.path.write_bytes(original)
        with patch.object(self.runtime.os, "replace", side_effect=OSError("recovery commit failed")):
            with self.assertRaises(OSError):
                self.runtime.PeerPolicy(self.state)
        self.assertTrue(marker.exists())
        self.assertEqual(policy.path.read_bytes(), original)

    def test_peer_orphan_archive_failure_retains_marker_after_durable_off(self):
        policy = self.runtime.PeerPolicy(self.state)
        policy.save(endpoint=self.endpoint)
        marker = self.state / "peer-policy.tmp"
        marker.write_bytes(b"partial public peer intent")
        marker.chmod(0o600)
        archived, failed = [False], [False]
        rename, sync = self.runtime.os.rename, self.runtime.os.fsync
        def observe_rename(source, destination, *args, **kwargs):
            result = rename(source, destination, *args, **kwargs)
            archived[0] = Path(source) == marker
            return result
        def fail_archive_sync(fd):
            if archived[0] and not failed[0]:
                failed[0] = True
                raise OSError("fixture archive sync failed")
            return sync(fd)
        with patch.object(self.runtime.os, "rename", side_effect=observe_rename), \
                patch.object(self.runtime.os, "fsync", side_effect=fail_archive_sync):
            with self.assertRaises(OSError):
                self.runtime.PeerPolicy(self.state)
        self.assertTrue(marker.exists())
        self.assertIs(json.loads(policy.path.read_bytes())["network_active"], False)
        self.assertIs(self.runtime.PeerPolicy(self.state).record["network_active"], False)

    def test_peer_orphan_symlink_or_hardlink_is_never_reconciled(self):
        policy = self.runtime.PeerPolicy(self.state)
        policy.save(endpoint=self.endpoint)
        marker = self.state / "peer-policy.tmp"
        marker.symlink_to(policy.path)
        with self.assertRaises(OSError):
            self.runtime.PeerPolicy(self.state)
        self.assertTrue(marker.is_symlink())
        marker.unlink()
        marker.write_bytes(b"partial public peer intent")
        marker.chmod(0o600)
        os.link(marker, self.state / "extra-link")
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.runtime.PeerPolicy(self.state)
        self.assertTrue(marker.exists())
        self.assertTrue(json.loads(policy.path.read_bytes())["network_active"])

    def test_policy_refuses_hardlinks_oversize_and_foreign_owner(self):
        policy = self.runtime.PeerPolicy(self.state)
        policy.save(endpoint=self.endpoint)
        path = self.state / "peer-policy.json"
        os.link(path, self.state / "extra-link")
        with self.assertRaisesRegex(ValueError, "ownership"):
            self.runtime.PeerPolicy(self.state)
        (self.state / "extra-link").unlink()
        original = self.runtime.os.fstat
        def foreign(fd):
            info = original(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1, st_nlink=info.st_nlink, st_size=info.st_size)
        with patch.object(self.runtime.os, "fstat", side_effect=foreign):
            with self.assertRaisesRegex(ValueError, "ownership"):
                self.runtime.PeerPolicy(self.state)
        path.write_bytes(b" " * 4097)
        with self.assertRaisesRegex(ValueError, "size"):
            self.runtime.PeerPolicy(self.state)

    def test_peer_status_is_wallet_free_and_counts_only_ready_transaction_peers(self):
        self.value.dispatch("peer", {"endpoint": self.endpoint})
        for peer in (self.ready_peer(relay=False), self.ready_peer(version=0), self.ready_peer()):
            self.peers[:] = [peer]
            evidence = self.value.dispatch("peer_status", {})
            self.assertEqual(evidence["peers"], 1)
            self.assertEqual(evidence["transaction_peers"], int(peer["relaytxes"] and peer["version"] > 0))
        self.assertTrue(all(0 < timeout <= self.runtime.PEER_RPC_SECONDS for timeout in self.timeouts))

    def test_version_and_relay_without_completed_ping_are_not_ready(self):
        self.value.dispatch("peer", {"endpoint": self.endpoint})
        peer = self.ready_peer()
        peer.pop("pingtime", None)
        self.peers[:] = [peer]
        self.assertEqual(self.value.dispatch("peer_status", {})["transaction_peers"], 0)
        for ping in (None, 0, -1, True, "0.001", float("inf"), Decimal("NaN"), Decimal("Infinity"), 61):
            peer["pingtime"] = ping
            self.peers[:] = [peer]
            self.assertEqual(self.value.dispatch("peer_status", {})["transaction_peers"], 0)

    def test_retry_cadence_and_known_onetry_timeout_remain_bounded(self):
        self.onetry_timeout = True
        with patch.object(self.runtime.time, "monotonic", side_effect=lambda: self.clock[0]):
            evidence = self.value.dispatch("peer", {"endpoint": self.endpoint})
            self.assertEqual(evidence["maintenance"]["uncertain_endpoints"], [self.endpoint])
            for now in (100.1, 102.1, 104.2):
                self.clock[0] = now
                self.value.dispatch("peer_status", {})
            self.assertEqual(self.calls.count(("addnode", self.endpoint, "onetry")), 1)
            self.clock[0] = 105.1
            self.value.dispatch("peer_status", {})
            self.assertEqual(self.calls.count(("addnode", self.endpoint, "onetry")), 1)
            self.clock[0] = 106.3
            self.value.dispatch("peer_status", {})
            self.assertEqual(self.calls.count(("addnode", self.endpoint, "onetry")), 2)

    def test_peer_maintenance_stops_at_its_total_operation_budget(self):
        network, peers = self.rpc.getnetworkinfo, self.rpc.getpeerinfo
        def delayed_network():
            self.clock[0] += 1.1
            return network()
        def delayed_peers():
            self.clock[0] += 1.1
            return peers()
        with patch.object(self.runtime.time, "monotonic", side_effect=lambda: self.clock[0]), \
                patch.object(self.rpc, "getnetworkinfo", side_effect=delayed_network), \
                patch.object(self.rpc, "getpeerinfo", side_effect=delayed_peers):
            with self.assertRaisesRegex(ValueError, "public peer operation deadline"):
                self.value.dispatch("peer", {"endpoint": self.endpoint})
        self.assertEqual(self.calls, [("getnetworkinfo",), ("getpeerinfo",)])
        self.assertTrue(all(timeout <= self.runtime.PEER_RPC_SECONDS for timeout in self.timeouts))

    def test_native_and_durable_network_off_suppress_all_reconnects(self):
        self.active = False
        self.value.dispatch("peer", {"endpoint": self.endpoint})
        evidence = self.value.dispatch("peer_status", {})
        self.assertEqual(evidence["maintenance"]["suppressed"], "NETWORK_INACTIVE")
        self.assertFalse(any(row[0] == "addnode" for row in self.calls))
        self.value.dispatch("network", {"active": False})
        replacement = self.new_runtime()
        replacement.running = False
        with patch.object(replacement, "status", return_value={"started": True}):
            replacement.start()
        self.assertFalse(self.active)
        self.assertIn(("node_start", False, False), self.calls)
        self.assertFalse(any(row[0] == "addnode" for row in self.calls))

    def test_start_reindex_and_worker_replacement_reapply_persisted_endpoint(self):
        self.value.dispatch("peer", {"endpoint": self.endpoint})
        replacement = self.new_runtime()
        replacement.running = False
        with patch.object(replacement, "status", return_value={"started": True}):
            replacement.start()
            replacement.dispatch("reindex", {})
        self.assertIn(self.endpoint, self.added)
        self.assertEqual(self.calls.count(("addnode", self.endpoint, "add")), 3)
        self.assertEqual([row for row in self.calls if row[0] == "node_start"], [("node_start", False, True), ("node_start", True, True)])

    def test_duplicate_add_requires_exact_query_and_other_errors_are_preserved(self):
        self.added.add(self.endpoint)
        self.missing_once = True
        value = self.value.dispatch("peer", {"endpoint": self.endpoint})
        self.assertTrue(value["registered"])
        self.added.clear()
        self.add_error = -8
        with self.assertRaises(self.RPCError) as caught:
            self.value.dispatch("peer", {"endpoint": self.endpoint})
        self.assertEqual(caught.exception.error["code"], -8)
        self.add_error = -23
        with self.assertRaisesRegex(ValueError, "not proved"):
            self.value.dispatch("peer", {"endpoint": self.endpoint})
        self.added_override = [{"addednode": "127.0.0.1:23835", "connected": False}]
        with self.assertRaisesRegex(ValueError, "exact maintained"):
            self.value.dispatch("peer", {"endpoint": self.endpoint})

    def test_rebroadcast_requires_known_same_transaction_without_wallet_issuance(self):
        before = copy.deepcopy(self.value.store.record)
        value = self.value.dispatch("rebroadcast", {"txid": "22" * 32})
        self.assertEqual(value["txid"], "22" * 32)
        self.assertIs(value["known_in_mempool"], True)
        self.assertIs(value["reissued_payment"], False)
        self.assertEqual([row[0] for row in self.calls], ["getmempoolentry", "getrawtransaction", "decoderawtransaction", "sendrawtransaction"])
        self.assertEqual(self.value.store.record, before)
        self.assertTrue(all(timeout <= self.runtime.PEER_RPC_SECONDS for timeout in self.timeouts))

    def test_rebroadcast_refuses_unknown_invalid_or_changed_transaction_and_never_retries_timeout(self):
        for txid in (None, True, "22" * 31, "AA" * 32, "gg" * 32):
            with self.subTest(txid=txid), self.assertRaises(ValueError):
                self.value.dispatch("rebroadcast", {"txid": txid})
        self.assertEqual(self.calls, [])
        self.known = False
        with self.assertRaises(self.RPCError):
            self.value.dispatch("rebroadcast", {"txid": "22" * 32})
        self.assertFalse(any(row[0] == "sendrawtransaction" for row in self.calls))
        self.known = True
        for raw in (None, "x1", "0", "AB", "00" * 1000001):
            self.raw = raw
            with self.subTest(raw_type=type(raw).__name__), self.assertRaisesRegex(ValueError, "transaction bytes"):
                self.value.dispatch("rebroadcast", {"txid": "22" * 32})
        self.raw = "0100"
        self.known, self.decoded_txid = True, "33" * 32
        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.value.dispatch("rebroadcast", {"txid": "22" * 32})
        self.assertFalse(any(row[0] == "sendrawtransaction" for row in self.calls))
        self.decoded_txid, self.send_timeout = "22" * 32, True
        with self.assertRaises(TimeoutError):
            self.value.dispatch("rebroadcast", {"txid": "22" * 32})
        self.assertEqual(self.calls.count(("sendrawtransaction", self.raw)), 1)


class PublicAppPeerRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("public_app_peer_ci", ROOT / "contrib/ml-dsa-qualification/run_public_app_ci.py")
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)

    def test_peer_wait_requires_transaction_readiness_inside_one_deadline(self):
        self.assertTrue(callable(getattr(self.runner, "wait_transaction_peers", None)), "Native peer recovery readiness wait missing")
        clock, samples = [10.0], [0]
        def action(name, params=None, *, include_status=True):
            self.assertEqual((name, params, include_status), ("peer_status", None, False))
            samples[0] += 1
            return {"result": {"network_active": True, "transaction_peers": int(samples[0] >= 2), "peers": 1}}
        with patch.object(self.runner.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(self.runner.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            result = self.runner.wait_transaction_peers([SimpleNamespace(action=action)], 11.0)
        self.assertEqual(result[0]["transaction_peers"], 1)
        self.assertGreaterEqual(samples[0], 2)
        self.assertLess(clock[0], 11.0)

    def test_peer_wait_cannot_restart_an_expired_budget(self):
        clock, calls = [10.0], []
        def action(*args, **kwargs):
            calls.append((args, kwargs))
            clock[0] += 0.6
            return {"result": {"network_active": True, "transaction_peers": 0}}
        with patch.object(self.runner.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(self.runner.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaisesRegex(ValueError, "deadline"):
                self.runner.wait_transaction_peers([SimpleNamespace(action=action)], 11.0)
        self.assertEqual(len(calls), 2)

    def test_disconnect_receipt_is_bound_to_exact_scoped_endpoint_and_old_node_id(self):
        endpoint = "172.17.0.3:23833"
        record = {"endpoint": endpoint, "matches": [], "disconnected_node_id": 7, "old_peer_absent": True}
        calls = []
        def invoke(*args, **kwargs):
            calls.append((args, kwargs))
            return json.dumps(record).encode()
        controller = SimpleNamespace(_invoke=invoke)
        deadline = self.runner.time.monotonic() + 1
        self.assertEqual(self.runner.native_peer(controller, endpoint, deadline, disconnect=True), record)
        self.assertEqual(calls[0][0][0], "1001:1000")
        self.assertIn(endpoint, calls[0][0])
        self.assertIn("disconnect", calls[0][0])
        record["matches"] = [{"id": 7, "addr": endpoint}]
        with self.assertRaisesRegex(ValueError, "not proved"):
            self.runner.native_peer(controller, endpoint, deadline, disconnect=True)
        record["matches"] = [{"id": 8, "addr": "172.17.0.9:23833"}]
        with self.assertRaisesRegex(ValueError, "Exact native peer"):
            self.runner.native_peer(controller, endpoint, deadline, disconnect=True)

    def test_known_reannouncement_refuses_identity_or_floor_changes(self):
        self.assertTrue(callable(getattr(self.runner, "reannounce_known", None)), "Same-transaction recovery helper missing")
        point = {"wallet_id": "11" * 16, "generation": 1, "next_receive": 3, "next_change": 2}
        receipt = {"txid": "22" * 32, "known_in_mempool": True, "rebroadcast": True, "reissued_payment": False}
        controller = SimpleNamespace(journal={"checkpoint": point})
        def action(name, params, *, include_status=True):
            self.assertEqual((name, params, include_status), ("rebroadcast", {"txid": "22" * 32}, False))
            return {"result": receipt}
        controller.action = action
        deadline = self.runner.time.monotonic() + 1
        self.assertEqual(self.runner.reannounce_known(controller, "22" * 32, deadline), receipt)
        receipt["txid"] = "33" * 32
        with self.assertRaisesRegex(ValueError, "identity"):
            self.runner.reannounce_known(controller, "22" * 32, deadline)
        receipt["txid"] = "22" * 32
        def changes_floor(*args, **kwargs):
            result = action(*args, **kwargs)
            point["next_change"] += 1
            return result
        controller.action = changes_floor
        with self.assertRaisesRegex(ValueError, "floor|checkpoint"):
            self.runner.reannounce_known(controller, "22" * 32, deadline)


if __name__ == "__main__":
    unittest.main()
