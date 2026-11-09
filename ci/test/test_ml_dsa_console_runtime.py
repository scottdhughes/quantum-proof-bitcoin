#!/usr/bin/env python3
"""Console policy tests; only native RPC and signer transport are fixtures."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/functional"))
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-signer"))
import node_wallet  # noqa: E402
from test_framework.messages import CTransaction  # noqa: E402


class SignerFixture:
    """External signer response fixture. No private keys or native code."""
    def __init__(self):
        self.available = True
        self.locked = False
        self.counters = [0, 0]
        self.keys = {}
        self.calls = []

    def call(self, kind, body=b""):
        self.calls.append(kind)
        if not self.available:
            raise node_wallet.WalletError("authenticated signer transport refused")
        if kind == 5:
            return bytes([self.locked]) + b"\x11" * 16 + b"".join(n.to_bytes(4, "little") for n in self.counters)
        if kind == 2:
            if self.locked:
                raise node_wallet.WalletError("signer locked")
            branch = body[0]
            index = self.counters[branch]
            key = bytes([1 + index + branch * 100]) * 1312
            self.keys[branch, index] = key
            self.counters[branch] += 1
            return bytes([branch]) + index.to_bytes(4, "little") + key + node_wallet.protocol.key_commitment("regtest", key)
        if kind == 3:
            # Real IPC decode proves runtime/NodeWallet preserve exact amounts,
            # paths and transaction construction through the transport boundary.
            request = node_wallet.ipc_v1.decode_sign_request(body)
            self.last_request = request
            paths = request[2]
            return bytes([len(paths)]) + b"".join(b"\x42" * 2420 + self.keys[tuple(path)] for path in paths)
        if kind == 4:
            self.locked = True
            return b""
        raise AssertionError(kind)


class RPCFixture:
    def __init__(self):
        self.height = 101
        self.coins = {}
        self.pool = {}
        self.broadcasts = []
        self.submissions = []
        genesis = "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"
        self.blocks = ["00" * 80]
        previous = genesis
        for n in range(1, 102):
            header = b"\x01\0\0\0" + bytes.fromhex(previous)[::-1] + bytes([n]) * 44
            self.blocks.append(header.hex())
            previous = hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()

    def getblockchaininfo(self):
        return {"chain": "regtest", "blocks": self.height, "valueless_mldsa44_demo": {
            "scope": "VALUELESS_EXPERIMENTAL_REGTEST_ONLY", "active": self.height >= 1,
            "activation_height": 1, "network_binding": node_wallet.protocol.binding("regtest").hex(),
            "spec_sha256": node_wallet.SPEC}}

    def getblockcount(self):
        return self.height

    def getbestblockhash(self):
        return self.getblockhash(self.height)

    def getblockhash(self, height):
        if height == 0:
            return "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"
        return hashlib.sha256(hashlib.sha256(bytes.fromhex(self.blocks[height])[:80]).digest()).digest()[::-1].hex()

    def getblock(self, blockhash, verbosity=1):
        index = next(i for i in range(self.height + 1) if self.getblockhash(i) == blockhash)
        if verbosity == 0:
            return self.blocks[index]
        return {"tx": [{"txid": "55" * 32, "vout": [{"n": 0, "value": node_wallet.Decimal("50"),
            "scriptPubKey": {"hex": "51"}}]}]}

    def getpeerinfo(self):
        return [{}]

    def gettxoutsetinfo(self):
        return {"bestblock": self.getbestblockhash(), "hash_serialized_3": "aa" * 32, "txouts": len(self.coins)}

    def scantxoutset(self, action, descriptors):
        wanted = {item["desc"][4:-1] for item in descriptors}
        return {"success": True, "height": self.height, "unspents": [dict(item) for item in self.coins.values()
            if item["scriptPubKey"] in wanted and item["height"] > 0]}

    def gettxout(self, txid, vout, include_mempool=True):
        assert include_mempool is True
        item = self.coins.get((txid, vout))
        if item is None or item.get("spent"):
            return None
        confirmations = self.height - item["height"] + 1 if item["height"] else 0
        return {"bestblock": self.getbestblockhash(), "confirmations": confirmations,
            "value": item["amount"], "scriptPubKey": {"hex": item["scriptPubKey"]},
            "coinbase": item.get("coinbase", False)}

    def decoderawtransaction(self, raw):
        tx = CTransaction()
        tx.deserialize(io.BytesIO(bytes.fromhex(raw)))
        return {"version": tx.version, "locktime": tx.nLockTime,
            "vin": [{"txid": f"{entry.prevout.hash:064x}", "vout": entry.prevout.n,
                "sequence": entry.nSequence, "scriptSig": {"hex": entry.scriptSig.hex()}} for entry in tx.vin],
            "vout": [{"n": i, "value": node_wallet.Decimal(entry.nValue) / 100000000,
                "scriptPubKey": {"hex": entry.scriptPubKey.hex()}} for i, entry in enumerate(tx.vout)]}

    def testmempoolaccept(self, raws):
        tx = CTransaction()
        tx.deserialize(io.BytesIO(bytes.fromhex(raws[0])))
        return [{"allowed": True, "txid": tx.txid_hex}]

    def sendrawtransaction(self, raw):
        tx = self.decoderawtransaction(raw)
        transaction = CTransaction()
        transaction.deserialize(io.BytesIO(bytes.fromhex(raw)))
        txid = transaction.txid_hex
        for entry in tx["vin"]:
            self.coins[entry["txid"], entry["vout"]]["spent"] = True
        self.pool[txid] = tx
        for entry in tx["vout"]:
            self.coins[txid, entry["n"]] = {"txid": txid, "vout": entry["n"], "height": 0,
                "amount": entry["value"], "scriptPubKey": entry["scriptPubKey"]["hex"]}
        self.broadcasts.append(raw)
        return txid

    def getrawmempool(self):
        return list(self.pool)

    def getrawtransaction(self, txid, verbose=True):
        return self.pool[txid]

    def submitblock(self, raw):
        self.submissions.append(raw)
        self.blocks.append(raw)
        self.height += 1
        return None

    def generatetodescriptor(self, count, descriptor):
        assert descriptor == "raw(51)"
        mined = []
        for _ in range(count):
            header = b"\x01\0\0\0" + bytes.fromhex(self.getbestblockhash())[::-1] + b"\x77" * 44
            self.blocks.append(header.hex())
            self.height += 1
            mined.append(self.getbestblockhash())
        for coin in self.coins.values():
            if coin["height"] == 0:
                coin["height"] = self.height
        self.pool.clear()
        return mined

    def generateblock(self, descriptor, raws):
        assert descriptor == "raw(51)"
        for raw in raws:
            self.sendrawtransaction(raw)
        return {"hash": self.generatetodescriptor(1, descriptor)[0]}


class NodeFixture:
    def __init__(self, rpc, name="node0"):
        self.connection = rpc
        self.name = name

    def rpc(self):
        return self.connection


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / "contrib/ml-dsa-console/runtime.py"
        self.assertTrue(path.exists(), "runtime implementation missing")
        spec = importlib.util.spec_from_file_location("console_runtime", path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory(prefix="mldsa-console-test-")
        self.addCleanup(self.temp.cleanup)
        self.rpc = RPCFixture()
        self.signer = SignerFixture()
        self.runtime = self.module.Runtime(ROOT, ROOT / "build", Path(self.temp.name) / "state", "/tmp/public.sock", 1000,
            signer=self.signer, nodes=[NodeFixture(self.rpc), NodeFixture(self.rpc, "node1")])
        self.addCleanup(lambda: self.runtime.close() if self.runtime is not None else None)

    def receive(self):
        return self.runtime.dispatch("receive", {})

    def coin(self, entry, txid="22" * 32, amount="0.02000000", height=101, **kwargs):
        self.rpc.coins[txid, 0] = {"txid": txid, "vout": 0, "amount": node_wallet.Decimal(amount),
            "height": height, "scriptPubKey": entry["script_pubkey"], **kwargs}

    def test_chain_only_status_does_not_initialize_store_and_import_precedes_observation(self):
        self.signer.available = False
        status = self.runtime.dispatch("status", {})
        self.assertEqual(status["nodes"][0]["height"], 101)
        self.assertIsNone(status["wallet"]["wallet_id"])
        self.assertIsNone(self.runtime.manifest())
        self.signer.available = True
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            with node_wallet.PublicStore(directory) as store:
                store.observe_status(self.signer.call(5))
                manifest = store.export()
        self.runtime.dispatch("import_manifest", {"manifest": manifest})
        self.assertEqual(self.runtime.manifest(), manifest)

    def test_manifest_never_contacts_signer(self):
        self.receive()
        self.signer.available = False
        before = len(self.signer.calls)
        result = self.runtime.dispatch("manifest", {})
        self.assertEqual(result["next_receive"], 1)
        self.assertEqual(len(self.signer.calls), before)

    def test_scan_excludes_mempool_spent_and_immature_inputs_from_spendable(self):
        entry = self.receive()
        self.coin(entry)
        self.coin(entry, txid="33" * 32, amount="0.03000000", spent=True)
        self.coin(entry, txid="44" * 32, amount="50", coinbase=True, height=100)
        result = self.runtime.dispatch("status", {})["wallet"]
        self.assertEqual(result["balance_sats"], 5002000000)
        self.assertEqual(result["spendable_sats"], 2000000)
        self.assertEqual(len(result["utxos"]), 2)

    def test_send_validates_address_amount_fee_and_funds_before_reserving_change(self):
        entry = self.receive()
        self.coin(entry)
        original = self.runtime.manifest()
        for params in ({"address": "invalid", "amount_sats": 10},
                       {"address": entry["address"], "amount_sats": True},
                       {"address": entry["address"], "amount_sats": 0},
                       {"address": entry["address"], "amount_sats": 10, "fee_sats": 20001},
                       {"address": entry["address"], "amount_sats": 2000000}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.runtime.dispatch("send", params)
            self.assertEqual(self.runtime.manifest(), original)
        self.assertEqual(self.rpc.broadcasts, [])

    def test_send_uses_real_node_wallet_and_exact_amounts_broadcasts_without_mining(self):
        entry = self.receive()
        self.coin(entry)
        result = self.runtime.dispatch("send", {"address": entry["address"], "amount_sats": 1000001, "fee_sats": 1234})
        self.assertTrue(result["broadcast"])
        self.assertEqual(self.rpc.height, 101)
        self.assertEqual(len(self.rpc.broadcasts), 1)
        decoded = self.rpc.decoderawtransaction(self.rpc.broadcasts[0])
        self.assertEqual([v["value"] for v in decoded["vout"]], [node_wallet.Decimal("0.01000001"), node_wallet.Decimal("0.00998765")])
        self.assertEqual(decoded["vin"][0]["txid"], "22" * 32)
        self.assertEqual(self.runtime.manifest()["next_change"], 1)
        wallet = self.runtime.dispatch("status", {})["wallet"]
        self.assertEqual(wallet["spendable_sats"], 0)
        self.assertEqual(wallet["pending_sats"], 1998766)

    def test_exact_spend_does_not_consume_a_change_address(self):
        entry = self.receive()
        self.coin(entry)
        self.runtime.dispatch("send", {"address": entry["address"], "amount_sats": 1999000})
        self.assertEqual(self.runtime.manifest()["next_change"], 0)
        self.assertEqual(len(self.rpc.decoderawtransaction(self.rpc.broadcasts[0])["vout"]), 1)

    def test_json_envelope_preserves_manifest_and_contains_no_decimal_values(self):
        entry = self.receive()
        self.coin(entry)
        result = self.runtime.response({"action": "status", "params": {}})
        encoded = json.dumps(result)
        self.assertTrue(result["ok"])
        self.assertEqual(result["manifest"]["next_receive"], 1)
        self.assertNotIn("public_key", json.dumps(result["result"]["wallet"]))
        self.assertIn('"balance_sats": 2000000', encoded)

    def test_chain_export_import_enforces_identity_prefix_bounds_before_replay(self):
        exported = self.runtime.dispatch("export_chain", {})
        self.assertEqual(len(exported["blocks"]), 101)
        self.assertEqual(exported["tip"], self.rpc.getbestblockhash())
        original = list(self.rpc.blocks)
        # Existing chain is a validated prefix. Importing the same snapshot is idempotent.
        self.runtime.dispatch("import_chain", exported)
        self.assertEqual(self.rpc.submissions, [])
        for change in ({"genesis": "00" * 32}, {"tip": "00" * 32}, {"blocks": ["00"]}, {"blocks": ["ab" * 80] * 5001}):
            with self.subTest(change=next(iter(change))), self.assertRaises(ValueError):
                self.runtime.dispatch("import_chain", {**exported, **change})
            self.assertEqual(self.rpc.blocks, original)

    def test_wallet_identity_mismatch_is_not_reported_as_disconnected_signer(self):
        self.receive()
        original = self.signer.call
        self.signer.call = lambda kind, body=b"": b"\0" + b"\x22" * 16 + b"\x01\0\0\0" + b"\0" * 4 if kind == 5 else original(kind, body)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.runtime.dispatch("status", {})

    def test_status_reports_real_node_utxo_inventory_for_independent_comparison(self):
        self.receive()
        result = self.runtime.dispatch("status", {})
        self.assertEqual(result["nodes"][0].get("utxo_hash"), "aa" * 32)
        self.assertEqual(result["nodes"][0].get("utxo_count"), 0)

    def test_import_rejects_broken_header_link_before_replaying_any_block(self):
        exported = self.runtime.dispatch("export_chain", {})
        exported["blocks"][0] = "01" * 80
        with self.assertRaisesRegex(ValueError, "header.*link"):
            self.runtime.dispatch("import_chain", exported)
        self.assertEqual(self.rpc.submissions, [])

    def test_import_replays_only_missing_blocks_to_each_node(self):
        exported = self.runtime.dispatch("export_chain", {})
        second = RPCFixture()
        self.runtime.nodes[1] = NodeFixture(second, "node1")
        for rpc in (self.rpc, second):
            rpc.blocks.pop()
            rpc.height = 100
        result = self.runtime.dispatch("import_chain", exported)
        self.assertEqual(result["height"], 101)
        self.assertEqual(self.rpc.submissions, [exported["blocks"][-1]])
        self.assertEqual(second.submissions, [exported["blocks"][-1]])

    def test_fund_creates_confirmed_test_coins_from_mature_public_faucet(self):
        self.coin({"script_pubkey": "51"}, amount="50", height=1, coinbase=True)
        result = self.runtime.dispatch("fund", {"amount_sats": 2000001})
        self.assertTrue(result["mined"])
        self.assertEqual(result["height"], 102)
        self.assertEqual(result["amount_sats"], 2000001)
        wallet = self.runtime.dispatch("status", {})["wallet"]
        self.assertEqual(wallet["confirmed_sats"], 2000001)
        self.assertEqual(wallet["spendable_sats"], 2000001)
        self.assertEqual(wallet["pending_sats"], 0)
        self.assertEqual(wallet["next_receive"], 1)

    def test_fund_rejects_invalid_amount_or_immature_faucet_before_issuing_address(self):
        self.coin({"script_pubkey": "51"}, amount="50", height=2, coinbase=True)
        for params in ({"amount_sats": 0}, {"amount_sats": True}, {"address": "invalid"}, {}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.runtime.dispatch("fund", params)
        self.assertEqual(self.runtime.manifest()["next_receive"], 0)
        self.assertEqual(self.rpc.height, 101)

    def test_mine_confirms_pending_outputs_and_respects_block_bound(self):
        entry = self.receive()
        self.coin(entry)
        self.runtime.dispatch("send", {"address": entry["address"], "amount_sats": 1000000})
        for blocks in (0, 102, True):
            with self.subTest(blocks=blocks), self.assertRaises(ValueError):
                self.runtime.dispatch("mine", {"blocks": blocks})
        self.assertEqual(self.rpc.height, 101)
        result = self.runtime.dispatch("mine", {})
        self.assertEqual(result["height"], 102)
        self.assertEqual(len(result["blocks"]), 1)
        wallet = self.runtime.dispatch("status", {})["wallet"]
        self.assertEqual(wallet["pending_sats"], 0)
        self.assertEqual(wallet["spendable_sats"], 1999000)

    def test_lock_rejects_receive_and_send_while_retaining_public_balance(self):
        entry = self.receive()
        self.coin(entry)
        self.runtime.dispatch("lock", {})
        for action, params in (("receive", {}), ("send", {"address": entry["address"], "amount_sats": 1000000})):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "locked"):
                self.runtime.dispatch(action, params)
        status = self.runtime.dispatch("status", {})
        self.assertTrue(status["wallet"]["locked"])
        self.assertEqual(status["wallet"]["balance_sats"], 2000000)

    def test_bad_requests_produce_error_envelopes_without_wallet_mutation(self):
        for request in (None, [], {}, {"action": "unknown"}, {"action": "status", "params": {"method": "anything"}},
                        {"action": "receive", "params": [], "extra": 1}):
            with self.subTest(request=request):
                result = self.runtime.response(request)
                self.assertFalse(result["ok"])
                self.assertTrue(result["error"])
        self.assertIsNone(self.runtime.manifest())

    def test_deliberate_lock_keeps_initialized_chain_wallet_ready_for_unlock(self):
        self.receive()
        self.runtime.dispatch("lock", {})
        self.signer.available = False
        status = self.runtime.dispatch("status", {})
        self.assertTrue(status["ready"])
        self.assertTrue(status["wallet"]["locked"])
        self.assertFalse(status["wallet"]["signer_connected"])

    def test_restart_preserves_orphan_public_temp_and_uses_signer_counter_authority(self):
        self.receive()
        before = self.runtime.manifest()
        self.runtime.close()
        self.runtime = None
        state = Path(self.temp.name) / "state"
        public = state / "public"
        temporary = public / "public-wallet.tmp"
        temporary.write_bytes(b"partial public metadata from interrupted write")
        temporary.chmod(0o600)
        self.signer.counters[0] = 4
        resumed = self.module.Runtime(ROOT, ROOT / "build", state, "/tmp/public.sock", 1000,
            signer=self.signer, nodes=[NodeFixture(self.rpc), NodeFixture(self.rpc, "node1")])
        self.addCleanup(resumed.close)
        self.assertEqual(resumed.manifest(), before)
        self.assertFalse(temporary.exists(), "orphan must not block the next exclusive public write")
        diagnostics = list(public.glob("public-wallet.orphan-*/public-wallet.tmp"))
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0].read_bytes(), b"partial public metadata from interrupted write")
        self.assertEqual(diagnostics[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(diagnostics[0].parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(resumed.dispatch("status", {})["wallet"]["next_receive"], 4)
        self.assertEqual(resumed.dispatch("receive", {})["index"], 4)
        self.assertEqual(diagnostics[0].read_bytes(), b"partial public metadata from interrupted write")

    def test_orphan_reconciliation_cannot_rename_a_live_public_writer_temp(self):
        public = Path(self.temp.name) / "state/public"
        temporary = public / "public-wallet.tmp"
        temporary.write_bytes(b"live writer data")
        temporary.chmod(0o600)
        with self.assertRaises(ValueError):
            self.module.Runtime(ROOT, ROOT / "build", public.parent, "/tmp/public.sock", 1000)
        self.assertEqual(temporary.read_bytes(), b"live writer data")
        self.assertEqual(list(public.glob("public-wallet.orphan-*")), [])

    def test_orphan_with_unsafe_mode_type_or_links_is_refused_and_preserved(self):
        for kind in ("mode", "hardlink", "symlink", "directory"):
            with self.subTest(kind=kind):
                state = Path(self.temp.name) / ("unsafe-" + kind)
                state.mkdir(mode=0o700)
                public = state / "public"
                public.mkdir(mode=0o700)
                temporary = public / "public-wallet.tmp"
                if kind in ("mode", "hardlink"):
                    temporary.write_bytes(b"uncertain public bytes")
                    temporary.chmod(0o644 if kind == "mode" else 0o600)
                    if kind == "hardlink":
                        os.link(temporary, public / "other-link")
                elif kind == "symlink":
                    target = public / "target"
                    target.write_bytes(b"preserve public target")
                    target.chmod(0o600)
                    temporary.symlink_to(target)
                else:
                    temporary.mkdir(mode=0o700)
                with self.assertRaises(ValueError):
                    opened = self.module.Runtime(ROOT, ROOT / "build", state, "/tmp/public.sock", 1000)
                    self.addCleanup(opened.close)
                self.assertTrue(temporary.exists())
                self.assertEqual(list(public.glob("public-wallet.orphan-*")), [])
                if kind == "symlink":
                    self.assertEqual(target.read_bytes(), b"preserve public target")

    def test_repeated_orphans_get_distinct_diagnostics_without_overwriting_older_evidence(self):
        self.runtime.close()
        self.runtime = None
        state = Path(self.temp.name) / "state"
        public = state / "public"
        existing = public / "public-wallet.orphan-existing"
        existing.mkdir(mode=0o700)
        marker = existing / "public-wallet.tmp"
        marker.write_bytes(b"older diagnostic")
        marker.chmod(0o600)
        for data in (b"first interrupted write", b"second interrupted write"):
            temporary = public / "public-wallet.tmp"
            temporary.write_bytes(data)
            temporary.chmod(0o600)
            opened = self.module.Runtime(ROOT, ROOT / "build", state, "/tmp/public.sock", 1000)
            opened.close()
        self.assertEqual(sorted(path.read_bytes() for path in public.glob("public-wallet.orphan-*/public-wallet.tmp")),
            [b"first interrupted write", b"older diagnostic", b"second interrupted write"])

    def test_uncertain_orphan_fsync_refuses_open_but_preserves_all_public_bytes(self):
        self.receive()
        self.runtime.close()
        self.runtime = None
        state = Path(self.temp.name) / "state"
        public = state / "public"
        canonical = (public / "public-wallet.json").read_bytes()
        temporary = public / "public-wallet.tmp"
        temporary.write_bytes(b"uncertain interrupted write")
        temporary.chmod(0o600)
        with patch.object(self.module.os, "fsync", side_effect=OSError("fixture fsync failure")), self.assertRaises(ValueError):
            self.module.Runtime(ROOT, ROOT / "build", state, "/tmp/public.sock", 1000)
        self.assertEqual((public / "public-wallet.json").read_bytes(), canonical)
        candidates = list(public.glob("public-wallet.orphan-*/public-wallet.tmp"))
        if temporary.exists():
            candidates.append(temporary)
        self.assertEqual([path.read_bytes() for path in candidates], [b"uncertain interrupted write"])

    def test_new_action_replaces_idle_poisoned_rpc_without_replaying_a_request(self):
        class Connection:
            def __init__(self, endpoint):
                self.endpoint = endpoint
                self.stale = False

            def __getattr__(self, name):
                target = getattr(self.endpoint, name)

                def request(*args, **kwargs):
                    if self.stale:
                        raise OSError("Request-sent: fixture stale HTTP connection")
                    return target(*args, **kwargs)
                return request

        class ConnectingNode(NodeFixture):
            def rpc(self):
                return Connection(self.connection)

        self.runtime.nodes[0] = ConnectingNode(self.rpc)
        stale = Connection(self.rpc)
        stale.stale = True
        self.runtime.wallet.rpc = stale
        result = self.runtime.response({"action": "status", "params": {}})
        self.assertTrue(result["ok"], result.get("error"))
        previous = self.runtime.wallet.rpc
        previous.stale = True
        entry = self.runtime.response({"action": "receive", "params": {}})
        self.assertTrue(entry["ok"], entry.get("error"))
        self.assertEqual(entry["result"]["index"], 0)
        self.assertIsNot(self.runtime.wallet.rpc, previous)

    def test_ambiguous_broadcast_transport_failure_is_never_retried(self):
        entry = self.receive()
        self.coin(entry)
        endpoint = self.rpc

        class AmbiguousBroadcast:
            def __init__(self):
                self.attempts = 0

            def __getattr__(self, name):
                return getattr(endpoint, name)

            def sendrawtransaction(self, raw):
                self.attempts += 1
                endpoint.sendrawtransaction(raw)
                raise OSError("fixture disconnected after broadcast")

        uncertain = AmbiguousBroadcast()
        self.runtime.nodes[0] = NodeFixture(uncertain)
        result = self.runtime.response({"action": "send", "params": {"address": entry["address"], "amount_sats": 1000000}})
        self.assertFalse(result["ok"])
        self.assertEqual(uncertain.attempts, 1)
        self.assertEqual(len(endpoint.broadcasts), 1)

    def test_port_collision_is_refused_without_contacting_existing_listener(self):
        self.assertTrue(callable(getattr(self.module, "preflight_ports", None)), "port preflight missing")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            with self.assertRaisesRegex(ValueError, "port.*occupied"):
                self.module.preflight_ports([listener.getsockname()[1]])
            listener.settimeout(0.01)
            with self.assertRaises(TimeoutError):
                listener.accept()

    def test_abnormal_owned_node_exit_is_reported_without_foreign_rpc(self):
        self.assertTrue(callable(getattr(self.module, "PersistentNode", None)), "persistent node adapter missing")
        demo = SimpleNamespace(AuthServiceProxy=lambda *_args, **_kwargs: self.fail("RPC must not touch exited child"))
        node = self.module.PersistentNode("/public-binary", Path(self.temp.name) / "node", 1234, 1235, "node", demo)
        node.process = SimpleNamespace(poll=lambda: 7)
        with self.assertRaisesRegex(ValueError, "exit|shutdown"):
            node.stop()

    def test_forced_node_cleanup_is_bounded_and_reported_as_failure(self):
        self.assertTrue(callable(getattr(self.module, "PersistentNode", None)), "persistent node adapter missing")
        class Child:
            def __init__(self):
                self.code = None
                self.terminated = False

            def poll(self):
                return self.code

            def wait(self, timeout):
                return self.code

            def terminate(self):
                self.code = 0
                self.terminated = True
        child = Child()
        class RPC:
            def stop(self):
                raise OSError("fixture RPC unavailable")
        demo = SimpleNamespace(AuthServiceProxy=lambda *_args, **_kwargs: RPC())
        node = self.module.PersistentNode("/public-binary", Path(self.temp.name) / "node", 1234, 1235, "node", demo)
        node.process = child
        with self.assertRaisesRegex(ValueError, "forced|shutdown"):
            node.stop()
        self.assertTrue(child.terminated)

    def test_rpc_fixture_nonce_is_distinct_per_owned_node(self):
        self.assertTrue(callable(getattr(self.module, "PersistentNode", None)), "persistent node adapter missing")
        demo = SimpleNamespace(AuthServiceProxy=lambda url, **_kwargs: url)
        first = self.module.PersistentNode("/public-binary", Path(self.temp.name) / "node-a", 1234, 1235, "a", demo)
        second = self.module.PersistentNode("/public-binary", Path(self.temp.name) / "node-b", 1234, 1235, "b", demo)
        self.assertNotEqual(first.rpc(), second.rpc())
        self.assertNotIn("public-valueless-fixture", first.rpc())

    def test_sigterm_runs_worker_finally_and_reaps_owned_python_child(self):
        self.assertTrue(callable(getattr(self.module, "serve", None)), "signal-aware public worker loop missing")
        script = '''import importlib.util,json,pathlib,subprocess,sys
spec=importlib.util.spec_from_file_location("console_runtime",sys.argv[1]);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
runtime=mod.Runtime(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[2])/"build",pathlib.Path(sys.argv[3]),"/tmp/public.sock",1000)
class Node:
 def __init__(self):
  self.process=subprocess.Popen([sys.executable,"-c","import signal;signal.alarm(15);print('ready',flush=True);signal.pause()"],stdout=subprocess.PIPE)
  assert self.process.stdout.readline()==b"ready\\n"
 def stop(self):
  self.process.terminate();self.process.wait(timeout=5);self.process.stdout.close()
node=Node();runtime.nodes=[node]
print(json.dumps({"child_pid":node.process.pid}),flush=True)
mod.serve(runtime)
'''
        process = subprocess.Popen([sys.executable, "-c", script, str(ROOT / "contrib/ml-dsa-console/runtime.py"),
            str(ROOT), str(Path(self.temp.name) / "signal-state")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        child_pid = None
        try:
            child_pid = json.loads(process.stdout.readline())["child_pid"]
            process.stdin.write(b'{"action":"manifest","params":{}}\n')
            process.stdin.flush()
            self.assertTrue(json.loads(process.stdout.readline())["ok"])
            process.terminate()
            output, error = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, error.decode())
            self.assertEqual(output, b"")
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()


if __name__ == "__main__":
    unittest.main()
