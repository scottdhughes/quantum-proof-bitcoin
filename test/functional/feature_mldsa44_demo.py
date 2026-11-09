#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Explicit valueless two-daemon demo. Run ONLY inside offline bounded Linux."""
if not __debug__:
    raise RuntimeError("optimized Python is not permitted for demo evidence")
import argparse
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import select
import sys
import tempfile
import time

from test_framework.authproxy import AuthServiceProxy, JSONRPCException
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut

GENESIS = "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"
MANIFEST = json.loads((Path(__file__).resolve().parents[2] / "contrib/ml-dsa-production-contract/regtest-demo-manifest-v1.json").read_text(encoding="utf8"))
TIMEOUT_FACTOR = 1


def wait_until(predicate, timeout=45):
    deadline = time.monotonic() + timeout * TIMEOUT_FACTOR
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("demo condition deadline")
        time.sleep(0.05)


class DemoNode:
    def __init__(self, binary, directory, port, rpcport):
        self.binary, self.directory = str(binary), directory
        self.port, self.rpcport = port, rpcport
        directory.mkdir(mode=0o700)
        self.process = None
        self.output = None

    def start(self, extra=()):
        self.output = (self.directory / ("process-" + str(time.monotonic_ns()) + ".log")).open("wb")
        command = [self.binary, "-regtest", "-mldsa44demo=1", "-nosettings", "-server=1",
                   "-datadir=" + str(self.directory), "-listen=1", "-bind=127.0.0.1",
                   "-port=" + str(self.port), "-rpcport=" + str(self.rpcport), "-rpcbind=127.0.0.1",
                   "-rpcallowip=127.0.0.1", "-rpcuser=demo", "-rpcpassword=public-valueless-fixture",
                   "-dnsseed=0", "-fixedseeds=0", "-discover=0", "-listenonion=0", "-natpmp=0",
                   "-connect=0", "-acceptnonstdtxn=0", "-dbcache=16", "-maxmempool=32", "-par=2",
                   "-debug=validation", "-debug=mempool", *extra]
        self.process = subprocess.Popen(command, stdout=self.output, stderr=subprocess.STDOUT)

        def ready():
            if self.process.poll() is not None:
                raise AssertionError("demo daemon exited; inspect " + self.output.name)
            try:
                return self.rpc().getblockcount() >= 0
            except (OSError, JSONRPCException):
                return False
        wait_until(ready)
        assert self.rpc().getblockhash(0) == GENESIS
        info = self.rpc().getblockchaininfo()
        context = info.get("valueless_mldsa44_demo")
        assert context is not None, "valueless deployment context missing"
        assert context["network_binding"] == MANIFEST["message_start_hex"] + bytes.fromhex(MANIFEST["genesis_display_hash"])[::-1].hex()
        assert context["spec_sha256"] == MANIFEST["spec_sha256"]
        assert context["activation_height"] == MANIFEST["activation_height"]
        assert context["active"] == (info["blocks"] >= MANIFEST["activation_height"])
        assert (self.directory / "mldsa44-regtest-v1").is_dir()
        assert not (self.directory / "regtest").exists()

    def rpc(self):
        # This public test credential is created for this isolated fixture only.
        return AuthServiceProxy("http://demo:public-valueless-fixture@127.0.0.1:" + str(self.rpcport), timeout=60)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.rpc().stop()
            self.process.wait(timeout=30)
            assert self.process.returncode == 0
        if self.output:
            self.output.close()


def rejected(call, contains):
    try:
        call()
    except JSONRPCException as error:
        assert contains.lower() in error.error["message"].lower(), error.error
        return error.error
    raise AssertionError("invalid ML-DSA operation accepted")


def synchronize(nodes):
    wait_until(lambda: len({node.rpc().getbestblockhash() for node in nodes}) == 1)


def configuration_refusals(binary, root):
    for index, config in enumerate(("[regtest]\nmldsa44demo=1\n", "mldsa44demo=1\n[regtest]\nmldsa44demo=0\n", "mldsa44demo=1\n")):
        directory = root / ("refused-config-" + str(index))
        directory.mkdir(mode=0o700)
        config_file = directory / "public-test.conf"
        config_file.write_text(config, encoding="utf8")
        result = subprocess.run([str(binary), "-regtest", "-nosettings", "-conf=" + str(config_file),
            "-datadir=" + str(directory), "-printtoconsole=1"], capture_output=True, text=True, timeout=20 * TIMEOUT_FACTOR)
        assert result.returncode != 0 and "command-line only" in result.stderr, (result.stdout, result.stderr)
    return 3


def reject_actual_spend(nodes, wire, label):
    observations = []
    for node in nodes:
        result = node.rpc().testmempoolaccept([wire])[0]
        assert result["allowed"] is False and "block-script-verify-flag-failed" in result["reject-reason"], result
        block = rejected(lambda: node.rpc().generateblock("raw(51)", [wire]), "block-script-verify-flag-failed")
        observations.append({"label": label, "node_port": node.port, "mempool_reason": result["reject-reason"], "block_reason": block["message"]})
    return observations


def validation_demo(nodes):
    a, b = nodes
    a.rpc().addnode("127.0.0.1:" + str(b.port), "onetry")
    wait_until(lambda: bool(a.rpc().getpeerinfo()) and bool(b.rpc().getpeerinfo()))
    blocks = a.rpc().generatetodescriptor(101, "raw(51)")
    synchronize(nodes)
    coinbase = a.rpc().getblock(blocks[0], 2)["tx"][0]["txid"]
    program_script = bytes.fromhex("5220" + "42" * 32)
    funding = CTransaction()
    funding.vin = [CTxIn(COutPoint(int(coinbase, 16), 0))]
    funding.vout = [CTxOut(1000000, program_script), CTxOut(4998999000, b"\x51")]
    funding_block = a.rpc().generateblock("raw(51)", [funding.serialize().hex()])["hash"]
    synchronize(nodes)
    bad = CTransaction()
    bad.vin = [CTxIn(COutPoint(funding.txid_int, 0))]
    bad.vout = [CTxOut(999000, program_script)]
    bad.wit.vtxinwit = [CTxInWitness()]
    bad.wit.vtxinwit[0].scriptWitness.stack = [bytes(2420), bytes(1312)]
    wire = bad.serialize().hex()
    observations = []
    for node in nodes:
        observations.append(rejected(lambda: node.rpc().sendrawtransaction(wire), "block-script-verify-flag-failed"))
        observations.append(rejected(lambda: node.rpc().generateblock("raw(51)", [wire]), "block-script-verify-flag-failed"))
        assert node.rpc().getbestblockhash() == funding_block
        assert node.rpc().gettxout(funding.txid_hex, 0) is not None
    a.rpc().invalidateblock(blocks[0])
    assert a.rpc().getblockcount() == 0 and a.rpc().getrawmempool() == []
    a.rpc().reconsiderblock(blocks[0])
    synchronize(nodes)
    a.stop()
    a.start(["-reindex=1"])
    wait_until(lambda: a.rpc().getbestblockhash() == funding_block)
    assert a.rpc().gettxout(funding.txid_hex, 0) is not None
    return {"scope": "ACTUAL_TWO_NODE_INVALID_WITNESS_ENFORCEMENT_NOT_VALID_SPEND",
            "genesis": GENESIS, "funding_txid": funding.txid_hex, "tip": funding_block,
            "negative_operations": observations, "reorg_and_reindex": True}


def spend_restore_demo(nodes, root, args):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "contrib/ml-dsa-signer"))
    # Loaded from the explicit companion directory above, outside mypy's roots.
    import node_wallet as wallet  # type: ignore[import]
    a, b = nodes
    a.rpc().addnode("127.0.0.1:" + str(b.port), "onetry")
    wait_until(lambda: bool(a.rpc().getpeerinfo()) and bool(b.rpc().getpeerinfo()))
    signer = wallet.NativeSigner(args.client, args.socket, args.signer_uid)
    first_public = root / "public-first"
    first_public.mkdir(mode=0o700)
    # No address or signing request is allowed while still at genesis.
    with wallet.PublicStore(first_public) as store:
        first = wallet.NodeWallet(a.rpc(), signer, store)
        try:
            first.reserve(0)
        except wallet.WalletError:
            pass
        else:
            raise AssertionError("pre-activation wallet address issued")
        blocks = a.rpc().generatetodescriptor(101, "raw(51)")
        synchronize(nodes)
        try:
            wallet.NativeSigner(args.client, args.socket, 1007).call(5)
        except wallet.WalletError:
            pass
        else:
            raise AssertionError("wrong signer UID accepted")
        receive, destination, change = first.reserve(0), first.reserve(0), first.reserve(1)
        assert (receive["index"], destination["index"], change["index"]) == (0, 1, 0)
        coinbase = a.rpc().getblock(blocks[0], 2)["tx"][0]["txid"]
        funding = CTransaction()
        funding.vin = [CTxIn(COutPoint(int(coinbase, 16), 0))]
        funding.vout = [CTxOut(1000000, bytes.fromhex(receive["script_pubkey"])),
                        CTxOut(1000000, bytes.fromhex(receive["script_pubkey"])), CTxOut(4997990000, b"\x51")]
        a.rpc().generateblock("raw(51)", [funding.serialize().hex()])
        synchronize(nodes)
        assert a.rpc().gettxout(funding.txid_hex, 0)["scriptPubKey"]["address"] == receive["address"]
        assert {item["txid"] for item in first.scan()} == {funding.txid_hex}
        spend = CTransaction()
        spend.vin = [CTxIn(COutPoint(funding.txid_int, index)) for index in (0, 1)]
        spend.vout = [CTxOut(1000000, bytes.fromhex(destination["script_pubkey"])), CTxOut(990000, bytes.fromhex(change["script_pubkey"]))]
        signed = first.sign(spend.serialize().hex())
        # A still-valid signature cannot authorize changed outputs or witnesses.
        mutated = CTransaction()
        mutated.deserialize(io.BytesIO(bytes.fromhex(signed["hex"])))
        mutated.vout[0].nValue -= 1
        negatives = reject_actual_spend(nodes, mutated.serialize().hex(), "changed-output")
        mutated = CTransaction()
        mutated.deserialize(io.BytesIO(bytes.fromhex(signed["hex"])))
        original = mutated.wit.vtxinwit[0].scriptWitness.stack[0]
        mutated.wit.vtxinwit[0].scriptWitness.stack[0] = bytes([original[0] ^ 1]) + original[1:]
        negatives += reject_actual_spend(nodes, mutated.serialize().hex(), "altered-signature")
        mutated = CTransaction()
        mutated.deserialize(io.BytesIO(bytes.fromhex(signed["hex"])))
        # Both Coins really exist with equal amounts/scripts. Swapping just the
        # outpoints must fail signature binding, NOT duplicate/missing-input checks.
        mutated.vin[0].prevout, mutated.vin[1].prevout = mutated.vin[1].prevout, mutated.vin[0].prevout
        negatives += reject_actual_spend(nodes, mutated.serialize().hex(), "changed-outpoint")
        # Deliberately false node-supplied amount: signer self-checks THAT model,
        # but both actual nodes must independently reject it using real Coins.
        model, paths, _ = first.prepare(spend.serialize().hex())
        model["inputs"][0]["amount"] += 1
        payload = signer.call(3, wallet.ipc_v1.encode_sign_request(bytes.fromhex(store.export()["wallet_id"]), model, paths))
        false_wire = wallet.attach_witnesses(model, paths, store.export(), payload)
        negatives += reject_actual_spend(nodes, false_wire.hex(), "false-prevout-amount")
        model, paths, _ = first.prepare(spend.serialize().hex())
        wrong_script = copy.deepcopy(model)
        wrong_script["inputs"][0]["script_pubkey"] = destination["script_pubkey"]
        try:
            signer.call(3, wallet.ipc_v1.encode_sign_request(bytes.fromhex(store.export()["wallet_id"]), wrong_script, paths))
        except wallet.WalletError as error:
            assert "signer refused status 9" in str(error), error
        else:
            raise AssertionError("signer accepted a path/script mismatch")
        # Now give the signer a consistent B path for the false B script. Its
        # self-verified B signature still cannot spend the actual A Coin.
        wrong_paths = list(paths)
        wrong_paths[0] = (0, destination["index"])
        payload = signer.call(3, wallet.ipc_v1.encode_sign_request(bytes.fromhex(store.export()["wallet_id"]), wrong_script, wrong_paths))
        false_script_wire = wallet.attach_witnesses(wrong_script, wrong_paths, store.export(), payload)
        negatives += reject_actual_spend(nodes, false_script_wire.hex(), "false-prevout-script")
        txid = a.rpc().sendrawtransaction(signed["hex"])
        assert txid == signed["txid"]
        wait_until(lambda: txid in b.rpc().getrawmempool())
        first_block = a.rpc().generatetodescriptor(1, "raw(51)")[0]
        synchronize(nodes)
        for node in nodes:
            assert node.rpc().gettxout(txid, 0) is not None and node.rpc().gettxout(funding.txid_hex, 0) is None
        try:
            first.sign(spend.serialize().hex())
        except wallet.WalletError as error:
            assert "confirmed Coin" in str(error)
        else:
            raise AssertionError("spent Coin signed again")
        public_backup = store.export()
    # Quiesce the old wallet/client before restoring the older encrypted record.
    a.stop()
    print(json.dumps({"event": "RESTORE_REQUIRED", "public_manifest": public_backup, "first_spend": txid}), flush=True)
    assert select.select([sys.stdin], [], [], 60 * TIMEOUT_FACTOR)[0], "operator restore deadline"
    assert sys.stdin.readline() == "RESTORED\n", "operator restore acknowledgement"
    restored_public = root / "public-restored"
    restored_public.mkdir(mode=0o700)
    with wallet.PublicStore(restored_public) as store:
        second = wallet.NodeWallet(b.rpc(), signer, store)
        second.import_manifest(public_backup)
        unspent = second.scan()
        assert {(item["txid"], item["vout"]) for item in unspent} == {(txid, 0), (txid, 1)}
        restored_address = second.reserve(0)
        assert restored_address["index"] == 2, "old encrypted backup reused a retained index"
        restored_spend = CTransaction()
        restored_spend.vin = [CTxIn(COutPoint(int(txid, 16), index)) for index in (0, 1)]
        restored_spend.vout = [CTxOut(1980000, bytes.fromhex(restored_address["script_pubkey"]))]
        final = second.sign(restored_spend.serialize().hex())
        second_txid = b.rpc().sendrawtransaction(final["hex"])
        final_block = b.rpc().generatetodescriptor(1, "raw(51)")[0]
        b.rpc().invalidateblock(final_block)
        assert b.rpc().gettxout(txid, 0, False) is not None
        b.rpc().reconsiderblock(final_block)
        assert b.rpc().gettxout(second_txid, 0) is not None
        second.lock()
        try:
            second.reserve(0)
        except wallet.WalletError:
            pass
        else:
            raise AssertionError("locked signer issued an address")
        try:
            signer.call(2, b"\0")
        except wallet.WalletError as error:
            assert "signer refused status 5" in str(error), error
        else:
            raise AssertionError("native signer accepted GET_ADDRESS after LOCK")
        final_manifest = store.export()
    b.stop()
    b.start(["-reindex=1"])
    wait_until(lambda: b.rpc().getbestblockhash() == final_block)
    assert b.rpc().gettxout(second_txid, 0) is not None
    a.start()
    a.rpc().addnode("127.0.0.1:" + str(b.port), "onetry")
    synchronize(nodes)
    assert a.rpc().gettxout(second_txid, 0) == b.rpc().gettxout(second_txid, 0)
    inventories = [node.rpc().gettxoutsetinfo() for node in nodes]
    assert inventories[0]["bestblock"] == inventories[1]["bestblock"] == final_block
    assert inventories[0]["hash_serialized_3"] == inventories[1]["hash_serialized_3"]
    assert inventories[0]["txouts"] == inventories[1]["txouts"]
    return {"scope": "ACTUAL_TWO_NODE_SIGNER_SPEND_ENCRYPTED_OLD_RECORD_RESTORE", "first_spend": txid,
            "restored_spend": second_txid, "first_block": first_block, "final_block": final_block,
            "public_wallet_id": final_manifest["wallet_id"], "next_receive": final_manifest["next_receive"],
            "next_change": final_manifest["next_change"], "restored_receive_index": 2,
            "actual_nodes": 2, "restored_inputs": 2, "value": "VALUELESS_REGTEST_ONLY",
            "mutation_and_false_prevout_rejections_per_node": 5, "negative_admission_observations": negatives,
            "whole_utxo_hash": inventories[0]["hash_serialized_3"], "whole_utxo_count": inventories[0]["txouts"],
            "native_locked_status": 5, "script_path_mismatch_status": 9, "reorg_reindex_restart": True}


def main():
    global TIMEOUT_FACTOR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validation-only", action="store_true")
    mode.add_argument("--spend-restore", action="store_true")
    parser.add_argument("--client", type=Path)
    parser.add_argument("--socket")
    parser.add_argument("--signer-uid", type=int, default=1000)
    parser.add_argument("--timeout-factor", type=int, default=1, choices=range(1, 9))
    args = parser.parse_args()
    TIMEOUT_FACTOR = args.timeout_factor
    assert os.uname().sysname == "Linux" and os.geteuid() != 0
    root = Path(tempfile.mkdtemp(prefix="mldsa-real-node-demo-"))
    nodes = [DemoNode(args.binary, root / ("node" + str(i)), 24843 + i, 24853 + i) for i in range(2)]
    print(json.dumps({"retained_demo_directory": str(root)}), flush=True)
    try:
        config_rejections = configuration_refusals(args.binary, root)
        for node in nodes:
            node.start()
        result = validation_demo(nodes) if args.validation_only else spend_restore_demo(nodes, root, args)
        print(json.dumps({"result": "PASS", "config_rejections": config_rejections, **result}), flush=True)
    finally:
        for node in nodes:
            node.stop()
    print("MLDSA_DEMO_VALIDATION_TERMINAL_EXIT_0" if args.validation_only else "MLDSA_DEMO_SPEND_RESTORE_TERMINAL_EXIT_0", flush=True)


if __name__ == "__main__":
    main()
