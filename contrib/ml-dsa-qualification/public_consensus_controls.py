#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Actual-node public-profile accepted-set and both reindex-path controls.

Use only public synthetic fixtures in a bounded offline Linux container. The
parent qualification runner joins these observations to its exact source/image
receipts. This command alone is neither platform admission nor a public soak.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "PQBTC-MLDSA44-PUBLIC-CONSENSUS-CONTROLS-1"
SCOPE = "ACTUAL_NODE_PUBLIC_PROFILE_ACCEPTED_SET_AND_REINDEX"
POSITIVE_CONTROLS = {"same_coin_valid_native_spend", "canonical_direct_byte_01",
                     "canonical_empty_push", "canonical_direct_80_bytes"}
CONTROL_NAMES = (
    "classical_H1_coinbase", "classical_OP_TRUE", "witness_v0", "witness_v1_rc2", "future_v3", "P2SH",
    "OP_RETURN_smallint_alias", "OP_RETURN_81bytes", "nonempty_scriptSig", "actual_wrong_network_signature",
    "same_coin_valid_native_spend", "canonical_direct_byte_01", "canonical_empty_push", "canonical_direct_80_bytes",
    "reindex-chainstate_full_history_and_native_rejection", "reindex_full_history_and_native_rejection",
)


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_report(value):
    require(type(value) is dict and value.get("schema") == SCHEMA and value.get("scope") == SCOPE and
            value.get("result") == "PASS" and digest(value.get("binary_sha256")) and
            value.get("owned_node_cleanup") == "STOPPED", "Public consensus control report is incomplete")
    observations = value.get("observations")
    require(type(observations) is list and len(observations) == len(CONTROL_NAMES) and
            all(type(row) is dict for row in observations), "All sixteen actual public consensus controls are required")
    rows = {row.get("control"): row for row in observations}
    require(set(rows) == set(CONTROL_NAMES), "Public consensus controls are missing, duplicated or unknown")
    baseline = value.get("state_before_reindex")
    require(type(baseline) is dict and digest(baseline.get("tip")) and type(baseline.get("height")) is int and
            type(baseline.get("utxo")) is dict and digest(baseline["utxo"].get("muhash")) and
            baseline["utxo"].get("height") == baseline["height"] and baseline["utxo"].get("bestblock") == baseline["tip"] and
            type(baseline["utxo"].get("txouts")) is int and "total_amount" in baseline["utxo"],
            "Full pre-reindex UTXO fingerprint is missing")
    for name, row in rows.items():
        admission = row.get("testmempoolaccept", {})
        if name in POSITIVE_CONTROLS:
            require(admission.get("allowed") is True and "submitblock" in row and row["submitblock"] is None,
                    "A canonical/native positive control did not pass: " + name)
        else:
            reason = "bad-mldsa44-prevout" if name == "nonempty_scriptSig" else "bad-mldsa44-output"
            if name == "actual_wrong_network_signature":
                require(admission.get("allowed") is False and "script-verify" in admission.get("reject-reason", "") and
                        type(row.get("submitblock")) is str and "script-verify" in row["submitblock"],
                        "The actual wrong-network signature was not rejected by both paths")
            else:
                require(row.get("submitblock") == reason and (name == "classical_H1_coinbase" or
                        (admission.get("allowed") is False and admission.get("reject-reason") == reason)),
                        "A forbidden public-profile shape was not rejected by both paths: " + name)
            require(row.get("tip_unchanged") is True, "Rejected control changed the valid tip: " + name)
        if name.startswith("reindex"):
            require(row.get("state") == baseline and digest(row.get("rejected_block_hash")),
                    "Reindex did not retain the complete valid state or a new rejected block identity")
    full = rows["reindex_full_history_and_native_rejection"]
    prior = rows["reindex-chainstate_full_history_and_native_rejection"]["rejected_block_hash"]
    require(full.get("revisited_stored_block_hash") == prior and digest(full.get("fresh_reindex_log_sha256")) and
            type(full.get("stored_rejection_log_line")) is str and
            "ConnectBlock " + prior + " failed, bad-mldsa44-output" in full["stored_rejection_log_line"],
            "Full reindex did not demonstrably reject the exact previously stored forbidden block")


def fingerprint(rpc):
    utxo = rpc.gettxoutsetinfo("muhash")
    return {"tip": rpc.getbestblockhash(), "height": rpc.getblockcount(),
            "utxo": {key: utxo[key] for key in ("height", "bestblock", "txouts", "total_amount", "muhash")}}


def restart(node, mode, baseline, *, stored_hash=None):
    # ResourceNode is reused for process ownership, but every readiness attempt
    # gets a new RPC transport. An old keep-alive connection is not restart proof.
    from test_framework.authproxy import JSONRPCException
    args = list(node.process.args)
    node.stop()
    require(node.process.returncode == 0, "Owned node did not stop cleanly before " + mode)
    debug = node.directory / "mldsa44-test-v1/debug.log"
    offset = debug.stat().st_size
    node.output = (node.directory / (mode + "-process.log")).open("wb")
    node.process = subprocess.Popen(args + ["-" + mode + "=1"], stdout=node.output, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 60
    log = ""
    while time.monotonic() < deadline:
        require(node.process.poll() is None, "Owned node exited during " + mode)
        log = debug.read_bytes()[offset:].decode("utf8", "replace")
        try:
            same_tip = node.rpc().getbestblockhash() == baseline["tip"]
        except (OSError, JSONRPCException):
            same_tip = False
        if same_tip and (mode != "reindex" or ("Reindexing finished" in log and
                "ConnectBlock " + stored_hash + " failed, bad-mldsa44-output" in log)):
            break
        time.sleep(0.05)
    else:
        raise ValueError(mode + " actual-history/stored-rejection deadline")
    after = fingerprint(node.rpc())
    require(after == baseline, {"mode": mode, "before": baseline, "after": after})
    log_path = node.directory.parent / (mode + "-debug.log")
    log_path.write_text(log, encoding="utf8")
    proof = {}
    if mode == "reindex":
        proof = {"revisited_stored_block_hash": stored_hash,
                 "stored_rejection_log_line": next(line for line in log.splitlines()
                     if "ConnectBlock " + stored_hash + " failed, bad-mldsa44-output" in line),
                 "fresh_reindex_log_sha256": hashlib.sha256(log.encode()).hexdigest()}
    return after, proof


def controls(node, signer, evidence, rw):
    from test_framework.blocktools import create_block, create_coinbase
    from test_framework.messages import CTxOut
    from test_framework.script import CScript, OP_TRUE, OP_0, OP_1, OP_3, OP_RETURN, OP_HASH160, OP_EQUAL
    import protocol_v1

    rpc = node.rpc()
    previous = rpc.getblockheader(rpc.getbestblockhash())
    coinbase = create_coinbase(1, script_pubkey=CScript([OP_TRUE]), halving_period=210_000)
    forbidden_h1 = create_block(int(previous["hash"], 16), coinbase, previous["time"] + 1)
    forbidden_h1.solve()
    result = rpc.submitblock(forbidden_h1.serialize().hex())
    require(result == "bad-mldsa44-output" and rpc.getblockcount() == 0, result)
    evidence["observations"].append({"control": "classical_H1_coinbase", "submitblock": result,
                                     "tip_unchanged": rpc.getbestblockhash() == previous["hash"],
                                     "rejected_block_hash": forbidden_h1.hash_hex})
    rpc.generatetodescriptor(1, "raw(5220" + "00" * 32 + ")")
    blocks = rpc.generatetodescriptor(101, "raw(" + signer.script.hex() + ")")
    source = rpc.getblock(blocks[0], 2)["tx"][0]
    owned_coin = rw.coin(source["txid"], 0, 5_000_000_000, signer.script)

    def rejected(name, tx, expected, *, script_failure=False):
        prior = rpc.getbestblockhash()
        admission = rpc.testmempoolaccept([tx.serialize().hex()])[0]
        block = rw.block_for(rpc, signer, [tx])
        submitted = rpc.submitblock(block.serialize().hex())
        if script_failure:
            require(admission.get("allowed") is False and "script-verify" in admission.get("reject-reason", "") and
                    type(submitted) is str and "script-verify" in submitted, (name, admission, submitted))
        else:
            require(admission.get("allowed") is False and admission.get("reject-reason") == expected and
                    submitted == expected, (name, admission, submitted))
        unchanged = rpc.getbestblockhash() == prior
        require(unchanged, "Rejected block changed the valid chain")
        row = {"control": name, "testmempoolaccept": admission, "submitblock": submitted,
               "tip_unchanged": unchanged, "rejected_block_hash": block.hash_hex}
        evidence["observations"].append(row)
        return row

    shapes = (("classical_OP_TRUE", bytes([OP_TRUE])),
              ("witness_v0", bytes(CScript([OP_0, bytes(32)]))),
              ("witness_v1_rc2", bytes(CScript([OP_1, bytes(32)]))),
              ("future_v3", bytes(CScript([OP_3, bytes(32)]))),
              ("P2SH", bytes(CScript([OP_HASH160, bytes(20), OP_EQUAL]))),
              ("OP_RETURN_smallint_alias", bytes([OP_RETURN, OP_1])),
              ("OP_RETURN_81bytes", bytes(CScript([OP_RETURN, bytes(81)]))))
    for index, (name, script) in enumerate(shapes):
        tx = signer.spend([owned_coin], fee=20_000, lock_time=index + 1)
        tx.vout[0] = CTxOut(0 if name.startswith("OP_RETURN") else 4_999_980_000, script)
        signer.sign(tx, [owned_coin])
        rejected(name, tx, "bad-mldsa44-output")

    tx = signer.spend([owned_coin], fee=20_000, lock_time=100)
    tx.vin[0].scriptSig = CScript([OP_0])
    rejected("nonempty_scriptSig", tx, "bad-mldsa44-prevout")
    binding = rw.TEST_BINDING
    try:
        # Change only the signed message's network binding; the Coin/program
        # remains the actual TEST key. This exercises a real wrong signature.
        rw.TEST_BINDING = protocol_v1.binding("regtest")
        wrong = signer.spend([owned_coin], fee=20_000, lock_time=101)
    finally:
        rw.TEST_BINDING = binding
    rejected("actual_wrong_network_signature", wrong, None, script_failure=True)

    def accepted(name, tx):
        admission = rpc.testmempoolaccept([tx.serialize().hex()])[0]
        require(admission.get("allowed") is True, (name, admission))
        block = rw.block_for(rpc, signer, [tx])
        result = rpc.submitblock(block.serialize().hex())
        require(result is None and rpc.getbestblockhash() == block.hash_hex, (name, result))
        evidence["observations"].append({"control": name, "testmempoolaccept": admission,
                                         "submitblock": result, "accepted_block_hash": block.hash_hex})
        return rw.coin(tx.txid_hex, 0, tx.vout[0].nValue, signer.script)

    good = signer.spend([owned_coin], fee=20_000)
    owned_coin = accepted("same_coin_valid_native_spend", good)
    for name, script in (("canonical_direct_byte_01", bytes.fromhex("6a0101")),
                         ("canonical_empty_push", bytes.fromhex("6a00")),
                         ("canonical_direct_80_bytes", bytes(CScript([OP_RETURN, b"B" * 80])))):
        tx = signer.spend([owned_coin], fee=20_000)
        tx.vout.append(CTxOut(0, script))
        signer.sign(tx, [owned_coin])
        owned_coin = accepted(name, tx)

    baseline = fingerprint(rpc)
    evidence["state_before_reindex"] = baseline
    stored_hash = None
    for mode in ("reindex-chainstate", "reindex"):
        state, proof = restart(node, mode, baseline, stored_hash=stored_hash)
        rpc = node.rpc()
        tx = signer.spend([owned_coin], fee=20_000, lock_time=1 if mode == "reindex" else 2)
        tx.vout[0].scriptPubKey = CScript([OP_TRUE])
        signer.sign(tx, [owned_coin])
        row = rejected(mode + "_full_history_and_native_rejection", tx, "bad-mldsa44-output")
        row.update({"state": state, **proof})
        stored_hash = row["rejected_block_hash"]


def main(argv=None):
    require(__debug__, "Optimized Python cannot produce consensus evidence")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cc", choices=("gcc", "clang"), default="gcc")
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args(argv)
    require(sys.platform == "linux" and os.geteuid() != 0, "Non-root contained Linux execution is required")
    sys.path[:0] = [str(ROOT / "test/functional"), str(ROOT / "contrib/ml-dsa-production-contract"), str(Path(__file__).parent)]
    from feature_mldsa44_resources import ResourceNode
    import resource_workloads as rw

    base = args.work_dir or Path(tempfile.mkdtemp(prefix="mldsa-public-consensus-"))
    if args.work_dir:
        require(not base.exists() and not base.is_symlink(), "Choose a fresh consensus fixture directory")
        base.mkdir(mode=0o700)
    require(base.name.startswith("mldsa-public-consensus-"), "Isolated public consensus fixture prefix is required")
    node = ResourceNode(args.binary.resolve(), base / "node")
    evidence = {"schema": SCHEMA, "scope": SCOPE, "result": "FAIL", "observations": [],
                "data_directory": str(base), "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                "public_soak": False, "source_binding": "parent must join exact-source qualification receipt"}
    candidate_pass = False
    try:
        node.start()
        library = rw.compile_fixture_library(args.cc, base)
        evidence["fixture_library_sha256"] = hashlib.sha256(library.read_bytes()).hexdigest()
        signer = rw.FixtureSigner(library, scope=rw.SCOPE)
        controls(node, signer, evidence, rw)
        candidate_pass = True
    except BaseException as error:
        evidence["failure"] = {"type": type(error).__name__, "detail": str(error)}
        raise
    finally:
        try:
            node.stop()
            require(node.process is not None and node.process.returncode == 0, "Owned consensus node did not stop cleanly")
            evidence["owned_node_cleanup"] = "STOPPED"
            if candidate_pass:
                evidence["result"] = "PASS"
                validate_report(evidence)
        except BaseException as error:
            evidence["result"] = "FAIL"
            evidence["cleanup_or_receipt_error"] = {"type": type(error).__name__, "detail": str(error)}
            raise
        finally:
            evidence["diagnostic_sha256"] = {str(path.relative_to(base)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(base.rglob("*.log")) if path.is_file()}
            (base / "public-consensus-results.json").write_text(json.dumps(evidence, indent=2, default=str) + "\n")
            print(json.dumps({"event": "public_consensus_controls_complete", "result": evidence["result"],
                              "controls": len(evidence["observations"]), "evidence": str(base / "public-consensus-results.json")}), flush=True)
    print("MLDSA_PUBLIC_CONSENSUS_CONTROLS_TERMINAL_EXIT_0", flush=True)


if __name__ == "__main__":
    main()
