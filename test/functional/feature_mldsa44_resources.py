#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Actual-node native ML-DSA accounting and resource qualification fixture.

Run in a bounded offline Linux container against current-source binaries. This
uses a PUBLIC synthetic fixture key, never a public wallet or the shipped signer.
It records RPC-observed 25/26, template/block 128/129, mempool pressure and 30
distinct 4,000,000-WU, 128-verification validations. Instrumented timing is kept
separate and cannot pass the release timing gate.
"""

import argparse
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "contrib/ml-dsa-qualification"))
from resource_workloads import (  # noqa: E402
    FixtureSigner, SCOPE, block_for, coin, compile_fixture_library,
)
from test_framework.authproxy import AuthServiceProxy, JSONRPCException  # noqa: E402
from test_framework.script import CScript  # noqa: E402

GENESIS = "2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979"


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class ResourceNode:
    def __init__(self, binary, directory):
        self.directory = directory
        self.port = unused_port()
        self.process = None
        self.output = None
        self.binary = str(binary)

    def rpc(self):
        return AuthServiceProxy(
            f"http://resource:public-synthetic-fixture@127.0.0.1:{self.port}", timeout=120)

    def start(self):
        self.directory.mkdir(mode=0o700)
        self.output = (self.directory / "process.log").open("wb")
        self.process = subprocess.Popen([
            self.binary, "-chain=test", "-mldsa44test=1", "-nosettings", "-server=1",
            "-datadir=" + str(self.directory), "-listen=0", "-connect=0", "-dnsseed=0", "-fixedseeds=0",
            "-discover=0", "-listenonion=0", "-natpmp=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
            f"-rpcport={self.port}", "-rpcuser=resource", "-rpcpassword=public-synthetic-fixture",
            "-maxmempool=32", "-dbcache=16", "-par=2", "-persistmempool=0", "-acceptnonstdtxn=0",
        ], stdout=self.output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            require(self.process.poll() is None, "resource node exited; inspect " + self.output.name)
            try:
                if self.rpc().getblockcount() >= 0:
                    break
            except (OSError, JSONRPCException):
                pass
            time.sleep(0.05)
        else:
            raise AssertionError("resource node startup deadline")
        require(self.rpc().getblockhash(0) == GENESIS, "wrong public TEST genesis")
        context = self.rpc().getblockchaininfo().get("valueless_mldsa44_test")
        require(context is not None, "explicit public native context missing")
        require(self.rpc().getmempoolinfo()["maxmempool"] == 32_000_000, "32 MB reference mempool missing")
        require((self.directory / "mldsa44-test-v1").is_dir(), "isolated TEST data namespace missing")

    def sample(self):
        # /proc retains raw node CPU counters; VmHWM includes every node thread.
        stat = Path(f"/proc/{self.process.pid}/stat").read_text().split(")", 1)[1].split()
        status = dict(line.split(":", 1) for line in Path(f"/proc/{self.process.pid}/status").read_text().splitlines())
        return {"user_ticks": int(stat[11]), "system_ticks": int(stat[12]),
                "rss_bytes": int(status["VmRSS"].split()[0]) * 1024,
                "peak_rss_bytes": int(status["VmHWM"].split()[0]) * 1024}

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            try:
                self.rpc().stop()
                self.process.wait(timeout=30)
            except Exception:
                self.process.kill()
                self.process.wait(timeout=10)
                raise
        if self.output is not None:
            self.output.close()


class Workload:
    def __init__(self, node, signer):
        self.node, self.rpc, self.signer = node, node.rpc(), signer
        self.coins = []
        self.offset = 0

    def take(self, count):
        selected = self.coins[self.offset:self.offset + count]
        require(len(selected) == count, "exhausted independent resource fixture Coins")
        self.offset += count
        return selected

    def accepted_block(self, txs, *, full_weight=False):
        block = block_for(self.rpc, self.signer, txs, full_weight=full_weight)
        wire = block.serialize().hex()
        before = self.node.sample()
        start = time.monotonic_ns()
        result = self.rpc.submitblock(wire)
        end = time.monotonic_ns()
        after = self.node.sample()
        require(result is None, {"submitblock": result, "block": block.hash_hex})
        require(self.rpc.getbestblockhash() == block.hash_hex, "submitted valid block did not become tip")
        return {"wall_ns": end - start, "start_monotonic_ns": start, "end_monotonic_ns": end,
                "before": before, "after": after,
                "user_ticks": after["user_ticks"] - before["user_ticks"],
                "system_ticks": after["system_ticks"] - before["system_ticks"],
                "block_hash": block.hash_hex, "block_weight": block.get_weight(),
                "native_verifications": sum(len(tx.vin) for tx in txs),
                "wire_sha256": hashlib.sha256(bytes.fromhex(wire)).hexdigest()}

    def fund(self):
        # H1 bootstrap is unowned. All later funding is directly native.
        self.rpc.generatetodescriptor(1, "raw(5220" + "00" * 32 + ")")
        blocks = self.rpc.generatetodescriptor(101, "raw(" + self.signer.script.hex() + ")")
        tx = self.rpc.getblock(blocks[0], 2)["tx"][0]
        source = coin(tx["txid"], 0, 50 * 100_000_000, self.signer.script)
        # A large actual signed transaction is consensus-only fixture generation;
        # the native service's separate 100-output request bound is unchanged.
        funding = self.signer.spend([source], output_count=16_000, output_value=100_000)
        self.accepted_block([funding])
        funding_txid = funding.txid_hex
        self.coins = [coin(funding_txid, index, 100_000, self.signer.script) for index in range(16_000)]

    def boundaries(self, observations):
        good = self.signer.spend(self.take(25), fee=500_000)
        over = self.signer.spend(self.take(26), fee=520_000)
        allowed = self.rpc.testmempoolaccept([good.serialize().hex()])[0]
        refused = self.rpc.testmempoolaccept([over.serialize().hex()])[0]
        require(allowed["allowed"], allowed)
        require(not refused["allowed"] and refused["reject-reason"] == "bad-txns-too-many-sigops", refused)
        observations.update({"25_input_testmempoolaccept": allowed, "26_input_testmempoolaccept": refused})
        txid = self.rpc.sendrawtransaction(good.serialize().hex(), 0)
        entry = self.rpc.getmempoolentry(txid)
        # Existing sigop-adjusted vsize must reflect actual entry accounting.
        require(entry["vsize"] == 78_125, entry)
        observations["25_input_entry"] = entry
        self.accepted_block([good])

        # Each transaction is standard, but one extra native input cannot fit.
        exact = [self.signer.spend(self.take(count), fee=25_000 * count if count == 3 else 20_000 * count)
                 for count in (25, 25, 25, 25, 25, 3)]
        extra = self.signer.spend(self.take(1), fee=5_000)
        for tx in exact + [extra]:
            require(self.rpc.sendrawtransaction(tx.serialize().hex(), 0) == tx.txid_hex, "broadcast txid mismatch")
        template = self.rpc.getblocktemplate({"rules": ["segwit"]})
        template_ids = {item["txid"] for item in template["transactions"]}
        require(template_ids == {tx.txid_hex for tx in exact}, {"template_txids": sorted(template_ids)})
        require(sum(item["sigops"] for item in template["transactions"]) == 80_000, template)
        over_block = block_for(self.rpc, self.signer, exact + [extra])
        previous = self.rpc.getbestblockhash()
        block_reason = self.rpc.submitblock(over_block.serialize().hex())
        require(block_reason == "bad-blk-sigops", block_reason)
        require(self.rpc.getbestblockhash() == previous, "129-check block altered chain")
        limit = self.accepted_block(exact)
        # Mine the remaining 1-check transaction before malformed controls.
        self.accepted_block([extra])

        malformed = self.signer.spend(self.take(1), fee=20_000)
        malformed.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(2420)
        negative = self.rpc.testmempoolaccept([malformed.serialize().hex()])[0]
        require(not negative["allowed"] and "script-verify" in negative["reject-reason"], negative)
        observations.update({"template_native_verifications": 128,
                             "template_sigops": 80_000, "129_input_submitblock": block_reason,
                             "128_input_block": limit, "malformed_testmempoolaccept": negative})

    def pressure(self):
        admitted, refused = [], []
        initial_minfee = self.rpc.getmempoolinfo()["mempoolminfee"]
        for index in range(10_000):
            # Increasing fees eventually replace earlier lower-fee entries.
            fee = 5_000 if index < 6_000 else 40_000
            tx = self.signer.spend(self.take(1), fee=fee)
            try:
                admitted.append(self.rpc.sendrawtransaction(tx.serialize().hex(), 0))
            except JSONRPCException as error:
                require("mempool" in error.error["message"].lower(), error.error)
                refused.append(error.error)
            if index % 50 == 49:
                info = self.rpc.getmempoolinfo()
                require(info["usage"] <= info["maxmempool"], info)
                require(info["bytes"] == info["size"] * 3_125, info)
                retained = set(self.rpc.getrawmempool())
                evicted = set(admitted) - retained
                if evicted and info["mempoolminfee"] > initial_minfee:
                    return {"submitted": index + 1, "admitted": len(admitted), "rejected": len(refused),
                            "evicted": len(evicted), "mempool": info,
                            "initial_mempoolminfee": initial_minfee,
                            "retained": len(retained), "rejections": refused[:5]}
        raise AssertionError("bounded actual 32 MB pressure workload observed no eviction/fee-floor rise")

    def measurements(self, count):
        records = []
        for index in range(count):
            # Stress actual all-input/all-output preparation as well as the 128
            # verifications. This consensus-only fixture exceeds both service
            # item caps; the shipped signer is never involved. Two transactions
            # make witness weight divisible by four for exact 4,000,000 WU.
            txs = [self.signer.spend(self.take(127), output_count=20_000, output_value=500),
                   self.signer.spend(self.take(1), fee=20_000)]
            if index == 0:
                overweight = copy.deepcopy(block_for(self.rpc, self.signer, txs, full_weight=True))
                # One additional stripped byte is four weight units. Keep the
                # otherwise-valid coinbase below its 100-byte scriptSig bound.
                overweight.vtx[0].vin[0].scriptSig = CScript(bytes(overweight.vtx[0].vin[0].scriptSig) + b"\x00")
                overweight.hashMerkleRoot = overweight.calc_merkle_root()
                overweight.solve()
                require(overweight.get_weight() == 4_000_004, "overweight control shape")
                reason = self.rpc.submitblock(overweight.serialize().hex())
                require(reason == "bad-blk-weight", {"overweight_reason": reason})
            record = self.accepted_block(txs, full_weight=True)
            if index == 0:
                record["4000004_weight_rejection"] = "bad-blk-weight"
            require(record["native_verifications"] == 128 and record["block_weight"] == 4_000_000, record)
            record["sample"] = index
            record["transaction_input_counts"] = [len(tx.vin) for tx in txs]
            record["transaction_output_counts"] = [len(tx.vout) for tx in txs]
            records.append(record)
            print(json.dumps({"event": "full_block_sample", **record}), flush=True)
        return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture-library", type=Path)
    parser.add_argument("--cc", default="gcc", choices=("gcc", "clang"))
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--samples", type=int, default=30, choices=range(1, 31))
    parser.add_argument("--timing-class", choices=("release", "instrumented"), required=True)
    parser.add_argument("--skip-pressure", action="store_true", help="development only; prevents full qualification")
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() != 0, "bounded non-root Linux fixture required")
    root = args.work_dir or Path(tempfile.mkdtemp(prefix="mldsa-resource-fixture-"))
    if args.work_dir:
        root.mkdir(mode=0o700)
    require(root.name.startswith("mldsa-resource-fixture-"), "isolated fixture directory prefix required")
    print(json.dumps({"event": "resource_fixture_start", "scope": SCOPE, "directory": str(root)}), flush=True)
    library = args.fixture_library or compile_fixture_library(args.cc, root)
    signer = FixtureSigner(library, scope=SCOPE)
    node = ResourceNode(args.binary.resolve(), root / "node")
    evidence = {"result": "FAIL", "scope": SCOPE, "timing_class": args.timing_class,
                "qualification_scope": "RELEASE_RESOURCE_CONFIGURATION" if args.timing_class == "release" else "INSTRUMENTED_CORRECTNESS_ONLY",
                "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                "fixture_library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
                "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"), "hardware": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()),
                "logical_cpu_count": os.cpu_count(),
                "cpu_identifiers": sorted({line for line in Path("/proc/cpuinfo").read_text().splitlines()
                                           if line.startswith(("model name", "Hardware", "CPU implementer", "CPU part"))}),
                "cgroup_cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
                "cgroup_memory_max": Path("/sys/fs/cgroup/memory.max").read_text().strip(),
                "timing_scope": "submitblock RPC wall; node /proc CPU ticks and lifetime VmHWM; fixture generation excluded"}
    try:
        node.start()
        workload = Workload(node, signer)
        workload.fund()
        evidence["boundaries"] = {}
        workload.boundaries(evidence["boundaries"])
        # Keep pressure separate from validation timing, with disjoint inputs.
        evidence["samples"] = workload.measurements(args.samples)
        evidence["pressure"] = None if args.skip_pressure else workload.pressure()
        ordered = sorted(record["wall_ns"] for record in evidence["samples"])
        evidence["p95_wall_ns"] = ordered[math.ceil(0.95 * len(ordered)) - 1]
        evidence["node_peak_rss_bytes"] = node.sample()["peak_rss_bytes"]
        evidence["release_timing_pass"] = (args.timing_class == "release" and args.samples == 30 and
                                            evidence["p95_wall_ns"] <= 2_000_000_000 and
                                            evidence["node_peak_rss_bytes"] <= 1_073_741_824)
        if args.timing_class == "release":
            require(evidence["node_peak_rss_bytes"] <= 1_073_741_824, evidence["node_peak_rss_bytes"])
        if args.timing_class == "release" and args.samples == 30:
            require(evidence["release_timing_pass"], "declared release resource threshold exceeded")
        evidence["result"] = "PASS" if args.samples == 30 and not args.skip_pressure else "DEVELOPMENT_ONLY"
    except BaseException as error:
        evidence["error"] = repr(error)
        raise
    finally:
        try:
            node.stop()
        finally:
            (root / "resource-results.json").write_text(json.dumps(evidence, indent=2, default=str) + "\n")
    print(json.dumps({"event": "resource_fixture_complete", "result": evidence["result"],
                      "evidence": str(root / "resource-results.json"),
                      "release_timing_pass": evidence["release_timing_pass"]}), flush=True)


if __name__ == "__main__":
    main()
