#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Explicit valueless two-daemon demo. Run ONLY inside offline bounded Linux."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from test_framework.authproxy import AuthServiceProxy, JSONRPCException
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut

GENESIS = "36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2"


def wait_until(predicate, timeout=45):
    deadline = time.monotonic() + timeout
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
        observations.append(rejected(lambda: node.rpc().sendrawtransaction(wire), "witness"))
        observations.append(rejected(lambda: node.rpc().generateblock("raw(51)", [wire]), "TestBlockValidity failed"))
        assert node.rpc().getbestblockhash() == funding_block
        assert node.rpc().gettxout(funding.txid_hex, 0) is not None
    a.rpc().invalidateblock(blocks[0])
    assert a.rpc().getblockcount() == 0 and a.rpc().getrawmempool() == []
    a.rpc().reconsiderblock(blocks[0])
    synchronize(nodes)
    a.stop()
    a.start(["-reindex=1"])
    assert a.rpc().getbestblockhash() == funding_block
    assert a.rpc().gettxout(funding.txid_hex, 0) is not None
    return {"scope": "ACTUAL_TWO_NODE_INVALID_WITNESS_ENFORCEMENT_NOT_VALID_SPEND",
            "genesis": GENESIS, "funding_txid": funding.txid_hex, "tip": funding_block,
            "negative_operations": observations, "reorg_and_reindex": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--validation-only", action="store_true", required=True)
    args = parser.parse_args()
    assert os.uname().sysname == "Linux" and os.geteuid() != 0
    root = Path(tempfile.mkdtemp(prefix="mldsa-real-node-demo-"))
    nodes = [DemoNode(args.binary, root / ("node" + str(i)), 24843 + i, 24853 + i) for i in range(2)]
    print(json.dumps({"retained_demo_directory": str(root)}), flush=True)
    try:
        for node in nodes:
            node.start()
        result = validation_demo(nodes)
        print(json.dumps({"result": "PASS", **result}), flush=True)
    finally:
        for node in nodes:
            node.stop()
    print("MLDSA_DEMO_VALIDATION_TERMINAL_EXIT_0", flush=True)


if __name__ == "__main__":
    main()
