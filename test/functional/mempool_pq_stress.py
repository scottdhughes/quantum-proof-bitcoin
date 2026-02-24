#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Relay and mempool stress scenarios for PQ witness-heavy traffic."""

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
)
from test_framework.authproxy import JSONRPCException
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.script import CScript, OP_DROP, OP_TRUE
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework


class MempoolPQStressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.uses_wallet = True

    def run_test(self):
        node0, node1 = self.nodes
        self.generate(node0, 120)
        self.sync_all()

        witness_script = CScript([OP_DROP, OP_TRUE])
        p2wsh_spk = script_to_p2wsh_script(witness_script)
        dest_spk = bytes(script_to_p2wsh_script(CScript([OP_TRUE])))

        fund_txs = []
        fund_hex = []
        for _ in range(12):
            fund_tx = create_wallet_funded_tx(node0, bytes(p2wsh_spk), amount_sat=3_000_000)
            fund_txid = fund_tx.txid_hex
            fund_txs.append((fund_tx, fund_txid))
            fund_hex.append(fund_tx.serialize().hex())
        self.generateblock(node0, output="raw(51)", transactions=fund_hex)
        self.sync_all()

        def build_witness_heavy_spend(*, fund_txid: str, amount: int, payload_size: int, fee_sat: int) -> CTransaction:
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0), b"", SEQUENCE_FINAL - 1)]
            tx.vout = [CTxOut(amount - fee_sat, dest_spk)]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [b"S" * payload_size, bytes(witness_script)]
            return tx

        spend_txids = []
        for idx, (fund_tx, fund_txid) in enumerate(fund_txs):
            spend = build_witness_heavy_spend(
                fund_txid=fund_txid,
                amount=fund_tx.vout[0].nValue,
                payload_size=9_100 + (idx % 5) * 100,
                fee_sat=25_000 + idx * 1_000,
            )
            spend_hex = spend.serialize().hex()
            accepted0 = node0.testmempoolaccept([spend_hex])[0]
            accepted1 = node1.testmempoolaccept([spend_hex])[0]
            assert accepted0["allowed"], accepted0
            assert accepted1["allowed"], accepted1
            txid = node0.sendrawtransaction(spend_hex)
            spend_txids.append(txid)
            try:
                node1.sendrawtransaction(spend_hex)
            except JSONRPCException as exc:
                message = exc.error.get("message", "")
                if "already in mempool" not in message and "already known" not in message:
                    raise

        for txid in spend_txids:
            self.wait_until(lambda txid=txid: txid in node0.getrawmempool(False))
            self.wait_until(lambda txid=txid: txid in node1.getrawmempool(False))

        self.restart_node(1)
        node1 = self.nodes[1]
        self.connect_nodes(0, 1)
        self.sync_all()
        for txid in spend_txids:
            self.wait_until(lambda txid=txid: txid in node1.getrawmempool(False))

        stress_block = self.generate(node1, 1)[0]
        self.sync_all()
        for txid in spend_txids:
            assert txid not in node0.getrawmempool(False)
            assert txid not in node1.getrawmempool(False)

        node1.invalidateblock(stress_block)
        for txid in spend_txids:
            self.wait_until(lambda txid=txid: txid in node1.getrawmempool(False))

        node1.reconsiderblock(stress_block)
        self.sync_all()
        for txid in spend_txids:
            self.wait_until(lambda txid=txid: txid not in node1.getrawmempool(False))


if __name__ == "__main__":
    MempoolPQStressTest(__file__).main()
