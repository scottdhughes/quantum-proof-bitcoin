#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reorg/mempool reconciliation behavior for PQ-signed spends."""

from test_framework.authproxy import JSONRPCException
from test_framework.pqbtc_slo import PQBTCSLORecorder
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
)
from test_framework.pqsig import (
    build_pq_keypair,
    create_wallet_funded_tx,
    sign_segwitv0_input_pq,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework


class PQSigReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.uses_wallet = True

    def run_test(self):
        recorder = PQBTCSLORecorder("feature_pq_reorg")
        try:
            node0, node1 = self.nodes
            self.generate(node0, 110)
            self.sync_all()

            sk_seed, pk_script = build_pq_keypair(bytes.fromhex("61" * 32))
            witness_script = CScript([pk_script, OP_CHECKSIG])
            script_pubkey = script_to_p2wsh_script(witness_script)

            fund_tx = create_wallet_funded_tx(node0, bytes(script_pubkey), amount_sat=5_000_000)
            fund_txid = fund_tx.txid_hex
            self.generateblock(node0, output="raw(51)", transactions=[fund_tx.serialize().hex()])
            self.sync_all()

            self.disconnect_nodes(0, 1)

            dest_spk = bytes(script_to_p2wsh_script(CScript([OP_TRUE])))
            spend_tx = CTransaction()
            spend_tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0), b"", SEQUENCE_FINAL - 1)]
            spend_tx.vout = [CTxOut(fund_tx.vout[0].nValue - 2_000, dest_spk)]
            spend_tx.wit.vtxinwit = [CTxInWitness()]
            sig = sign_segwitv0_input_pq(spend_tx, witness_script, fund_tx.vout[0].nValue, sk_seed, pk_script)
            spend_tx.wit.vtxinwit[0].scriptWitness.stack = [sig, bytes(witness_script)]

            accept = node0.testmempoolaccept([spend_tx.serialize().hex()])[0]
            assert accept["allowed"], accept
            spend_hex = spend_tx.serialize().hex()
            spend_txid = node0.sendrawtransaction(spend_hex)
            self.wait_until(lambda: spend_txid in node0.getrawmempool())

            spend_block = self.generate(node0, 1, sync_fun=lambda: None)[0]
            assert spend_txid not in node0.getrawmempool()

            competing_tip = self.generate(node1, 2, sync_fun=lambda: None)[-1]
            assert node0.getbestblockhash() == spend_block
            assert node1.getbestblockhash() == competing_tip

            self.restart_node(0)
            node0 = self.nodes[0]
            self.connect_nodes(0, 1)
            self.sync_blocks()

            self.wait_until(lambda: node0.getbestblockhash() == competing_tip)
            self.wait_until(lambda: spend_txid in node0.getrawmempool())
            accepted_after_reorg = node1.testmempoolaccept([spend_hex])[0]
            assert accepted_after_reorg["allowed"], accepted_after_reorg
            try:
                node1.sendrawtransaction(spend_hex)
            except JSONRPCException as exc:
                message = exc.error.get("message", "")
                if "already in mempool" not in message and "already known" not in message:
                    raise
            self.wait_until(lambda: spend_txid in node1.getrawmempool())

            final_block = self.generate(node1, 1)[0]
            self.sync_all()
            self.wait_until(lambda: spend_txid not in node0.getrawmempool())
            self.wait_until(lambda: spend_txid not in node1.getrawmempool())
            assert node0.getbestblockhash() == final_block
            assert node1.getbestblockhash() == final_block

            recorder.update(
                reorg_result="competing-branch-reinserted-then-remined",
                restart_node0_before_reconnect=True,
                competing_branch_blocks=2,
                reinserted_tx_count=1,
            )
            recorder.success()
        except Exception as exc:
            recorder.failure(str(exc))
            raise


if __name__ == "__main__":
    PQSigReorgTest(__file__).main()
