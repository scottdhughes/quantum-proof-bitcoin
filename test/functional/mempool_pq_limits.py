#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Policy boundary checks for PQSig and large witness elements."""

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    SEQUENCE_FINAL,
    tx_from_hex,
)
from test_framework.pqsig import (
    build_pq_keypair,
    create_wallet_funded_tx,
    sign_segwitv0_input_pq,
)
from test_framework.script import (
    CScript,
    OP_CHECKSIG,
    OP_DROP,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework


class MempoolPQLimitsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        self._check_pqsig_signature_size_boundaries(node)
        self._check_witness_item_boundaries(node)
        self._check_churn_and_rbf_under_large_witness(node)

    def _check_pqsig_signature_size_boundaries(self, node):
        sk_seed, pk_script = build_pq_keypair(bytes.fromhex("31" * 32))
        witness_script = CScript([pk_script, OP_CHECKSIG])
        script_pubkey = script_to_p2wsh_script(witness_script)

        fund_tx = create_wallet_funded_tx(node, bytes(script_pubkey), amount_sat=5_000_000)
        fund_txid = fund_tx.txid_hex
        self.generateblock(node, output="raw(51)", transactions=[fund_tx.serialize().hex()])

        dest_spk = bytes(script_to_p2wsh_script(CScript([OP_TRUE])))
        spend_tx = CTransaction()
        spend_tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0), b"", SEQUENCE_FINAL - 1)]
        spend_tx.vout = [CTxOut(fund_tx.vout[0].nValue - 2_000, dest_spk)]
        spend_tx.wit.vtxinwit = [CTxInWitness()]

        sig = sign_segwitv0_input_pq(spend_tx, witness_script, fund_tx.vout[0].nValue, sk_seed, pk_script)

        good = tx_from_hex(spend_tx.serialize().hex())
        good.wit.vtxinwit = [CTxInWitness()]
        good.wit.vtxinwit[0].scriptWitness.stack = [sig, bytes(witness_script)]
        good_accept = node.testmempoolaccept([good.serialize().hex()])[0]
        assert good_accept["allowed"], good_accept

        short_sig_tx = tx_from_hex(spend_tx.serialize().hex())
        short_sig_tx.wit.vtxinwit = [CTxInWitness()]
        short_sig_tx.wit.vtxinwit[0].scriptWitness.stack = [sig[:-1], bytes(witness_script)]
        assert not node.testmempoolaccept([short_sig_tx.serialize().hex()])[0]["allowed"]

        long_sig_tx = tx_from_hex(spend_tx.serialize().hex())
        long_sig_tx.wit.vtxinwit = [CTxInWitness()]
        long_sig_tx.wit.vtxinwit[0].scriptWitness.stack = [sig + b"\x00", bytes(witness_script)]
        assert not node.testmempoolaccept([long_sig_tx.serialize().hex()])[0]["allowed"]

    def _check_witness_item_boundaries(self, node):
        witness_script = CScript([OP_DROP, OP_TRUE])
        p2wsh_spk = script_to_p2wsh_script(witness_script)

        fund_tx = create_wallet_funded_tx(node, bytes(p2wsh_spk), amount_sat=4_000_000)
        fund_txid = fund_tx.txid_hex
        self.generateblock(node, output="raw(51)", transactions=[fund_tx.serialize().hex()])

        def build_spend(item_size: int) -> CTransaction:
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0), b"", SEQUENCE_FINAL - 1)]
            dest_spk = bytes(script_to_p2wsh_script(CScript([OP_TRUE])))
            tx.vout = [CTxOut(fund_tx.vout[0].nValue - 2_000, dest_spk)]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [b"X" * item_size, bytes(witness_script)]
            return tx

        at_limit = build_spend(10_000)
        assert node.testmempoolaccept([at_limit.serialize().hex()])[0]["allowed"]

        over_limit = build_spend(10_001)
        assert not node.testmempoolaccept([over_limit.serialize().hex()])[0]["allowed"]

    def _check_churn_and_rbf_under_large_witness(self, node):
        witness_script = CScript([OP_DROP, OP_TRUE])
        p2wsh_spk = script_to_p2wsh_script(witness_script)
        dest_spk = bytes(script_to_p2wsh_script(CScript([OP_TRUE])))

        fund_tx = create_wallet_funded_tx(node, bytes(p2wsh_spk), amount_sat=6_000_000)
        fund_txid = fund_tx.txid_hex
        self.generateblock(node, output="raw(51)", transactions=[fund_tx.serialize().hex()])

        def build_spend(*, txid_hex: str, amount: int, payload_size: int, fee_sat: int, sequence: int) -> CTransaction:
            tx = CTransaction()
            tx.vin = [CTxIn(COutPoint(int(txid_hex, 16), 0), b"", sequence)]
            tx.vout = [CTxOut(amount - fee_sat, dest_spk)]
            tx.wit.vtxinwit = [CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [b"R" * payload_size, bytes(witness_script)]
            return tx

        # Stable reject reason for malformed oversized witness item.
        oversized = build_spend(
            txid_hex=fund_txid,
            amount=fund_tx.vout[0].nValue,
            payload_size=10_001,
            fee_sat=3_000,
            sequence=SEQUENCE_FINAL - 2,
        )
        reject1 = node.testmempoolaccept([oversized.serialize().hex()])[0]
        reject2 = node.testmempoolaccept([oversized.serialize().hex()])[0]
        assert not reject1["allowed"]
        assert not reject2["allowed"]
        reject_reason = reject1.get("reject-reason", "")
        assert reject_reason != ""
        assert reject_reason == reject2.get("reject-reason", "")

        # Reject reason must remain stable across restart.
        self.restart_node(0)
        node = self.nodes[0]
        reject3 = node.testmempoolaccept([oversized.serialize().hex()])[0]
        assert not reject3["allowed"]
        assert reject_reason == reject3.get("reject-reason", "")

        # RBF churn with large witness payloads.
        replacement_fees = [3_000, 5_000, 7_000, 9_000, 11_000]
        last_txid = None
        for fee_sat in replacement_fees:
            candidate = build_spend(
                txid_hex=fund_txid,
                amount=fund_tx.vout[0].nValue,
                payload_size=9_500,
                fee_sat=fee_sat,
                sequence=SEQUENCE_FINAL - 2,
            )
            result = node.testmempoolaccept([candidate.serialize().hex()])[0]
            assert result["allowed"], result
            txid = node.sendrawtransaction(candidate.serialize().hex())
            self.wait_until(lambda: txid in node.getrawmempool(False))
            if last_txid is not None:
                assert last_txid not in node.getrawmempool(False)
            last_txid = txid

        # Sustained large-witness churn from independent UTXOs.
        batch_funds = []
        batch_fund_hex = []
        for _ in range(8):
            batch_fund = create_wallet_funded_tx(node, bytes(p2wsh_spk), amount_sat=3_000_000)
            batch_fund_txid = batch_fund.txid_hex
            batch_funds.append((batch_fund, batch_fund_txid))
            batch_fund_hex.append(batch_fund.serialize().hex())
        self.generateblock(node, output="raw(51)", transactions=batch_fund_hex)

        churn_txids = []
        for idx, (batch_fund, batch_fund_txid) in enumerate(batch_funds):
            spend = build_spend(
                txid_hex=batch_fund_txid,
                amount=batch_fund.vout[0].nValue,
                payload_size=9_000 + (idx % 4) * 100,
                fee_sat=2_500 + idx * 100,
                sequence=SEQUENCE_FINAL - 1,
            )
            accepted = node.testmempoolaccept([spend.serialize().hex()])[0]
            assert accepted["allowed"], accepted
            churn_txids.append(node.sendrawtransaction(spend.serialize().hex()))

        for txid in churn_txids:
            self.wait_until(lambda txid=txid: txid in node.getrawmempool(False))

        self.restart_node(0)
        node = self.nodes[0]
        for txid in churn_txids:
            self.wait_until(lambda txid=txid: txid in node.getrawmempool(False))

        self.generate(node, 1)
        for txid in churn_txids:
            assert txid not in node.getrawmempool(False)


if __name__ == "__main__":
    MempoolPQLimitsTest(__file__).main()
