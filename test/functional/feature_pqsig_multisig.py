#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PQSig multisig flow (2-of-2 CHECKMULTISIG)."""

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
    OP_2,
    OP_CHECKMULTISIG,
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework


class PQSigMultisigTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

        sk1, pk1 = build_pq_keypair(bytes.fromhex("41" * 32))
        sk2, pk2 = build_pq_keypair(bytes.fromhex("52" * 32))

        witness_script = CScript([OP_2, pk1, pk2, OP_2, OP_CHECKMULTISIG])
        multisig_spk = script_to_p2wsh_script(witness_script)
        fund_tx = create_wallet_funded_tx(node, bytes(multisig_spk), amount_sat=6_000_000)
        fund_txid = fund_tx.txid_hex
        self.generateblock(node, output="raw(51)", transactions=[fund_tx.serialize().hex()])

        dest_spk = bytes(script_to_p2wsh_script(CScript([OP_TRUE])))
        spend_tx = CTransaction()
        spend_tx.vin = [CTxIn(COutPoint(int(fund_txid, 16), 0), b"", SEQUENCE_FINAL - 1)]
        spend_tx.vout = [CTxOut(fund_tx.vout[0].nValue - 3_000, dest_spk)]
        spend_tx.wit.vtxinwit = [CTxInWitness()]

        sig1 = sign_segwitv0_input_pq(spend_tx, witness_script, fund_tx.vout[0].nValue, sk1, pk1)
        sig2 = sign_segwitv0_input_pq(spend_tx, witness_script, fund_tx.vout[0].nValue, sk2, pk2)

        good = tx_from_hex(spend_tx.serialize().hex())
        good.wit.vtxinwit = [CTxInWitness()]
        good.wit.vtxinwit[0].scriptWitness.stack = [b"", sig1, sig2, bytes(witness_script)]
        good_accept = node.testmempoolaccept([good.serialize().hex()])[0]
        assert good_accept["allowed"], good_accept

        bad_sig2 = bytearray(sig2)
        bad_sig2[15] ^= 0x01
        bad = tx_from_hex(spend_tx.serialize().hex())
        bad.wit.vtxinwit = [CTxInWitness()]
        bad.wit.vtxinwit[0].scriptWitness.stack = [b"", sig1, bytes(bad_sig2), bytes(witness_script)]
        assert not node.testmempoolaccept([bad.serialize().hex()])[0]["allowed"]

        txid = node.sendrawtransaction(good.serialize().hex())
        self.generate(node, 1)
        assert txid


if __name__ == "__main__":
    PQSigMultisigTest(__file__).main()
