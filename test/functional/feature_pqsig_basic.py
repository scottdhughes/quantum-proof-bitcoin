#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Basic positive/negative PQSig flow on regtest."""

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
    OP_TRUE,
)
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework


class PQSigBasicTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.uses_wallet = True

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 101)

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
        accept_good = node.testmempoolaccept([good.serialize().hex()])[0]
        assert accept_good["allowed"], accept_good

        bad_size = tx_from_hex(spend_tx.serialize().hex())
        bad_size.wit.vtxinwit = [CTxInWitness()]
        bad_size.wit.vtxinwit[0].scriptWitness.stack = [sig[:-1], bytes(witness_script)]
        accept_bad_size = node.testmempoolaccept([bad_size.serialize().hex()])[0]
        assert not accept_bad_size["allowed"]

        bad_sig = bytearray(sig)
        bad_sig[20] ^= 0x40
        bad_sig_tx = tx_from_hex(spend_tx.serialize().hex())
        bad_sig_tx.wit.vtxinwit = [CTxInWitness()]
        bad_sig_tx.wit.vtxinwit[0].scriptWitness.stack = [bytes(bad_sig), bytes(witness_script)]
        accept_bad_sig = node.testmempoolaccept([bad_sig_tx.serialize().hex()])[0]
        assert not accept_bad_sig["allowed"]

        spend_txid = node.sendrawtransaction(good.serialize().hex())
        self.generate(node, 1)

        assert spend_txid in node.getrawmempool(False) or node.gettxout(spend_txid, 0) is not None


if __name__ == "__main__":
    PQSigBasicTest(__file__).main()
