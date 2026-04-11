#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQ-only wallet raw-signing posture."""

from __future__ import annotations

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import build_active_pq_descriptor_entry
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")
PQ_SIGNATURE_HEX_LEN = 2 * 4480


class WalletPQSignRawTransactionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_block(self):
        return self.nodes[0].generatetodescriptor(1, RAW_TRUE_DESCRIPTOR, called_by_framework=True)[0]

    def fund_entry(self, entry, amount_sat: int) -> str:
        tx = create_wallet_funded_tx(self.nodes[0], bytes(entry.script_pub_key), amount_sat)
        return self.nodes[0].sendrawtransaction(tx.serialize().hex())

    def find_unspent(self, wallet, address: str, txid: str):
        matches = [u for u in wallet.listunspent() if u["address"] == address and u["txid"] == txid]
        assert_equal(len(matches), 1)
        return matches[0]

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("3a" * 32)
        receive_entry = build_active_pq_descriptor_entry(root_seed, internal=False, index=0)

        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_address = sink.getnewaddress()

        node.createwallet(wallet_name="pqsignraw", blank=True)
        wallet = node.get_wallet_rpc("pqsignraw")
        wallet.createpqwalletmanagers(root_seed.hex(), 9)

        self.log.info("Fund a PQ-only wallet and construct a direct raw spend without fundrawtransaction or PSBT")
        assert_equal(wallet.getnewpqaddress("receive"), receive_entry.address)
        funding_txid = self.fund_entry(receive_entry, 6 * COIN)
        self.mine_block()
        funded = self.find_unspent(wallet, receive_entry.address, funding_txid)
        assert_equal(funded["has_private_keys"], True)

        locktime = node.getblockcount()
        raw_tx = node.createrawtransaction(
            [{"txid": funded["txid"], "vout": funded["vout"], "sequence": 0xFFFFFFFE}],
            {sink_address: Decimal("5.99900000")},
            locktime,
        )

        self.log.info("The default raw-signing path should match explicit SIGHASH_ALL on PQ-only wallets")
        signed_default = wallet.signrawtransactionwithwallet(raw_tx)
        assert_equal(signed_default["complete"], True)

        signed_all = wallet.signrawtransactionwithwallet(hexstring=raw_tx, sighashtype="ALL")
        assert_equal(signed_all["complete"], True)
        assert_equal(signed_default["hex"], signed_all["hex"])

        self.log.info("Non-ALL sighash modes remain unsupported on the PQ raw-signing path")
        signed_none = wallet.signrawtransactionwithwallet(hexstring=raw_tx, sighashtype="NONE")
        assert_equal(signed_none["complete"], False)
        assert_equal(signed_none["hex"], raw_tx)

        signed_anyonecanpay = wallet.signrawtransactionwithwallet(
            hexstring=raw_tx,
            sighashtype="ALL|ANYONECANPAY",
        )
        assert_equal(signed_anyonecanpay["complete"], False)
        assert_equal(signed_anyonecanpay["hex"], raw_tx)

        self.log.info("The signed transaction should preserve caller-chosen tx fields and emit the expected PQ witness shape")
        signed_again = wallet.signrawtransactionwithwallet(signed_default["hex"])
        assert_equal(signed_again["complete"], True)
        assert_equal(signed_again["hex"], signed_default["hex"])

        decoded = node.decoderawtransaction(signed_default["hex"])
        assert_equal(decoded["version"], 2)
        assert_equal(decoded["locktime"], locktime)
        assert_equal(decoded["vin"][0]["sequence"], 0xFFFFFFFE)
        assert_equal(len(decoded["vin"][0]["txinwitness"]), 2)
        assert_equal(len(decoded["vin"][0]["txinwitness"][0]), PQ_SIGNATURE_HEX_LEN)
        assert_equal(decoded["vin"][0]["txinwitness"][1], bytes(receive_entry.witness_script).hex())

        self.log.info("Broadcast the signed transaction to prove the owned raw-signing surface is usable end-to-end")
        txid = node.sendrawtransaction(signed_default["hex"])
        assert_equal(txid, decoded["txid"])
        self.mine_block()


if __name__ == "__main__":
    WalletPQSignRawTransactionTest(__file__).main()
