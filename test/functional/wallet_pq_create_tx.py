#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQ-only wallet direct transaction creation posture."""

from __future__ import annotations

from decimal import Decimal

from test_framework.blocktools import TIME_GENESIS_BLOCK
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN, tx_from_hex
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import build_active_pq_descriptor_entry
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")


class WalletPQCreateTxTest(BitcoinTestFramework):
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

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("38" * 32)
        receive_entry = build_active_pq_descriptor_entry(root_seed, internal=False, index=0)

        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_address = sink.getnewaddress()

        node.createwallet(wallet_name="pqcreate", blank=True)
        wallet = node.get_wallet_rpc("pqcreate")
        wallet.createpqwalletmanagers(root_seed.hex(), 9)

        self.log.info("Create an old tip and fund the PQ-only wallet under that old chain history")
        node.setmocktime(TIME_GENESIS_BLOCK)
        assert_equal(wallet.getnewpqaddress("old receive"), receive_entry.address)
        self.fund_entry(receive_entry, 6 * COIN)
        self.mine_block()
        node.setmocktime(0)

        self.log.info("Keep anti-fee-sniping disabled on old tips while preserving wallet tx version 2")
        old_txid = wallet.sendtoaddress(sink_address, Decimal("1.00000000"))
        old_tx = wallet.gettransaction(txid=old_txid, verbose=True)
        assert_equal(old_tx["decoded"]["locktime"], 0)
        assert_equal(tx_from_hex(old_tx["hex"]).version, 2)

        self.log.info("Mine a recent block and re-check the direct send path on the PQ-only wallet")
        self.mine_block()
        recent_txid = wallet.sendtoaddress(sink_address, Decimal("0.50000000"))
        recent_tx = wallet.gettransaction(txid=recent_txid, verbose=True)
        assert 0 < recent_tx["decoded"]["locktime"] <= node.getblockcount()
        assert_equal(tx_from_hex(recent_tx["hex"]).version, 2)


if __name__ == '__main__':
    WalletPQCreateTxTest(__file__).main()
