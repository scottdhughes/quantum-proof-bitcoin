#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQ-only wallet send RPC posture."""

from __future__ import annotations

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN, tx_from_hex
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import build_active_pq_descriptor_entry
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")


class WalletPQSendTest(BitcoinTestFramework):
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
        root_seed = bytes.fromhex("39" * 32)
        receive_entry = build_active_pq_descriptor_entry(root_seed, internal=False, index=0)

        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_address = sink.getnewaddress()

        node.createwallet(wallet_name="pqsend", blank=True)
        wallet = node.get_wallet_rpc("pqsend")
        wallet.createpqwalletmanagers(root_seed.hex(), 9)

        self.log.info("Fund the PQ-only wallet and exercise the default send RPC path")
        assert_equal(wallet.getnewpqaddress("receive"), receive_entry.address)
        self.fund_entry(receive_entry, 6 * COIN)
        self.mine_block()

        default_res = wallet.send(outputs={sink_address: Decimal("1.00000000")})
        assert_equal(default_res["complete"], True)
        default_tx = wallet.gettransaction(txid=default_res["txid"], verbose=True)
        assert_greater_than_or_equal(default_tx["decoded"]["locktime"], node.getblockcount() - 100)
        assert default_tx["decoded"]["locktime"] <= node.getblockcount()
        assert_equal(tx_from_hex(default_tx["hex"]).version, 2)
        self.mine_block()

        self.log.info("Respect an explicit locktime override on the PQ-only send RPC path")
        locked_res = wallet.send(
            outputs={sink_address: Decimal("0.50000000")},
            options={"locktime": 0},
        )
        assert_equal(locked_res["complete"], True)
        locked_tx = wallet.gettransaction(txid=locked_res["txid"], verbose=True)
        assert_equal(locked_tx["decoded"]["locktime"], 0)
        assert_equal(tx_from_hex(locked_tx["hex"]).version, 2)


if __name__ == '__main__':
    WalletPQSendTest(__file__).main()
