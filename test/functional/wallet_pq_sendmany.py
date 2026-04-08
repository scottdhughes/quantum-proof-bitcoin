#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQ-only wallet sendmany RPC posture."""

from __future__ import annotations

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN, tx_from_hex
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import build_active_pq_descriptor_entry
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")


class WalletPQSendmanyTest(BitcoinTestFramework):
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

    def find_output_amount(self, decoded_tx, address: str) -> Decimal:
        for vout in decoded_tx["vout"]:
            script_pub_key = vout["scriptPubKey"]
            output_address = script_pub_key.get("address")
            if output_address is None:
                addresses = script_pub_key.get("addresses", [])
                if addresses:
                    output_address = addresses[0]
            if output_address == address:
                return Decimal(str(vout["value"]))
        raise AssertionError(f"Unable to find output for {address}")

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("3b" * 32)
        receive_entries = [
            build_active_pq_descriptor_entry(root_seed, internal=False, index=0),
            build_active_pq_descriptor_entry(root_seed, internal=False, index=1),
        ]

        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_a = sink.getnewaddress()
        sink_b = sink.getnewaddress()

        node.createwallet(wallet_name="pqsendmany", blank=True)
        wallet = node.get_wallet_rpc("pqsendmany")
        wallet.createpqwalletmanagers(root_seed.hex(), 9)

        self.log.info("Fund the PQ-only wallet and exercise default sendmany")
        assert_equal(wallet.getnewpqaddress("receive-0"), receive_entries[0].address)
        self.fund_entry(receive_entries[0], 6 * COIN)
        self.mine_block()

        default_txid = wallet.sendmany("", {sink_a: Decimal("1.00000000"), sink_b: Decimal("0.50000000")})
        default_tx = wallet.gettransaction(txid=default_txid, verbose=True)
        assert_greater_than_or_equal(default_tx["decoded"]["locktime"], node.getblockcount() - 100)
        assert default_tx["decoded"]["locktime"] <= node.getblockcount()
        assert_equal(tx_from_hex(default_tx["hex"]).version, 2)
        assert_equal(self.find_output_amount(default_tx["decoded"], sink_a), Decimal("1.00000000"))
        assert_equal(self.find_output_amount(default_tx["decoded"], sink_b), Decimal("0.50000000"))
        self.mine_block()

        self.log.info("Respect subtractfeefrom on the PQ-only sendmany path")
        assert_equal(wallet.getnewpqaddress("receive-1"), receive_entries[1].address)
        self.fund_entry(receive_entries[1], 4 * COIN)
        self.mine_block()

        subtract_txid = wallet.sendmany(
            "",
            {sink_a: Decimal("0.80000000"), sink_b: Decimal("0.60000000")},
            subtractfeefrom=[sink_a],
        )
        subtract_tx = wallet.gettransaction(txid=subtract_txid, verbose=True)
        assert_greater_than_or_equal(subtract_tx["decoded"]["locktime"], node.getblockcount() - 100)
        assert subtract_tx["decoded"]["locktime"] <= node.getblockcount()
        assert_equal(tx_from_hex(subtract_tx["hex"]).version, 2)
        assert self.find_output_amount(subtract_tx["decoded"], sink_a) < Decimal("0.80000000")
        assert_equal(self.find_output_amount(subtract_tx["decoded"], sink_b), Decimal("0.60000000"))


if __name__ == '__main__':
    WalletPQSendmanyTest(__file__).main()
