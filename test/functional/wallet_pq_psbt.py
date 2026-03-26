#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQ wallet spendability and PSBT parity."""

from __future__ import annotations

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import (
    build_active_pq_descriptor_entry,
    make_pqpriv_import_request,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")
PQ_PROP_IDENTIFIER = "7071627463"


class WalletPQPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_block(self):
        return self.nodes[0].generatetodescriptor(1, RAW_TRUE_DESCRIPTOR, called_by_framework=True)[0]

    def ensure_wallet_loaded(self, wallet_name):
        node = self.nodes[0]
        if wallet_name not in node.listwallets():
            node.loadwallet(wallet_name)
        return node.get_wallet_rpc(wallet_name)

    def fund_entry(self, entry, amount_sat: int) -> str:
        tx = create_wallet_funded_tx(self.nodes[0], bytes(entry.script_pub_key), amount_sat)
        return self.nodes[0].sendrawtransaction(tx.serialize().hex())

    def find_unspent(self, wallet, address: str, txid: str | None = None):
        matches = [u for u in wallet.listunspent() if u["address"] == address and (txid is None or u["txid"] == txid)]
        assert_equal(len(matches), 1)
        return matches[0]

    def find_output_amount(self, txid: str, address: str, *, blockhash: str) -> Decimal:
        tx = self.nodes[0].getrawtransaction(txid, 2, blockhash)
        for vout in tx["vout"]:
            script_pub_key = vout["scriptPubKey"]
            output_address = script_pub_key.get("address")
            if output_address is None:
                addresses = script_pub_key.get("addresses", [])
                if addresses:
                    output_address = addresses[0]
            if output_address == address:
                return Decimal(str(vout["value"]))
        raise AssertionError(f"Unable to find output for {address} in {txid}")

    def find_pq_props(self, decoded_input):
        return [
            prop for prop in decoded_input.get("proprietary", [])
            if prop["identifier"] == PQ_PROP_IDENTIFIER and prop["subtype"] == 1
        ]

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("36" * 32)
        ext_entries = [build_active_pq_descriptor_entry(root_seed, internal=False, index=i) for i in range(4)]
        int_entries = [build_active_pq_descriptor_entry(root_seed, internal=True, index=i) for i in range(4)]

        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_a = sink.getnewaddress()
        sink_b = sink.getnewaddress()

        self.log.info("Create a blank descriptor wallet with active pqpriv() receive/change managers")
        node.createwallet(wallet_name="pqspend", blank=True)
        wallet = node.get_wallet_rpc("pqspend")
        result = wallet.importdescriptors([
            make_pqpriv_import_request(root_seed, internal=False, active=True, timestamp="now", range_end=9),
            make_pqpriv_import_request(root_seed, internal=True, active=True, timestamp="now", range_end=9),
        ])
        assert all(item["success"] for item in result)

        self.log.info("Fund the first generated PQ address and spend it through sendmany")
        assert_equal(wallet.getnewpqaddress("first receive"), ext_entries[0].address)
        funding_txid = self.fund_entry(ext_entries[0], 6 * COIN)
        self.mine_block()
        funded = self.find_unspent(wallet, ext_entries[0].address, funding_txid)
        assert_equal(funded["spendable"], True)
        assert_equal(funded["amount"], Decimal("6.00000000"))

        sendmany_txid = wallet.sendmany("", {sink_a: Decimal("1.00000000"), sink_b: Decimal("0.50000000")})
        sendmany_blockhash = self.mine_block()
        sendmany_change = self.find_output_amount(sendmany_txid, int_entries[0].address, blockhash=sendmany_blockhash)
        assert self.find_unspent(wallet, int_entries[0].address, sendmany_txid)["amount"] == sendmany_change

        self.log.info("Fund a second PQ address and spend it through walletcreatefundedpsbt/walletprocesspsbt/finalizepsbt")
        assert_equal(wallet.getnewpqaddress("psbt receive"), ext_entries[1].address)
        psbt_funding_txid = self.fund_entry(ext_entries[1], 4 * COIN)
        self.mine_block()
        psbt_utxo = self.find_unspent(wallet, ext_entries[1].address, psbt_funding_txid)

        created = wallet.walletcreatefundedpsbt(
            [{"txid": psbt_utxo["txid"], "vout": psbt_utxo["vout"]}],
            {sink_a: Decimal("1.25000000")},
            0,
            {"add_inputs": False, "fee_rate": 1},
        )
        processed = wallet.walletprocesspsbt(psbt=created["psbt"], finalize=False)
        assert "hex" not in processed

        decoded = node.decodepsbt(processed["psbt"])
        pq_props = self.find_pq_props(decoded["inputs"][0])
        assert_equal(len(pq_props), 1)
        assert pq_props[0]["key"].endswith(ext_entries[1].pk_script.hex())
        assert_equal(len(pq_props[0]["value"]), 2 * 4480)

        finalized = node.finalizepsbt(processed["psbt"])
        assert_equal(finalized["complete"], True)
        node.sendrawtransaction(finalized["hex"])
        self.mine_block()

        self.log.info("Restart, generate a later PQ address, then fund and spend it to confirm persisted next_index and spendability")
        self.restart_node(0, self.extra_args[0])
        node = self.nodes[0]
        wallet = self.ensure_wallet_loaded("pqspend")
        sink = self.ensure_wallet_loaded("sink")
        sink_a = sink.getnewaddress()

        assert_equal(wallet.getnewpqaddress("post-restart receive"), ext_entries[2].address)
        restart_funding_txid = self.fund_entry(ext_entries[2], 3 * COIN)
        self.mine_block()
        restart_utxo = self.find_unspent(wallet, ext_entries[2].address, restart_funding_txid)
        assert_equal(restart_utxo["spendable"], True)

        direct_send_txid = wallet.sendtoaddress(sink_a, 1)
        direct_send_blockhash = self.mine_block()
        direct_change = self.find_output_amount(direct_send_txid, int_entries[2].address, blockhash=direct_send_blockhash)
        assert self.find_unspent(wallet, int_entries[2].address, direct_send_txid)["amount"] == direct_change


if __name__ == "__main__":
    WalletPQPSBTTest(__file__).main()
