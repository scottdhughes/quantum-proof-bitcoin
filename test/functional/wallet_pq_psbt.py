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

    def find_decoded_output_address(self, decoded_tx, vout_index: int) -> str:
        script_pub_key = decoded_tx["vout"][vout_index]["scriptPubKey"]
        output_address = script_pub_key.get("address")
        if output_address is None:
            addresses = script_pub_key.get("addresses", [])
            if addresses:
                output_address = addresses[0]
        if output_address is None:
            raise AssertionError(f"Unable to resolve output address at vout={vout_index}")
        return output_address

    def find_pq_props(self, decoded_input):
        return [
            prop for prop in decoded_input.get("proprietary", [])
            if prop["identifier"] == PQ_PROP_IDENTIFIER and prop["subtype"] == 1
        ]

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("36" * 32)
        import_root_seed = bytes.fromhex("37" * 32)
        ext_entries = [build_active_pq_descriptor_entry(root_seed, internal=False, index=i) for i in range(5)]
        int_entries = [build_active_pq_descriptor_entry(root_seed, internal=True, index=i) for i in range(7)]
        import_ext_entries = [build_active_pq_descriptor_entry(import_root_seed, internal=False, index=i) for i in range(2)]

        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_a = sink.getnewaddress()
        sink_b = sink.getnewaddress()

        self.log.info("Create a blank descriptor wallet with active PQ receive/change managers via the dedicated setup RPC")
        node.createwallet(wallet_name="pqspend", blank=True)
        wallet = node.get_wallet_rpc("pqspend")
        result = wallet.createpqwalletmanagers(root_seed.hex(), 9)
        assert_equal(result["receive"]["desc"], make_pqpriv_import_request(root_seed, internal=False, active=True, timestamp="now", range_end=9)["desc"])
        assert_equal(result["receive"]["range"], [0, 9])
        assert_equal(result["receive"]["next_index"], 0)
        assert_equal(result["change"]["desc"], make_pqpriv_import_request(root_seed, internal=True, active=True, timestamp="now", range_end=9)["desc"])
        assert_equal(result["change"]["range"], [0, 9])
        assert_equal(result["change"]["next_index"], 0)

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
        sink_b = sink.getnewaddress()

        assert_equal(wallet.getnewpqaddress("post-restart receive"), ext_entries[2].address)
        restart_funding_txid = self.fund_entry(ext_entries[2], 3 * COIN)
        self.mine_block()
        restart_utxo = self.find_unspent(wallet, ext_entries[2].address, restart_funding_txid)
        assert_equal(restart_utxo["spendable"], True)

        direct_send_txid = wallet.sendtoaddress(sink_a, 1)
        direct_send_blockhash = self.mine_block()
        direct_change = self.find_output_amount(direct_send_txid, int_entries[2].address, blockhash=direct_send_blockhash)
        assert self.find_unspent(wallet, int_entries[2].address, direct_send_txid)["amount"] == direct_change

        self.log.info("Fund a raw transaction and confirm automatic PQ change stays on the active internal manager")
        raw_tx = node.createrawtransaction([], {sink_b: Decimal("0.75000000")})
        funded = wallet.fundrawtransaction(raw_tx, {"fee_rate": 1})
        assert funded["changepos"] >= 0
        decoded_funded = node.decoderawtransaction(funded["hex"])
        assert_equal(self.find_decoded_output_address(decoded_funded, funded["changepos"]), int_entries[3].address)

        signed = wallet.signrawtransactionwithwallet(funded["hex"])
        assert_equal(signed["complete"], True)
        funded_txid = node.sendrawtransaction(signed["hex"])
        funded_blockhash = self.mine_block()
        funded_change = self.find_output_amount(funded_txid, int_entries[3].address, blockhash=funded_blockhash)
        assert self.find_unspent(wallet, int_entries[3].address, funded_txid)["amount"] == funded_change

        self.log.info("Create a PQ-native PSBT with automatic input selection and confirm automatic PQ change")
        auto_created = wallet.walletcreatefundedpsbt(
            [],
            {sink_b: Decimal("0.60000000")},
            0,
            {"add_inputs": True, "fee_rate": 1},
        )
        assert auto_created["changepos"] >= 0
        decoded_auto_created = node.decodepsbt(auto_created["psbt"])
        assert_equal(self.find_decoded_output_address(decoded_auto_created["tx"], auto_created["changepos"]), int_entries[4].address)

        auto_processed = wallet.walletprocesspsbt(psbt=auto_created["psbt"], finalize=False)
        assert "hex" not in auto_processed
        decoded_auto_processed = node.decodepsbt(auto_processed["psbt"])
        assert len(decoded_auto_processed["inputs"]) >= 1
        for decoded_input in decoded_auto_processed["inputs"]:
            pq_props = self.find_pq_props(decoded_input)
            assert_equal(len(pq_props), 1)
            assert_equal(len(pq_props[0]["value"]), 2 * 4480)

        auto_finalized = node.finalizepsbt(auto_processed["psbt"])
        assert_equal(auto_finalized["complete"], True)
        auto_txid = node.sendrawtransaction(auto_finalized["hex"])
        auto_blockhash = self.mine_block()
        auto_change = self.find_output_amount(auto_txid, int_entries[4].address, blockhash=auto_blockhash)
        assert self.find_unspent(wallet, int_entries[4].address, auto_txid)["amount"] == auto_change

        self.log.info("Respect walletcreatefundedpsbt changePosition while keeping PQ change on the active internal manager")
        positioned = wallet.walletcreatefundedpsbt(
            [],
            {sink_a: Decimal("0.45000000")},
            0,
            {"add_inputs": True, "fee_rate": 1, "changePosition": 1},
        )
        assert_equal(positioned["changepos"], 1)
        decoded_positioned = node.decodepsbt(positioned["psbt"])
        assert_equal(self.find_decoded_output_address(decoded_positioned["tx"], positioned["changepos"]), int_entries[5].address)

        positioned_processed = wallet.walletprocesspsbt(psbt=positioned["psbt"], finalize=False)
        decoded_positioned_processed = node.decodepsbt(positioned_processed["psbt"])
        for decoded_input in decoded_positioned_processed["inputs"]:
            pq_props = self.find_pq_props(decoded_input)
            assert_equal(len(pq_props), 1)
            assert_equal(len(pq_props[0]["value"]), 2 * 4480)

        positioned_finalized = node.finalizepsbt(positioned_processed["psbt"])
        assert_equal(positioned_finalized["complete"], True)
        positioned_txid = node.sendrawtransaction(positioned_finalized["hex"])
        positioned_blockhash = self.mine_block()
        positioned_change = self.find_output_amount(positioned_txid, int_entries[5].address, blockhash=positioned_blockhash)
        assert self.find_unspent(wallet, int_entries[5].address, positioned_txid)["amount"] == positioned_change

        self.log.info("Respect walletcreatefundedpsbt subtractFeeFromOutputs while keeping PQ change on the active internal manager")
        subtracting = wallet.walletcreatefundedpsbt(
            [],
            {sink_b: Decimal("0.40000000")},
            0,
            {"add_inputs": True, "fee_rate": 1, "subtractFeeFromOutputs": [0]},
        )
        assert subtracting["changepos"] >= 0
        decoded_subtracting = node.decodepsbt(subtracting["psbt"])
        assert_equal(self.find_decoded_output_address(decoded_subtracting["tx"], subtracting["changepos"]), int_entries[6].address)

        subtracting_processed = wallet.walletprocesspsbt(psbt=subtracting["psbt"], finalize=False)
        decoded_subtracting_processed = node.decodepsbt(subtracting_processed["psbt"])
        for decoded_input in decoded_subtracting_processed["inputs"]:
            pq_props = self.find_pq_props(decoded_input)
            assert_equal(len(pq_props), 1)
            assert_equal(len(pq_props[0]["value"]), 2 * 4480)

        subtracting_finalized = node.finalizepsbt(subtracting_processed["psbt"])
        assert_equal(subtracting_finalized["complete"], True)
        subtracting_txid = node.sendrawtransaction(subtracting_finalized["hex"])
        subtracting_blockhash = self.mine_block()
        subtracting_change = self.find_output_amount(subtracting_txid, int_entries[6].address, blockhash=subtracting_blockhash)
        assert self.find_unspent(wallet, int_entries[6].address, subtracting_txid)["amount"] == subtracting_change
        recipient_amount = self.find_output_amount(subtracting_txid, sink_b, blockhash=subtracting_blockhash)
        assert recipient_amount < Decimal("0.40000000")

        self.log.info("Keep lower-level pqpriv() import coverage alive for descriptor-level setup")
        node.createwallet(wallet_name="pqspend_import", blank=True)
        imported_wallet = node.get_wallet_rpc("pqspend_import")
        import_result = imported_wallet.importdescriptors([
            make_pqpriv_import_request(import_root_seed, internal=False, active=True, timestamp="now", range_end=3),
            make_pqpriv_import_request(import_root_seed, internal=True, active=True, timestamp="now", range_end=3),
        ])
        assert all(item["success"] for item in import_result)
        assert_equal(imported_wallet.getnewpqaddress("imported receive"), import_ext_entries[0].address)
        assert_equal(imported_wallet.getnewpqaddress(), import_ext_entries[1].address)


if __name__ == "__main__":
    WalletPQPSBTTest(__file__).main()
