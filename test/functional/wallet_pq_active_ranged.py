#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test active ranged pqpriv() descriptor wallet managers."""

from __future__ import annotations

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import (
    build_active_pq_descriptor_entry,
    make_pqpriv_descriptor,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")


class WalletPQActiveRangedTest(BitcoinTestFramework):
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

    def descriptor_state(self, wallet):
        descriptors = {}
        for item in wallet.listdescriptors(True)["descriptors"]:
            descriptors[item["desc"]] = {
                "active": item["active"],
                "internal": item["internal"],
                "range": item["range"],
                "next_index": item["next_index"],
            }
        return descriptors

    def assert_descriptor_state(
        self,
        wallet,
        root_seed: bytes,
        *,
        external_next: int,
        internal_next: int,
        external_range: list[int] | None = None,
        internal_range: list[int] | None = None,
    ):
        if external_range is None:
            external_range = [0, 9]
        if internal_range is None:
            internal_range = [0, 9]
        descs = self.descriptor_state(wallet)
        expected = {
            make_pqpriv_descriptor(root_seed, False): {
                "active": True,
                "internal": False,
                "range": external_range,
                "next_index": external_next,
            },
            make_pqpriv_descriptor(root_seed, True): {
                "active": True,
                "internal": True,
                "range": internal_range,
                "next_index": internal_next,
            },
        }
        assert_equal(descs, expected)

    def assert_keypool_info(self, wallet, *, external: int, internal: int):
        info = wallet.getwalletinfo()
        assert_equal(info["keypoolsize"], external)
        assert_equal(info["keypoolsize_hd_internal"], internal)

    def assert_address_info(self, wallet, entry, *, is_change: bool, label: str | None = None):
        info = wallet.getaddressinfo(entry.address)
        assert_equal(info["desc"], entry.descriptor)
        assert_equal(info["ismine"], True)
        assert_equal(info["has_private_keys"], True)
        assert_equal(info["solvable"], True)
        assert_equal(info["ischange"], is_change)
        assert "parent_desc" not in info
        if label is not None:
            assert_equal(info["labels"], [label])

    def assert_owned_unspent(self, wallet, txid: str, entry, amount: Decimal, *, category: str | None = "receive"):
        if category is not None:
            tx = wallet.gettransaction(txid)
            details = [detail for detail in tx["details"] if detail["address"] == entry.address]
            assert_equal(len(details), 1)
            assert_equal(details[0]["category"], category)
        unspent = wallet.listunspent()
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]["txid"], txid)
        assert_equal(unspent[0]["address"], entry.address)
        assert_equal(unspent[0]["amount"], amount)
        assert_equal(unspent[0]["spendable"], True)
        assert_equal(unspent[0]["has_private_keys"], True)
        assert_equal(wallet.getbalances()["mine"]["trusted"], amount)

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

    def fund_entry(self, entry, amount_sat: int) -> str:
        tx = create_wallet_funded_tx(self.nodes[0], bytes(entry.script_pub_key), amount_sat)
        return self.nodes[0].sendrawtransaction(tx.serialize().hex())

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("24" * 32)
        ext_entries = [build_active_pq_descriptor_entry(root_seed, internal=False, index=i) for i in range(6)]
        int_entries = [build_active_pq_descriptor_entry(root_seed, internal=True, index=i) for i in range(4)]
        node.createwallet(wallet_name="sink")
        sink_wallet = node.get_wallet_rpc("sink")
        sink_addr = sink_wallet.getnewaddress()

        self.log.info("Reject PQ manager setup on wallets that already have active address managers")
        assert_raises_rpc_error(
            -4,
            "createpqwalletmanagers requires a wallet without active address managers",
            sink_wallet.createpqwalletmanagers,
            root_seed.hex(),
            9,
        )
        assert_raises_rpc_error(
            -8,
            "next_index is out of range",
            sink_wallet.createpqwalletmanagers,
            root_seed.hex(),
            9,
            10,
        )

        self.log.info("Create a blank descriptor wallet and activate the dedicated PQ receive/change managers")
        node.createwallet(wallet_name="pqactive", blank=True)
        wallet = node.get_wallet_rpc("pqactive")
        result = wallet.createpqwalletmanagers(root_seed.hex(), 9)
        assert_equal(result["receive"]["desc"], make_pqpriv_descriptor(root_seed, False))
        assert_equal(result["receive"]["active"], True)
        assert_equal(result["receive"]["internal"], False)
        assert_equal(result["receive"]["range"], [0, 9])
        assert_equal(result["receive"]["next_index"], 0)
        assert_equal(result["change"]["desc"], make_pqpriv_descriptor(root_seed, True))
        assert_equal(result["change"]["active"], True)
        assert_equal(result["change"]["internal"], True)
        assert_equal(result["change"]["range"], [0, 9])
        assert_equal(result["change"]["next_index"], 0)
        assert_raises_rpc_error(
            -4,
            "createpqwalletmanagers requires a wallet without active address managers",
            wallet.createpqwalletmanagers,
            root_seed.hex(),
            9,
        )

        self.assert_descriptor_state(wallet, root_seed, external_next=0, internal_next=0)
        self.assert_keypool_info(wallet, external=10, internal=10)
        assert_raises_rpc_error(-4, "Public export for ranged pqpriv() descriptors is not available.", wallet.listdescriptors, False)
        assert_equal(wallet.gethdkeys(), [])
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress",
            wallet.getnewaddress,
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress",
            wallet.getnewaddress,
            "",
            "bech32",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress",
            wallet.getnewaddress,
            "",
            "legacy",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress",
            wallet.getnewaddress,
            "",
            "p2sh-segwit",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress",
            wallet.getrawchangeaddress,
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress",
            wallet.getrawchangeaddress,
            "bech32",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress",
            wallet.getrawchangeaddress,
            "legacy",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress",
            wallet.getrawchangeaddress,
            "p2sh-segwit",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not expose HD keys; createwalletdescriptor only supports xpub-based descriptor families",
            wallet.createwalletdescriptor,
            "bech32",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not expose HD keys; createwalletdescriptor only supports xpub-based descriptor families",
            wallet.createwalletdescriptor,
            "bech32m",
        )

        self.log.info("Generate receive/change PQ addresses from the active managers")
        first_label = "pq receive"
        assert_equal(wallet.getnewpqaddress(first_label), ext_entries[0].address)
        assert_equal(wallet.getnewpqaddress(), ext_entries[1].address)
        assert_equal(wallet.getnewpqaddress(), ext_entries[2].address)
        assert_equal(wallet.getrawpqchangeaddress(), int_entries[0].address)

        self.assert_address_info(wallet, ext_entries[0], is_change=False, label=first_label)
        self.assert_address_info(wallet, ext_entries[2], is_change=False)
        self.assert_address_info(wallet, int_entries[0], is_change=True)
        self.assert_descriptor_state(wallet, root_seed, external_next=3, internal_next=1)
        self.assert_keypool_info(wallet, external=7, internal=9)

        self.log.info("Use keypoolrefill to expand the active PQ receive/change ranges")
        wallet.keypoolrefill(12)
        self.assert_descriptor_state(
            wallet,
            root_seed,
            external_next=3,
            internal_next=1,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(wallet, external=12, internal=12)

        self.log.info("Fund a later generated PQ address and confirm it is tracked and spendable")
        txid = self.fund_entry(ext_entries[2], 4 * COIN)
        self.mine_block()
        self.assert_owned_unspent(wallet, txid, ext_entries[2], Decimal("4.00000000"))

        self.log.info("Spend from the funded PQ output and confirm automatic PQ change uses the active internal manager")
        spend_txid = wallet.sendtoaddress(sink_addr, 1)
        spend_blockhash = self.mine_block()
        change_amount = self.find_output_amount(spend_txid, int_entries[1].address, blockhash=spend_blockhash)
        self.assert_owned_unspent(wallet, spend_txid, int_entries[1], change_amount, category=None)
        self.assert_descriptor_state(
            wallet,
            root_seed,
            external_next=3,
            internal_next=2,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(wallet, external=12, internal=11)
        self.assert_address_info(wallet, int_entries[1], is_change=True)

        self.log.info("Restart and confirm active manager state and tracked outputs persist")
        self.restart_node(0, self.extra_args[0])
        node = self.nodes[0]
        wallet = self.ensure_wallet_loaded("pqactive")
        self.assert_descriptor_state(
            wallet,
            root_seed,
            external_next=3,
            internal_next=2,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_owned_unspent(wallet, spend_txid, int_entries[1], change_amount, category=None)

        self.log.info("Back up and restore the wallet with active PQ managers intact")
        backup_path = node.datadir_path / "pqactive.bak"
        wallet.backupwallet(str(backup_path))
        node.restorewallet("pqactive_restored", str(backup_path))
        restored = node.get_wallet_rpc("pqactive_restored")

        self.assert_descriptor_state(
            restored,
            root_seed,
            external_next=3,
            internal_next=2,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(restored, external=12, internal=11)
        self.assert_owned_unspent(restored, spend_txid, int_entries[1], change_amount, category=None)
        self.assert_address_info(restored, int_entries[1], is_change=True)
        assert_equal(restored.gethdkeys(), [])
        assert_raises_rpc_error(-4, "Public export for ranged pqpriv() descriptors is not available.", restored.listdescriptors, False)
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress",
            restored.getnewaddress,
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress",
            restored.getnewaddress,
            "",
            "legacy",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress",
            restored.getrawchangeaddress,
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress",
            restored.getrawchangeaddress,
            "legacy",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not expose HD keys; createwalletdescriptor only supports xpub-based descriptor families",
            restored.createwalletdescriptor,
            "bech32",
        )
        assert_raises_rpc_error(
            -5,
            "Active pqpriv() managers do not expose HD keys; createwalletdescriptor only supports xpub-based descriptor families",
            restored.createwalletdescriptor,
            "bech32m",
        )

        self.log.info("Generated addresses continue from the correct next index after restore")
        assert_equal(restored.getnewpqaddress("restored receive"), ext_entries[3].address)
        assert_equal(restored.getrawpqchangeaddress(), int_entries[2].address)
        self.assert_descriptor_state(
            restored,
            root_seed,
            external_next=4,
            internal_next=3,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(restored, external=11, internal=10)

        self.log.info("Reload the restored wallet and confirm watch set and next_index remain stable")
        restored.unloadwallet()
        node.loadwallet("pqactive_restored")
        restored = node.get_wallet_rpc("pqactive_restored")
        self.assert_descriptor_state(
            restored,
            root_seed,
            external_next=4,
            internal_next=3,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(restored, external=11, internal=10)
        self.assert_owned_unspent(restored, spend_txid, int_entries[1], change_amount, category=None)
        assert_equal(restored.getnewpqaddress(), ext_entries[4].address)
        self.assert_descriptor_state(
            restored,
            root_seed,
            external_next=5,
            internal_next=3,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(restored, external=10, internal=10)

        self.log.info("Automatic PQ change still uses the restored internal manager after reload")
        restored_spend_txid = restored.sendtoaddress(sink_addr, 1)
        restored_spend_blockhash = self.mine_block()
        restored_change_amount = self.find_output_amount(
            restored_spend_txid,
            int_entries[3].address,
            blockhash=restored_spend_blockhash,
        )
        self.assert_owned_unspent(restored, restored_spend_txid, int_entries[3], restored_change_amount, category=None)
        self.assert_descriptor_state(
            restored,
            root_seed,
            external_next=5,
            internal_next=4,
            external_range=[0, 14],
            internal_range=[0, 12],
        )
        self.assert_keypool_info(restored, external=10, internal=9)
        self.assert_address_info(restored, int_entries[3], is_change=True)


if __name__ == "__main__":
    WalletPQActiveRangedTest(__file__).main()
