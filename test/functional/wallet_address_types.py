#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Freeze a narrow address-type boundary under PQBTC Track A.

This file no longer tries to rehabilitate the full inherited address-family
matrix. Instead it keeps:

- low-risk inherited address-shape smoke coverage that still passes
- one explicit deferred inherited sendmany negative control
- one PQ-only inherited-address rejection boundary for active pqpriv() wallets
"""

from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


GETNEWADDRESS_PQ_ERROR = (
    "Active pqpriv() managers do not use inherited getnewaddress; "
    "use getnewpqaddress"
)
GETRAWCHANGEADDRESS_PQ_ERROR = (
    "Active pqpriv() managers do not use inherited getrawchangeaddress; "
    "use getrawpqchangeaddress"
)


class AddressTypeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 6
        self.extra_args = [
            ["-addresstype=legacy"],
            ["-addresstype=p2sh-segwit"],
            ["-addresstype=p2sh-segwit", "-changetype=bech32"],
            ["-addresstype=bech32"],
            ["-changetype=p2sh-segwit"],
            [],
        ]
        # whitelist peers to speed up tx relay / mempool sync
        self.noban_tx_relay = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

        # Fully mesh-connect nodes for faster mempool sync
        for i in range(self.num_nodes):
            for j in range(i):
                self.connect_nodes(i, j)
        self.sync_all()

    def test_address(self, node, address, typ):
        """Run sanity checks on an address."""
        info = self.nodes[node].getaddressinfo(address)
        assert self.nodes[node].validateaddress(address)["isvalid"]
        assert_equal(info["solvable"], True)

        if typ == "legacy":
            # P2PKH
            assert not info["isscript"]
            assert not info["iswitness"]
            assert "pubkey" in info
        elif typ == "p2sh-segwit":
            # P2SH-P2WPKH
            assert info["isscript"]
            assert not info["iswitness"]
            assert_equal(info["script"], "witness_v0_keyhash")
            assert "pubkey" in info
        elif typ == "bech32":
            # P2WPKH
            assert not info["isscript"]
            assert info["iswitness"]
            assert_equal(info["witness_version"], 0)
            assert_equal(len(info["witness_program"]), 40)
            assert "pubkey" in info
        elif typ == "bech32m":
            # P2TR single sig
            assert info["isscript"]
            assert info["iswitness"]
            assert_equal(info["witness_version"], 1)
            assert_equal(len(info["witness_program"]), 64)
        else:
            # Unknown type
            raise AssertionError(f"Unknown type {typ}")

    def create_pq_wallet(self, node_index, wallet_name, *, root_seed_hex):
        node = self.nodes[node_index]
        node.createwallet(wallet_name=wallet_name, blank=True)
        wallet = node.get_wallet_rpc(wallet_name)
        wallet.createpqwalletmanagers(root_seed_hex, 9)
        return wallet

    def assert_pq_inherited_address_rpc_rejected(self, wallet):
        assert_raises_rpc_error(
            -5,
            GETNEWADDRESS_PQ_ERROR,
            wallet.getnewaddress,
        )
        for address_type in ("legacy", "p2sh-segwit", "bech32", "bech32m"):
            assert_raises_rpc_error(
                -5,
                GETNEWADDRESS_PQ_ERROR,
                wallet.getnewaddress,
                "",
                address_type,
            )

        assert_raises_rpc_error(
            -5,
            GETRAWCHANGEADDRESS_PQ_ERROR,
            wallet.getrawchangeaddress,
        )
        for address_type in ("legacy", "p2sh-segwit", "bech32", "bech32m"):
            assert_raises_rpc_error(
                -5,
                GETRAWCHANGEADDRESS_PQ_ERROR,
                wallet.getrawchangeaddress,
                address_type,
            )

    def test_basic_inherited_address_shapes(self):
        self.log.info("Smoke test inherited address-shape coverage that still passes")
        self.test_address(0, self.nodes[0].getnewaddress(), "legacy")
        self.test_address(0, self.nodes[0].getrawchangeaddress(), "legacy")
        self.test_address(1, self.nodes[1].getnewaddress(), "p2sh-segwit")
        self.test_address(1, self.nodes[1].getrawchangeaddress(), "p2sh-segwit")
        self.test_address(2, self.nodes[2].getnewaddress(), "p2sh-segwit")
        self.test_address(2, self.nodes[2].getrawchangeaddress(), "bech32")
        self.test_address(3, self.nodes[3].getnewaddress(), "bech32")
        self.test_address(3, self.nodes[3].getrawchangeaddress(), "bech32")
        self.test_address(4, self.nodes[4].getrawchangeaddress(), "p2sh-segwit")

    def test_invalid_address_type_arguments(self):
        self.log.info("Invalid address type arguments still fail before any PQ-specific guard")
        compressed_1 = "0296b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52"
        compressed_2 = "037211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073"
        wallet = self.nodes[3]

        assert_raises_rpc_error(
            -5,
            "Unknown address type ''",
            wallet.createmultisig,
            2,
            [compressed_1, compressed_2],
            address_type="",
        )
        assert_raises_rpc_error(-5, "Unknown address type ''", wallet.getnewaddress, None, "")
        assert_raises_rpc_error(-5, "Unknown address type ''", wallet.getrawchangeaddress, "")
        assert_raises_rpc_error(-5, "Unknown address type 'bech23'", wallet.getrawchangeaddress, "bech23")
        assert_raises_rpc_error(-5, "Unknown address type 'bech23'", wallet.createwalletdescriptor, "bech23")

    def test_descriptor_wallet_bech32m_smoke(self):
        self.log.info("Descriptor wallets still expose inherited bech32m smoke coverage")
        self.test_address(4, self.nodes[4].getnewaddress("", "bech32m"), "bech32m")
        self.test_address(4, self.nodes[4].getrawchangeaddress("bech32m"), "bech32m")

    def test_deferred_legacy_sendmany_negative_control(self):
        self.log.info("Freeze the current inherited classical sendmany failure as a deferred negative control")
        assert_greater_than(self.nodes[0].getbalance(), Decimal("1"))

        self_change = self.nodes[0].getrawchangeaddress()
        p2sh_1 = self.nodes[1].getnewaddress()
        p2sh_2 = self.nodes[2].getnewaddress()
        bech32 = self.nodes[3].getnewaddress()

        self.test_address(0, self_change, "legacy")
        self.test_address(1, p2sh_1, "p2sh-segwit")
        self.test_address(2, p2sh_2, "p2sh-segwit")
        self.test_address(3, bech32, "bech32")

        sends = {
            self_change: Decimal("0.10"),
            p2sh_1: Decimal("0.20"),
            p2sh_2: Decimal("0.30"),
            bech32: Decimal("0.40"),
        }
        assert_raises_rpc_error(-6, "Signing transaction failed", self.nodes[0].sendmany, "", sends)

    def test_pq_only_inherited_address_rpc_boundary(self):
        self.log.info("PQ-only active wallets reject inherited address RPCs for all valid inherited address types")
        wallet = self.create_pq_wallet(4, "pq_only_boundary", root_seed_hex=("41" * 32))
        receive_address = wallet.getnewpqaddress("pq receive")
        change_address = wallet.getrawpqchangeaddress()

        receive_info = wallet.getaddressinfo(receive_address)
        assert_equal(receive_info["ismine"], True)
        assert_equal(receive_info["has_private_keys"], True)
        assert_equal(receive_info["solvable"], True)
        assert_equal(receive_info["ischange"], False)

        change_info = wallet.getaddressinfo(change_address)
        assert_equal(change_info["ismine"], True)
        assert_equal(change_info["has_private_keys"], True)
        assert_equal(change_info["solvable"], True)
        assert_equal(change_info["ischange"], True)

        self.assert_pq_inherited_address_rpc_rejected(wallet)

    def test_pq_unknown_type_precedence(self):
        self.log.info("Unknown address types still fail before PQ-only inherited-address guards")
        wallet = self.create_pq_wallet(4, "pq_invalid_types", root_seed_hex=("42" * 32))
        assert_raises_rpc_error(-5, "Unknown address type ''", wallet.getnewaddress, "", "")
        assert_raises_rpc_error(-5, "Unknown address type ''", wallet.getrawchangeaddress, "")
        assert_raises_rpc_error(-5, "Unknown address type 'bech23'", wallet.getnewaddress, "", "bech23")
        assert_raises_rpc_error(-5, "Unknown address type 'bech23'", wallet.getrawchangeaddress, "bech23")

    def run_test(self):
        # Mine 101 blocks on node5 to bring nodes out of IBD and make sure that
        # no coinbases are maturing for the nodes-under-test during the test.
        self.generate(self.nodes[5], COINBASE_MATURITY + 1)
        self.test_basic_inherited_address_shapes()
        self.test_invalid_address_type_arguments()
        self.test_descriptor_wallet_bech32m_smoke()
        self.test_deferred_legacy_sendmany_negative_control()
        self.test_pq_only_inherited_address_rpc_boundary()
        self.test_pq_unknown_type_precedence()

if __name__ == '__main__':
    AddressTypeTest(__file__).main()
