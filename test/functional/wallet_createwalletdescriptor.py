#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test wallet createwalletdescriptor RPC."""

from test_framework.descriptors import descsum_create
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet_util import WalletUnlock


PQ_CREATEWALLETDESCRIPTOR_ERROR = (
    "Active pqpriv() managers do not expose HD keys; createwalletdescriptor "
    "only supports xpub-based descriptor families"
)


class WalletCreateDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        self.test_basic()
        self.test_imported_other_keys()
        self.test_encrypted()
        self.test_pq_active_managers_reject_inherited_descriptor_creation()

    def descriptor_snapshot(self, wallet):
        snapshot = []
        for descriptor in wallet.listdescriptors(private=True)["descriptors"]:
            snapshot.append({
                "desc": descriptor["desc"],
                "active": descriptor["active"],
                "internal": descriptor["internal"],
                "range": descriptor.get("range"),
                "next_index": descriptor.get("next_index"),
            })
        return sorted(snapshot, key=lambda item: item["desc"])

    def pq_wallet_state_snapshot(self, wallet):
        info = wallet.getwalletinfo()
        return {
            "descriptors": self.descriptor_snapshot(wallet),
            "hdkeys": wallet.gethdkeys(),
            "keypoolsize": info["keypoolsize"],
            "keypoolsize_hd_internal": info["keypoolsize_hd_internal"],
        }

    def test_basic(self):
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet("blank", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("blank")

        xpub_info = def_wallet.gethdkeys(private=True)
        xpub = xpub_info[0]["xpub"]
        xprv = xpub_info[0]["xprv"]
        expected_descs = []
        for desc in def_wallet.listdescriptors()["descriptors"]:
            if desc["desc"].startswith("wpkh("):
                expected_descs.append(desc["desc"])

        assert_raises_rpc_error(-5, "Unable to determine which HD key to use from active descriptors. Please specify with 'hdkey'", wallet.createwalletdescriptor, "bech32")
        assert_raises_rpc_error(-5, f"Private key for {xpub} is not known", wallet.createwalletdescriptor, type="bech32", hdkey=xpub)

        self.log.info("Test createwalletdescriptor after importing active descriptor to blank wallet")
        # Import one active descriptor
        assert_equal(wallet.importdescriptors([{"desc": descsum_create(f"pkh({xprv}/44h/2h/0h/0/0/*)"), "timestamp": "now", "active": True}])[0]["success"], True)
        assert_equal(len(wallet.listdescriptors()["descriptors"]), 1)
        assert_equal(len(wallet.gethdkeys()), 1)

        new_descs = wallet.createwalletdescriptor("bech32")["descs"]
        assert_equal(len(new_descs), 2)
        assert_equal(len(wallet.gethdkeys()), 1)
        assert_equal(new_descs, expected_descs)

        self.log.info("Test descriptor creation options")
        old_descs = set([(d["desc"], d["active"], d["internal"]) for d in wallet.listdescriptors(private=True)["descriptors"]])
        wallet.createwalletdescriptor(type="bech32m", internal=False)
        curr_descs = set([(d["desc"], d["active"], d["internal"]) for d in wallet.listdescriptors(private=True)["descriptors"]])
        new_descs = list(curr_descs - old_descs)
        assert_equal(len(new_descs), 1)
        assert_equal(len(wallet.gethdkeys()), 1)
        assert_equal(new_descs[0][0], descsum_create(f"tr({xprv}/86h/1h/0h/0/*)"))
        assert_equal(new_descs[0][1], True)
        assert_equal(new_descs[0][2], False)

        old_descs = curr_descs
        wallet.createwalletdescriptor(type="bech32m", internal=True)
        curr_descs = set([(d["desc"], d["active"], d["internal"]) for d in wallet.listdescriptors(private=True)["descriptors"]])
        new_descs = list(curr_descs - old_descs)
        assert_equal(len(new_descs), 1)
        assert_equal(len(wallet.gethdkeys()), 1)
        assert_equal(new_descs[0][0], descsum_create(f"tr({xprv}/86h/1h/0h/1/*)"))
        assert_equal(new_descs[0][1], True)
        assert_equal(new_descs[0][2], True)

    def test_imported_other_keys(self):
        self.log.info("Test createwalletdescriptor with multiple keys in active descriptors")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet("multiple_keys")
        wallet = self.nodes[0].get_wallet_rpc("multiple_keys")

        wallet_xpub = wallet.gethdkeys()[0]["xpub"]

        xpub_info = def_wallet.gethdkeys(private=True)
        xpub = xpub_info[0]["xpub"]
        xprv = xpub_info[0]["xprv"]

        assert_equal(wallet.importdescriptors([{"desc": descsum_create(f"wpkh({xprv}/0/0/*)"), "timestamp": "now", "active": True}])[0]["success"], True)
        assert_equal(len(wallet.gethdkeys()), 2)

        assert_raises_rpc_error(-5, "Unable to determine which HD key to use from active descriptors. Please specify with 'hdkey'", wallet.createwalletdescriptor, "bech32")
        assert_raises_rpc_error(-4, "Descriptor already exists", wallet.createwalletdescriptor, type="bech32m", hdkey=wallet_xpub)
        assert_raises_rpc_error(-5, "Unable to parse HD key. Please provide a valid xpub", wallet.createwalletdescriptor, type="bech32m", hdkey=xprv)

        # Able to replace tr() descriptor with other hd key
        wallet.createwalletdescriptor(type="bech32m", hdkey=xpub)

    def test_encrypted(self):
        self.log.info("Test createwalletdescriptor with encrypted wallets")
        def_wallet = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        self.nodes[0].createwallet("encrypted", blank=True, passphrase="pass")
        wallet = self.nodes[0].get_wallet_rpc("encrypted")

        xpub_info = def_wallet.gethdkeys(private=True)
        xprv = xpub_info[0]["xprv"]

        with WalletUnlock(wallet, "pass"):
            assert_equal(wallet.importdescriptors([{"desc": descsum_create(f"wpkh({xprv}/0/0/*)"), "timestamp": "now", "active": True}])[0]["success"], True)
        assert_equal(len(wallet.gethdkeys()), 1)

        assert_raises_rpc_error(-13, "Error: Please enter the wallet passphrase with walletpassphrase first.", wallet.createwalletdescriptor, type="bech32m")

        with WalletUnlock(wallet, "pass"):
            wallet.createwalletdescriptor(type="bech32m")

    def test_pq_active_managers_reject_inherited_descriptor_creation(self):
        self.log.info("Test createwalletdescriptor rejects PQ-only active managers without mutating wallet state")
        self.nodes[0].createwallet("pq_only", blank=True)
        wallet = self.nodes[0].get_wallet_rpc("pq_only")
        wallet.createpqwalletmanagers(("42" * 32), 9)

        state_before = self.pq_wallet_state_snapshot(wallet)
        assert_equal(state_before["hdkeys"], [])
        assert_equal(len(state_before["descriptors"]), 2)

        for output_type in ("bech32", "bech32m"):
            assert_raises_rpc_error(
                -5,
                PQ_CREATEWALLETDESCRIPTOR_ERROR,
                wallet.createwalletdescriptor,
                output_type,
            )
            assert_equal(self.pq_wallet_state_snapshot(wallet), state_before)



if __name__ == '__main__':
    WalletCreateDescriptorTest(__file__).main()
