#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test PQ descriptor backup/restore invariants for bounded imported batches."""

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.pq_wallet_helper import build_bounded_pq_descriptor_batch
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")


class WalletPQBackupRecoveryTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_block(self):
        self.nodes[0].generatetodescriptor(1, RAW_TRUE_DESCRIPTOR, called_by_framework=True)

    def ensure_wallet_loaded(self, wallet_name):
        node = self.nodes[0]
        if wallet_name not in node.listwallets():
            node.loadwallet(wallet_name)
        return node.get_wallet_rpc(wallet_name)

    def fund_entry(self, entry, amount_sat: int) -> str:
        tx = create_wallet_funded_tx(self.nodes[0], bytes(entry.script_pub_key), amount_sat)
        return self.nodes[0].sendrawtransaction(tx.serialize().hex())

    def descriptor_snapshot(self, wallet):
        return [
            {
                "active": item["active"],
                "desc": item["desc"],
                "timestamp": item["timestamp"],
            }
            for item in wallet.listdescriptors()["descriptors"]
        ]

    def assert_entry_metadata(self, wallet, entry):
        info = wallet.getaddressinfo(entry.address)
        assert_equal(info["desc"], entry.descriptor)
        assert_equal(info["ismine"], True)
        assert_equal(info["solvable"], True)
        assert_equal(info["ischange"], entry.internal)
        if entry.internal:
            assert_equal(info.get("labels", []), [])
        else:
            assert_equal(info["labels"], [entry.label])

    def assert_tracked_outputs(self, wallet, expected_amounts):
        observed = {item["address"]: item["amount"] for item in wallet.listunspent()}
        assert_equal(observed, expected_amounts)

    def run_test(self):
        node = self.nodes[0]
        root_seed = bytes.fromhex("42" * 32)
        external_entries, internal_entries = build_bounded_pq_descriptor_batch(
            root_seed,
            external_count=3,
            internal_count=2,
        )
        all_entries = external_entries + internal_entries

        self.log.info("Create a blank watch-only wallet and import a bounded PQ descriptor batch")
        node.createwallet(wallet_name="pqpool", disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc("pqpool")
        import_result = watch.importdescriptors([entry.import_request(0) for entry in all_entries])
        assert all(result["success"] for result in import_result)
        assert_equal(watch.getwalletinfo()["keypoolsize"], 0)

        initial_snapshot = self.descriptor_snapshot(watch)
        assert_equal(len(initial_snapshot), len(all_entries))
        for entry in all_entries:
            self.assert_entry_metadata(watch, entry)

        self.log.info("Back up the wallet before any PQ funding so restore must recover from the watch set")
        backup_path = node.datadir_path / "pqpool_pre_funding.bak"
        watch.backupwallet(str(backup_path))

        self.log.info("Fund sparse external/internal entries from the imported batch")
        funded_amounts = {
            external_entries[1].address: Decimal("3.00000000"),
            internal_entries[1].address: Decimal("5.00000000"),
        }
        self.fund_entry(external_entries[1], 3 * COIN)
        self.fund_entry(internal_entries[1], 5 * COIN)
        self.mine_block()
        self.assert_tracked_outputs(watch, funded_amounts)

        self.log.info("Restart the node and confirm descriptor inventory and tracked outputs persist")
        self.restart_node(0, self.extra_args[0])
        node = self.nodes[0]
        watch = self.ensure_wallet_loaded("pqpool")
        assert_equal(self.descriptor_snapshot(watch), initial_snapshot)
        for entry in all_entries:
            self.assert_entry_metadata(watch, entry)
        self.assert_tracked_outputs(watch, funded_amounts)

        self.log.info("Restore the pre-funding backup into a fresh wallet and confirm funded outputs are rediscovered")
        node.restorewallet("pqpool_restored", str(backup_path))
        restored = node.get_wallet_rpc("pqpool_restored")
        assert_equal(self.descriptor_snapshot(restored), initial_snapshot)
        for entry in all_entries:
            self.assert_entry_metadata(restored, entry)
        self.assert_tracked_outputs(restored, funded_amounts)

        self.log.info("Fund a previously unused PQ descriptor after restore and confirm it is tracked after reload")
        post_restore_amounts = dict(funded_amounts)
        post_restore_amounts[external_entries[0].address] = Decimal("7.00000000")
        self.fund_entry(external_entries[0], 7 * COIN)
        self.mine_block()
        self.assert_tracked_outputs(restored, post_restore_amounts)

        restored.unloadwallet()
        node.loadwallet("pqpool_restored")
        restored = node.get_wallet_rpc("pqpool_restored")
        assert_equal(self.descriptor_snapshot(restored), initial_snapshot)
        for entry in all_entries:
            self.assert_entry_metadata(restored, entry)
        self.assert_tracked_outputs(restored, post_restore_amounts)


if __name__ == "__main__":
    WalletPQBackupRecoveryTest(__file__).main()

