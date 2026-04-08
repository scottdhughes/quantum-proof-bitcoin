#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test fixed watch-only pq(...) descriptors."""

from decimal import Decimal

from test_framework.address import script_to_p2wsh
from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.pqsig import build_pq_keypair, create_wallet_funded_tx
from test_framework.script import CScript, OP_CHECKSIG, OP_TRUE
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


RAW_TRUE_DESCRIPTOR = descsum_create("raw(51)")


class WalletPQDescriptorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def mine_block(self):
        self.nodes[0].generatetodescriptor(1, RAW_TRUE_DESCRIPTOR, called_by_framework=True)

    def find_pq_props(self, decoded_input):
        return [
            prop for prop in decoded_input.get("proprietary", [])
            if prop["identifier"] == "7071627463" and prop["subtype"] == 1
        ]

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="sink")
        sink = node.get_wallet_rpc("sink")
        sink_address = sink.getnewaddress()

        node.createwallet(wallet_name="watch", disable_private_keys=True, blank=True)
        watch = node.get_wallet_rpc("watch")

        sk_seed = bytes.fromhex("11" * 32)
        _, pk_script = build_pq_keypair(sk_seed)
        witness_script = CScript([pk_script, OP_CHECKSIG])
        address = script_to_p2wsh(witness_script)
        descriptor = descsum_create(f"pq({pk_script.hex()})")

        self.log.info("Import a fixed watch-only pq(...) descriptor")
        result = watch.importdescriptors([{"desc": descriptor, "timestamp": "now"}])
        assert_equal(result[0]["success"], True)
        assert_equal(watch.getwalletinfo()["keypoolsize"], 0)

        self.log.info("Reject unsupported active/range/next_index combinations")
        active_result = watch.importdescriptors([{"desc": descriptor, "timestamp": "now", "active": True}])
        assert_equal(active_result[0]["success"], False)
        assert_equal(active_result[0]["error"]["code"], -8)
        assert_equal(active_result[0]["error"]["message"], "Active descriptors must be ranged")

        range_result = watch.importdescriptors([{"desc": descriptor, "timestamp": "now", "range": 1}])
        assert_equal(range_result[0]["success"], False)
        assert_equal(range_result[0]["error"]["code"], -8)
        assert_equal(range_result[0]["error"]["message"], "Range should not be specified for an un-ranged descriptor")

        next_result = watch.importdescriptors([{"desc": descriptor, "timestamp": "now", "next_index": 0}])
        assert_equal(next_result[0]["success"], False)
        assert_equal(next_result[0]["error"]["code"], -8)
        assert_equal(next_result[0]["error"]["message"], "next_index should not be specified for an un-ranged descriptor")

        self.log.info("Round-trip pq(...) through listdescriptors and getaddressinfo")
        descriptor_info = node.getdescriptorinfo(descriptor)
        assert_equal(descriptor_info["descriptor"], descriptor)
        assert_equal(descriptor_info["isrange"], False)
        assert_equal(descriptor_info["issolvable"], True)
        assert_equal(descriptor_info["hasprivatekeys"], False)
        assert_equal(node.deriveaddresses(descriptor), [address])
        assert_raises_rpc_error(
            -8,
            "Range should not be specified for an un-ranged descriptor",
            node.deriveaddresses,
            descriptor,
            [0, 1],
        )

        listed = watch.listdescriptors()
        assert_equal(listed["wallet_name"], "watch")
        assert_equal(len(listed["descriptors"]), 1)
        assert_equal(
            listed["descriptors"][0],
            {
                "active": False,
                "desc": descriptor,
                "timestamp": listed["descriptors"][0]["timestamp"],
            },
        )
        assert_raises_rpc_error(-4, "Can't get descriptor string", watch.listdescriptors, True)

        info = watch.getaddressinfo(address)
        assert_equal(info["desc"], descriptor)
        assert_equal(info["ismine"], True)
        assert_equal(info["has_private_keys"], False)
        assert_equal(info["solvable"], True)
        assert_equal(watch.getwalletinfo()["private_keys_enabled"], False)

        self.log.info("Descriptor survives unload/load")
        watch.unloadwallet()
        node.loadwallet("watch")
        watch = node.get_wallet_rpc("watch")
        assert_equal(watch.listdescriptors()["descriptors"][0]["desc"], descriptor)
        assert_equal(watch.getaddressinfo(address)["desc"], descriptor)

        self.log.info("Imported pq(...) tracks funds to the standard PQ P2WSH output")
        tx = create_wallet_funded_tx(node, bytes(script_to_p2wsh_script(witness_script)), 5 * COIN)
        tx.vout[1].scriptPubKey = script_to_p2wsh_script(CScript([OP_TRUE]))
        txid = node.sendrawtransaction(tx.serialize().hex())
        self.mine_block()

        unspent = watch.listunspent()
        assert_equal(len(unspent), 1)
        assert_equal(unspent[0]["txid"], txid)
        assert_equal(unspent[0]["address"], address)
        assert_equal(unspent[0]["amount"], Decimal("5.00000000"))
        assert_equal(unspent[0]["has_private_keys"], False)
        assert_equal(unspent[0]["solvable"], True)
        balances = watch.getbalances()
        tracked_bucket = balances["watchonly"] if "watchonly" in balances else balances["mine"]
        assert_equal(tracked_bucket["trusted"], Decimal("5.00000000"))

        self.log.info("Fixed watch-only pq(...) can prepare but not sign a PSBT-backed send")
        created = watch.send(
            outputs={sink_address: Decimal("5.00000000")},
            options={
                "inputs": [{"txid": unspent[0]["txid"], "vout": unspent[0]["vout"]}],
                "add_inputs": False,
                "subtract_fee_from_outputs": [0],
                "psbt": True,
            },
        )
        assert_equal(created["complete"], False)
        assert "txid" not in created
        decoded = node.decodepsbt(created["psbt"])
        assert_equal(len(decoded["inputs"]), 1)
        assert_equal(len(decoded["tx"]["vin"]), 1)
        assert_equal(len(decoded["tx"]["vout"]), 1)
        assert "witness_utxo" in decoded["inputs"][0]
        assert_equal(self.find_pq_props(decoded["inputs"][0]), [])
        assert "final_scriptwitness" not in decoded["inputs"][0]
        assert Decimal(str(decoded["tx"]["vout"][0]["value"])) < Decimal("5.00000000")

        processed = watch.walletprocesspsbt(psbt=created["psbt"], finalize=False)
        assert_equal(processed["complete"], False)
        processed_decoded = node.decodepsbt(processed["psbt"])
        assert_equal(self.find_pq_props(processed_decoded["inputs"][0]), [])
        assert "final_scriptwitness" not in processed_decoded["inputs"][0]


if __name__ == "__main__":
    WalletPQDescriptorsTest(__file__).main()
