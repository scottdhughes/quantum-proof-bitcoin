#!/usr/bin/env python3
# Copyright (c) 2021-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Freeze wallet_multisig_descriptor_psbt.py as a Track A non-signing carveout."""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_approx,
    assert_equal,
    assert_raises_rpc_error,
)


LEGACY_SIGNER_PSBT_ERROR = "TX decode failed Signature is not a valid encoding: unspecified iostream_category error"
PQ_PROP_IDENTIFIER = "7071627463"


class WalletMultisigDescriptorPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-keypool=100"]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def _get_xpub(wallet, internal):
        """Extract the wallet's xpubs using `listdescriptors` and pick the one from the `pkh` descriptor since it's least likely to be accidentally reused (legacy addresses)."""
        pkh_descriptor = next(filter(lambda d: d["desc"].startswith("pkh(") and d["internal"] == internal, wallet.listdescriptors()["descriptors"]))
        return pkh_descriptor["desc"].split("pkh(")[1].split(")")[0]

    @staticmethod
    def find_pq_props(decoded_input):
        return [
            prop for prop in decoded_input.get("proprietary", [])
            if prop["identifier"] == PQ_PROP_IDENTIFIER and prop["subtype"] == 1
        ]

    @staticmethod
    def find_unspent(wallet, address, txid):
        matches = [u for u in wallet.listunspent() if u["address"] == address and u["txid"] == txid]
        assert_equal(len(matches), 1)
        return matches[0]

    @staticmethod
    def _check_psbt(psbt, to, value, multisig):
        """Helper function for any participant to check the PSBT before signing."""
        tx = multisig.decodepsbt(psbt)["tx"]
        amount = 0
        for vout in tx["vout"]:
            address = vout["scriptPubKey"]["address"]
            assert_equal(multisig.getaddressinfo(address)["ischange"], address != to)
            if address == to:
                amount += vout["value"]
        assert_approx(amount, float(value), vspan=0.001)

    def participants_create_multisigs(self, external_xpubs, internal_xpubs):
        """Import the same watch-only multisig into every participant node."""
        for i, node in enumerate(self.nodes):
            node.createwallet(wallet_name=f"{self.name}_{i}", blank=True, disable_private_keys=True)
            multisig = node.get_wallet_rpc(f"{self.name}_{i}")
            external = multisig.getdescriptorinfo(f"wsh(sortedmulti({self.M},{','.join(external_xpubs)}))")
            internal = multisig.getdescriptorinfo(f"wsh(sortedmulti({self.M},{','.join(internal_xpubs)}))")
            result = multisig.importdescriptors([
                {
                    "desc": external["descriptor"],
                    "active": True,
                    "internal": False,
                    "timestamp": "now",
                },
                {
                    "desc": internal["descriptor"],
                    "active": True,
                    "internal": True,
                    "timestamp": "now",
                },
            ])
            assert all(r["success"] for r in result)
            yield multisig

    def run_test(self):
        self.M = 2
        self.N = self.num_nodes
        self.name = f"{self.M}_of_{self.N}_multisig"
        self.log.info(f"Testing {self.name} under the Track A non-signing carveout...")

        participants = {
            "signers": [node.get_wallet_rpc(node.createwallet(wallet_name=f"participant_{self.nodes.index(node)}")["name"]) for node in self.nodes],
            "multisigs": [],
        }

        self.log.info("Generate and exchange xpubs...")
        external_xpubs, internal_xpubs = [[self._get_xpub(signer, internal) for signer in participants["signers"]] for internal in [False, True]]

        self.log.info("Every participant imports the watch-only multisig descriptors...")
        participants["multisigs"] = list(self.participants_create_multisigs(external_xpubs, internal_xpubs))

        self.log.info("Check that every participant's multisig generates the same receive/change addresses...")
        for _ in range(10):
            receive_addresses = [multisig.getnewaddress() for multisig in participants["multisigs"]]
            assert all(address == receive_addresses[0] for address in receive_addresses)
            change_addresses = [multisig.getrawchangeaddress() for multisig in participants["multisigs"]]
            assert all(address == change_addresses[0] for address in change_addresses)

        self.log.info("Keep inherited classical multisig funding as an explicit deferred negative control...")
        coordinator_wallet = participants["signers"][0]
        self.generatetoaddress(self.nodes[0], 101, coordinator_wallet.getnewaddress())
        deposit_amount = Decimal("6.15000000")
        rejected_address = participants["multisigs"][0].getnewaddress()
        assert_raises_rpc_error(
            -6,
            "Signing transaction failed",
            coordinator_wallet.sendtoaddress,
            rejected_address,
            deposit_amount,
        )

        self.log.info("Fund the watch-only multisig through direct coinbase generation...")
        funded_address = participants["multisigs"][0].getnewaddress()
        funding_blockhash = self.generatetoaddress(self.nodes[0], 1, funded_address)[0]
        self.generatetoaddress(self.nodes[0], 100, coordinator_wallet.getnewaddress())
        funding_txid = self.nodes[0].getblock(funding_blockhash, 2)["tx"][0]["txid"]

        funded = self.find_unspent(participants["multisigs"][0], funded_address, funding_txid)
        assert_equal(funded["solvable"], True)
        assert_equal(funded["has_private_keys"], False)
        deposit_amount = funded["amount"]
        for multisig in participants["multisigs"]:
            tracked = self.find_unspent(multisig, funded_address, funding_txid)
            assert_equal(tracked["amount"], deposit_amount)
            balances = multisig.getbalances()
            tracked_bucket = balances["watchonly"] if "watchonly" in balances else balances["mine"]
            assert_equal(tracked_bucket["trusted"], deposit_amount)
            assert_equal(multisig.getbalance(), deposit_amount)

        self.log.info("Preserve the multisig descriptor PSBT surface as a non-signing watch-only carveout...")
        to = participants["signers"][self.N - 1].getnewaddress()
        value = Decimal("1.00000000")
        created = participants["multisigs"][0].walletcreatefundedpsbt(
            inputs=[{"txid": funded["txid"], "vout": funded["vout"]}],
            outputs={to: value},
            options={"add_inputs": False, "fee_rate": 1},
        )
        decoded = self.nodes[0].decodepsbt(created["psbt"])
        assert_equal(len(decoded["inputs"]), 1)
        assert_equal(len(decoded["tx"]["vin"]), 1)
        assert "witness_utxo" in decoded["inputs"][0]
        assert_equal(self.find_pq_props(decoded["inputs"][0]), [])
        assert "partial_signatures" not in decoded["inputs"][0]
        assert "final_scriptwitness" not in decoded["inputs"][0]

        for multisig in participants["multisigs"]:
            self._check_psbt(created["psbt"], to, value, multisig)
            processed = multisig.walletprocesspsbt(psbt=created["psbt"], finalize=False)
            assert_equal(processed["complete"], False)
            assert "hex" not in processed
            processed_decoded = self.nodes[0].decodepsbt(processed["psbt"])
            input0 = processed_decoded["inputs"][0]
            assert "witness_utxo" in input0
            assert_equal(self.find_pq_props(input0), [])
            assert "partial_signatures" not in input0
            assert "final_scriptwitness" not in input0

        self.log.info("Freeze the first inherited signer failure as an explicit deferred negative control...")
        legacy_psbt = created["psbt"]
        for signing_wallet in participants["signers"]:
            try:
                signed = signing_wallet.walletprocesspsbt(psbt=legacy_psbt, finalize=False)
            except JSONRPCException as exc:
                assert_equal(exc.error["code"], -22)
                assert_equal(exc.error["message"], LEGACY_SIGNER_PSBT_ERROR)
                break
            assert_equal(signed["complete"], False)
            legacy_psbt = signed["psbt"]
        else:
            raise AssertionError("Inherited classical signer path unexpectedly succeeded for all signers")


if __name__ == "__main__":
    WalletMultisigDescriptorPSBTTest(__file__).main()
