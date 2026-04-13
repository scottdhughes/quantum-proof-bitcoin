#!/usr/bin/env python3
# Copyright (c) 2024 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a decaying miniscript multisig under the Track A non-signing carveout.

Spending policy: `thresh(4,pk(key_1),pk(key_2),pk(key_3),pk(key_4),after(t1),after(t2),after(t3))`
This is similar to `test/functional/wallet_multisig_descriptor_psbt.py`.
"""

from decimal import Decimal

from test_framework.authproxy import JSONRPCException
from test_framework.messages import COIN
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)


LEGACY_SIGNER_PSBT_ERROR = "TX decode failed Signature is not a valid encoding: unspecified iostream_category error"
PQ_PROP_IDENTIFIER = "7071627463"


class WalletMiniscriptDecayingMultisigDescriptorPSBTTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []
        self.extra_args = [["-keypool=100", "-acceptnonstdtxn=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def _get_xpub(wallet, internal):
        """Extract the wallet's xpubs using `listdescriptors` and pick the one from the `pkh` descriptor since it's least likely to be accidentally reused (legacy addresses)."""
        pkh_descriptor = next(filter(lambda d: d["desc"].startswith("pkh(") and d["internal"] == internal, wallet.listdescriptors()["descriptors"]))
        # keep all key origin information (master key fingerprint and all derivation steps) for proper support of hardware devices
        # see section 'Key origin identification' in 'doc/descriptors.md' for more details...
        return pkh_descriptor["desc"].split("pkh(")[1].split(")")[0]

    def create_multisig(self, external_xpubs, internal_xpubs):
        """The multisig is created by importing the following descriptors. The resulting wallet is watch-only and every signer can do this."""
        self.node.createwallet(wallet_name=f"{self.name}", blank=True, disable_private_keys=True)
        multisig = self.node.get_wallet_rpc(f"{self.name}")
        # spending policy: `thresh(4,pk(key_1),pk(key_2),pk(key_3),pk(key_4),after(t1),after(t2),after(t3))`
        # IMPORTANT: when backing up your descriptor, the order of key_1...key_4 must be correct!
        external = multisig.getdescriptorinfo(f"wsh(thresh({self.N},pk({'),s:pk('.join(external_xpubs)}),sln:after({'),sln:after('.join(map(str, self.locktimes))})))")
        internal = multisig.getdescriptorinfo(f"wsh(thresh({self.N},pk({'),s:pk('.join(internal_xpubs)}),sln:after({'),sln:after('.join(map(str, self.locktimes))})))")
        result = multisig.importdescriptors([
            {  # receiving addresses (internal: False)
                "desc": external["descriptor"],
                "active": True,
                "internal": False,
                "timestamp": "now",
            },
            {  # change addresses (internal: True)
                "desc": internal["descriptor"],
                "active": True,
                "internal": True,
                "timestamp": "now",
            },
        ])
        assert all(r["success"] for r in result)
        return multisig

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

    def run_test(self):
        self.node = self.nodes[0]
        self.N = 4

        self.locktimes = [104, 106, 108]
        assert_equal(len(self.locktimes), self.N - 1)

        self.name = f"{self.N}_of_{self.N}_decaying_multisig"
        self.log.info(f"Testing a miniscript multisig which starts as 4-of-4 and 'decays' to 3-of-4 at block height {self.locktimes[0]}, 2-of-4 at {self.locktimes[1]}, and finally 1-of-4 at {self.locktimes[2]}...")

        self.log.info("Create the signer wallets and get their xpubs...")
        signers = [self.node.get_wallet_rpc(self.node.createwallet(wallet_name=f"signer_{i}")["name"]) for i in range(self.N)]
        external_xpubs, internal_xpubs = [[self._get_xpub(signer, internal) for signer in signers] for internal in [False, True]]

        self.log.info("Create the watch-only decaying multisig using signers' xpubs...")
        multisig = self.create_multisig(external_xpubs, internal_xpubs)

        self.log.info("Keep inherited classical funding as an explicit deferred negative control...")
        coordinator_wallet = self.node.get_wallet_rpc(self.node.createwallet(wallet_name="coordinator")["name"])
        self.generatetoaddress(self.node, 101, coordinator_wallet.getnewaddress())
        rejected_address = multisig.getnewaddress()
        deposit_amount = Decimal("6.15000000")
        assert_raises_rpc_error(
            -6,
            "Signing transaction failed",
            coordinator_wallet.sendtoaddress,
            rejected_address,
            deposit_amount,
        )

        self.log.info("Fund the watch-only minisig address through the PQ-safe raw helper...")
        funded_address = multisig.getnewaddress()
        funded_address_info = multisig.getaddressinfo(funded_address)
        funding_tx = create_wallet_funded_tx(
            self.node,
            bytes.fromhex(funded_address_info["scriptPubKey"]),
            int(deposit_amount * COIN),
        )
        funding_txid = self.node.sendrawtransaction(funding_tx.serialize().hex())
        self.generate(self.node, 1)
        funded = self.find_unspent(multisig, funded_address, funding_txid)
        assert_equal(funded["amount"], deposit_amount)
        assert_equal(funded["solvable"], True)
        balances = multisig.getbalances()
        tracked_bucket = balances["watchonly"] if "watchonly" in balances else balances["mine"]
        assert_equal(tracked_bucket["trusted"], deposit_amount)
        assert_equal(multisig.getbalance(), deposit_amount)

        self.log.info("Preserve the decaying miniscript PSBT surface as a non-signing watch-only carveout...")
        amount = Decimal("1.50000000")
        created_psbts = []
        for required_signers, locktime in zip(range(self.N, 0, -1), [0] + self.locktimes):
            self.log.info(f"At block height >= {locktime} this minisig would require {required_signers}-of-{self.N}")
            created = multisig.walletcreatefundedpsbt(
                inputs=[{"txid": funded["txid"], "vout": funded["vout"]}],
                outputs={signers[0].getnewaddress(): amount},
                locktime=locktime,
                options={"add_inputs": False, "fee_rate": 1},
            )
            created_psbts.append(created["psbt"])
            decoded = self.node.decodepsbt(created["psbt"])
            assert_equal(decoded["tx"]["locktime"], locktime)
            assert_equal(len(decoded["inputs"]), 1)
            assert_equal(len(decoded["tx"]["vin"]), 1)
            input0 = decoded["inputs"][0]
            assert "witness_utxo" in input0
            assert_equal(self.find_pq_props(input0), [])
            assert "final_scriptwitness" not in input0

            processed = multisig.walletprocesspsbt(psbt=created["psbt"], finalize=False)
            assert_equal(processed["complete"], False)
            assert "hex" not in processed
            processed_decoded = self.node.decodepsbt(processed["psbt"])
            assert_equal(processed_decoded["tx"]["locktime"], locktime)
            processed_input0 = processed_decoded["inputs"][0]
            assert "witness_utxo" in processed_input0
            assert_equal(self.find_pq_props(processed_input0), [])
            assert "final_scriptwitness" not in processed_input0

        self.log.info("Freeze the first inherited classical signer failure as an explicit deferred negative control...")
        legacy_psbt = created_psbts[0]
        for signer in signers:
            try:
                signed = signer.walletprocesspsbt(psbt=legacy_psbt, finalize=False)
            except JSONRPCException as exc:
                assert_equal(exc.error["code"], -22)
                assert_equal(exc.error["message"], LEGACY_SIGNER_PSBT_ERROR)
                break
            assert_equal(signed["complete"], False)
            legacy_psbt = signed["psbt"]
        else:
            raise AssertionError("Inherited classical signer path unexpectedly succeeded for all signers")


if __name__ == "__main__":
    WalletMiniscriptDecayingMultisigDescriptorPSBTTest(__file__).main()
