#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Freeze wallet_miniscript.py as a narrow Track A boundary.

Owned here:
- one static public-key miniscript import plus address derivation
- one direct-funding watch-only miniscript UTXO plus non-signing PSBT
  preparation
- one wallet-local xprv-backed miniscript import plus direct coinbase-funded
  signer UTXO
- one first-signer PSBT contribution seam for that signer-backed miniscript

Deferred here:
- inherited classical miniscript funding under the default policy path
- inherited ranged xpub/tprv miniscript imports
- inherited TapMiniscript import/signing behavior
- broad classical miniscript signer rehabilitation
"""

from decimal import Decimal

from test_framework.descriptors import descsum_create
from test_framework.messages import COIN
from test_framework.pqsig import create_wallet_funded_tx
from test_framework.psbt import PSBT, PSBT_IN_PARTIAL_SIG
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


# Fixed classical fixtures retained as deferred invalid-key controls under
# Track A. These are distinct from the wallet-local HD keys used below.
TPRV = "tprv8ZgxMBicQKsPerQj6m35no46amfKQdjY7AhLnmatHYXs8S4MTgeZYkWAn4edSGwwL3vkSiiGqSZQrmy5D3P5gBoqgvYP2fCUpBwbKTMTAkL"
TPUB_A = "tpubD6NzVbkrYhZ4YPAbyf6urxqqnmJF79PzQtyERAmvkSVS9fweCTjxjDh22Z5St9fGb1a5DUCv8G27nYupKP1Ctr1pkamJossoetzws1moNRn"
TPUB_B = "tpubD6NzVbkrYhZ4YMQC15JS7QcrsAyfGrGiykweqMmPxTkEVScu7vCZLNpPXW1XphHwzsgmqdHWDQAfucbM72EEB1ZEyfgZxYvkZjYVXx1xS9p"
PUBKEY_A = "02aebf2d10b040eb936a6f02f44ee82f8b34f5c1ccb20ff3949c2b28206b7c1068"
PUBKEY_B = "030f64b922aee2fd597f104bc6cb3b670f1ca2c6c49b1071a1a6c010575d94fe5a"
TAPROOT_INTERNAL_KEY = "4d54bb9928a0683b7e383de72943b214b0716f58aa54c7ba6bcea2328bc9c768"

STATIC_MINISCRIPT_DESC = f"wsh(or_b(pk({PUBKEY_A}),s:pk({PUBKEY_B})))"
XPUB_MINISCRIPT_DESC = f"wsh(or_b(pk({TPUB_A}/*),s:pk({TPUB_B}/*)))"
TAPROOT_XPUB_MINISCRIPT_DESC = (
    f"tr({TAPROOT_INTERNAL_KEY},or_b(pk({TPUB_A}/*),s:pk({TPUB_B}/*)))"
)
XPRV_MINISCRIPT_DESC = f"wsh(and_v(v:older(2),pk({TPRV}/*)))"
LEGACY_SIGNER_PSBT_ERROR = "TX decode failed Signature is not a valid encoding: unspecified iostream_category error"
LEGACY_PARTIAL_SIG_UPPER_BOUND = 100


class WalletMiniscriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.rpc_timeout = 180

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_import_rejected(self, wallet, request, expected_message):
        before = len(wallet.listdescriptors()["descriptors"])
        result = wallet.importdescriptors([request])[0]
        assert not result["success"], result
        assert expected_message in result["error"]["message"], result
        assert_equal(len(wallet.listdescriptors()["descriptors"]), before)

    def find_unspent(self, wallet, address, txid):
        matches = [u for u in wallet.listunspent() if u["address"] == address and u["txid"] == txid]
        assert_equal(len(matches), 1)
        return matches[0]

    @staticmethod
    def find_partial_sig_entries(psbt_input):
        return [
            (key[1:], value)
            for key, value in psbt_input.map.items()
            if isinstance(key, bytes) and key[:1] == bytes([PSBT_IN_PARTIAL_SIG])
        ]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Create wallets for the narrowed miniscript boundary")
        node.createwallet(wallet_name="ms_wo", blank=True, disable_private_keys=True)
        self.ms_wo_wallet = node.get_wallet_rpc("ms_wo")
        node.createwallet(wallet_name="ms_sig")
        self.ms_sig_wallet = node.get_wallet_rpc("ms_sig")
        node.createwallet(wallet_name="ms_sink")
        self.ms_sink_wallet = node.get_wallet_rpc("ms_sink")
        sink_address = self.ms_sink_wallet.getnewaddress()
        self.generatetoaddress(node, 110, sink_address)

        self.log.info("Keep the inherited miniscript sanity guards")
        insane = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create(
                        "wsh(and_b(ripemd160(1fd9b55a054a2b3f658d97e6b84cf3ee00be429a),a:1))"
                    ),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not insane["success"]
        assert "is not sane: witnesses without signature exist" in insane["error"]["message"]

        unsatisfiable = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": descsum_create("wsh(0)"),
                    "active": False,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert not unsatisfiable["success"]
        assert "is not satisfiable" in unsatisfiable["error"]["message"]

        self.log.info("Own one static public-key miniscript watch-only import")
        static_desc = descsum_create(STATIC_MINISCRIPT_DESC)
        imported = self.ms_wo_wallet.importdescriptors(
            [
                {
                    "desc": static_desc,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert imported["success"], imported
        address = node.deriveaddresses(static_desc)[0]
        address_info = self.ms_wo_wallet.getaddressinfo(address)
        assert_equal(address_info["ismine"], True)
        assert_equal(address_info["solvable"], True)

        self.log.info("Freeze inherited classical miniscript funding as an explicit deferred negative control")
        funding_tx = create_wallet_funded_tx(
            node,
            bytes.fromhex(address_info["scriptPubKey"]),
            5 * COIN,
        )
        assert_raises_rpc_error(
            -26,
            "scriptpubkey",
            node.sendrawtransaction,
            funding_tx.serialize().hex(),
        )
        assert_equal(self.ms_wo_wallet.listunspent(addresses=[address]), [])

        self.log.info("Fund the static miniscript watch-only address through direct coinbase generation")
        funding_blockhash = self.generatetoaddress(node, 1, address)[0]
        self.generatetoaddress(node, 100, sink_address)
        funding_txid = node.getblock(funding_blockhash, 2)["tx"][0]["txid"]
        funded = self.find_unspent(self.ms_wo_wallet, address, funding_txid)
        assert_equal(funded["solvable"], True)
        assert_equal(funded["has_private_keys"], False)
        balances = self.ms_wo_wallet.getbalances()
        tracked_bucket = balances["watchonly"] if "watchonly" in balances else balances["mine"]
        assert_equal(tracked_bucket["trusted"], funded["amount"])

        self.log.info("Own one non-signing miniscript PSBT preparation carveout")
        created = self.ms_wo_wallet.send(
            outputs={sink_address: funded["amount"]},
            options={
                "inputs": [{"txid": funded["txid"], "vout": funded["vout"]}],
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
        assert "partial_signatures" not in decoded["inputs"][0]
        assert "final_scriptwitness" not in decoded["inputs"][0]
        assert Decimal(str(decoded["tx"]["vout"][0]["value"])) < funded["amount"]

        processed = self.ms_wo_wallet.walletprocesspsbt(psbt=created["psbt"], finalize=False)
        assert_equal(processed["complete"], False)
        assert "hex" not in processed
        processed_decoded = node.decodepsbt(processed["psbt"])
        assert "witness_utxo" in processed_decoded["inputs"][0]
        assert "partial_signatures" not in processed_decoded["inputs"][0]
        assert "final_scriptwitness" not in processed_decoded["inputs"][0]
        assert_equal(node.finalizepsbt(processed["psbt"])["complete"], False)

        self.log.info("Own one wallet-local signer-backed miniscript import")
        signer_xprv = self.ms_sig_wallet.gethdkeys(private=True, active_only=True)[0]["xprv"]
        signer_desc = descsum_create(f"wsh(pk({signer_xprv}/*))")
        signer_imported = self.ms_sig_wallet.importdescriptors(
            [
                {
                    "desc": signer_desc,
                    "active": True,
                    "range": 1,
                    "next_index": 0,
                    "timestamp": "now",
                }
            ]
        )[0]
        assert signer_imported["success"], signer_imported
        signer_address = self.ms_sig_wallet.getnewaddress(address_type="bech32")
        signer_info = self.ms_sig_wallet.getaddressinfo(signer_address)
        assert_equal(signer_info["ismine"], True)
        assert_equal(signer_info["solvable"], True)
        assert_equal(signer_info["iswatchonly"], False)

        self.log.info("Freeze inherited classical miniscript funding as an explicit signer-side negative control")
        assert_raises_rpc_error(
            -6,
            "Signing transaction failed",
            self.ms_sink_wallet.sendtoaddress,
            signer_address,
            Decimal("1.00000000"),
        )
        assert_equal(self.ms_sig_wallet.listunspent(addresses=[signer_address]), [])

        self.log.info("Fund the signer-backed miniscript address through direct coinbase generation")
        signer_funding_blockhash = self.generatetoaddress(node, 1, signer_address)[0]
        self.generatetoaddress(node, 100, sink_address)
        signer_funding_txid = node.getblock(signer_funding_blockhash, 2)["tx"][0]["txid"]
        signer_funded = self.find_unspent(self.ms_sig_wallet, signer_address, signer_funding_txid)
        assert_equal(signer_funded["solvable"], True)
        assert_equal(signer_funded["spendable"], True)
        assert_equal(signer_funded["has_private_keys"], True)

        self.log.info("Freeze the wallet-local miniscript PSBT update/signing seam")
        signer_psbt = self.ms_sig_wallet.createpsbt(
            [{"txid": signer_funded["txid"], "vout": signer_funded["vout"]}],
            [{sink_address: Decimal("49.90000000")}],
            0,
        )
        unsigned_updated = self.ms_sig_wallet.walletprocesspsbt(
            psbt=signer_psbt,
            sign=False,
            finalize=False,
        )
        assert_equal(unsigned_updated["complete"], False)
        assert unsigned_updated["psbt"] != signer_psbt
        unsigned_updated_input = node.decodepsbt(unsigned_updated["psbt"])["inputs"][0]
        assert "witness_utxo" in unsigned_updated_input
        assert "witness_script" in unsigned_updated_input
        assert "bip32_derivs" in unsigned_updated_input
        assert "partial_signatures" not in unsigned_updated_input
        assert "final_scriptwitness" not in unsigned_updated_input

        signed = self.ms_sig_wallet.walletprocesspsbt(psbt=signer_psbt, finalize=False)
        assert_equal(signed["complete"], False)
        assert "hex" not in signed
        signed_psbt = PSBT.from_base64(signed["psbt"])
        partial_sigs = self.find_partial_sig_entries(signed_psbt.i[0])
        assert_equal(len(partial_sigs), 1)
        assert_equal(len(partial_sigs[0][0]), 33)
        assert partial_sigs[0][1]
        assert len(partial_sigs[0][1]) < LEGACY_PARTIAL_SIG_UPPER_BOUND
        assert_raises_rpc_error(-22, LEGACY_SIGNER_PSBT_ERROR, node.decodepsbt, signed["psbt"])
        assert_raises_rpc_error(-22, LEGACY_SIGNER_PSBT_ERROR, self.ms_sig_wallet.finalizepsbt, signed["psbt"])
        assert_raises_rpc_error(-22, LEGACY_SIGNER_PSBT_ERROR, node.finalizepsbt, signed["psbt"])

        self.log.info("Freeze inherited ranged xpub miniscript imports as explicit deferred failures")
        self.assert_import_rejected(
            self.ms_wo_wallet,
            {
                "desc": descsum_create(XPUB_MINISCRIPT_DESC),
                "active": True,
                "range": 2,
                "next_index": 0,
                "timestamp": "now",
            },
            f"key '{TPUB_A}' is not valid",
        )
        self.assert_import_rejected(
            self.ms_wo_wallet,
            {
                "desc": descsum_create(TAPROOT_XPUB_MINISCRIPT_DESC),
                "active": False,
                "timestamp": "now",
            },
            f"key '{TPUB_A}' is not valid",
        )

        self.log.info("Freeze inherited fixture-based ranged private-key miniscript imports as explicit deferred failures")
        self.assert_import_rejected(
            self.ms_sig_wallet,
            {
                "desc": descsum_create(XPRV_MINISCRIPT_DESC),
                "active": True,
                "range": 1,
                "next_index": 0,
                "timestamp": "now",
            },
            f"key '{TPRV}' is not valid",
        )


if __name__ == "__main__":
    WalletMiniscriptTest(__file__).main()
