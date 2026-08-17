#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Mine and spend actual PQBTC-SHRINCS-v0 outputs on private regtest."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType

from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import CScript, OP_2
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

DRAFT_COMMIT = "acc6bda51dc3b94848d118967247ad0f3cd7a80e"
REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "contrib" / "shrincs-tx" / "tx_model.py"


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def git_head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def kdf(label: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(label + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


class SHRINCSRegtestTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def _build_spend(
        self,
        *,
        model: ModuleType,
        reference: ModuleType,
        secret_key: bytes,
        public_key: bytes,
        funding: dict,
        funding_amount: int,
        destination_script: bytes,
        stateful: bool,
    ) -> CTransaction:
        fee = 20_000
        sequence = 0xFFFFFFFD
        transaction = CTransaction()
        transaction.version = 2
        transaction.vin = [
            CTxIn(
                COutPoint(int(funding["txid"], 16), funding["sent_vout"]),
                scriptSig=b"",
                nSequence=sequence,
            )
        ]
        transaction.vout = [
            CTxOut(funding_amount - fee, destination_script)
        ]
        transaction.nLockTime = 0

        spent_script = model.script_pubkey(public_key)
        model_transaction = model.Transaction(
            version=transaction.version,
            inputs=(
                model.SpentInput(
                    prevout=model.OutPoint(
                        bytes.fromhex(funding["txid"])[::-1],
                        funding["sent_vout"],
                    ),
                    amount=funding_amount,
                    script_pubkey=spent_script,
                    sequence=sequence,
                ),
            ),
            outputs=(
                model.TxOutput(
                    funding_amount - fee,
                    destination_script,
                ),
            ),
            lock_time=transaction.nLockTime,
        )
        digest = model.transaction_sighash(
            model_transaction,
            0,
            model.TEST_CHAIN_ID,
        )
        if stateful:
            signature = reference.shrincs_sign(
                digest,
                model.SHRINCS_CONTEXT,
                secret_key,
                0,
                None,
            )
        else:
            signature = reference.shrincs_sign(
                digest,
                model.SHRINCS_CONTEXT,
                secret_key,
                None,
                kdf(b"pqbtc-shrincs-regtest/stateless-randomizer", 16),
            )
        if signature is None:
            raise RuntimeError("pinned SHRINCS signer failed")

        assert_equal(
            reference.shrincs_verify(
                digest,
                signature,
                model.SHRINCS_CONTEXT,
                public_key,
            ),
            True,
        )
        transaction.wit.vtxinwit = [CTxInWitness()]
        transaction.wit.vtxinwit[0].scriptWitness.stack = [
            signature,
            public_key,
        ]
        return transaction

    def run_test(self):
        shrincs_bip = Path(os.environ["SHRINCS_BIP_DIR"]).resolve()
        assert_equal(git_head(shrincs_bip), DRAFT_COMMIT)
        model = load_module(MODEL_PATH, "pqbtc_shrincs_regtest_tx_model")
        reference = load_module(
            shrincs_bip / "impl" / "shrincs.py",
            "pqbtc_shrincs_regtest_reference",
        )

        seed = kdf(b"pqbtc-shrincs-regtest/key-seed", 48)
        structure = bytes([reference.FXMSS_SHAPE_UNBALANCED, 4])
        secret_key, public_key = reference.shrincs_keygen(seed, structure)
        assert_equal(len(public_key), model.PUBLIC_KEY_BYTES)

        shrincs_script = bytes(
            CScript([OP_2, model.output_commitment(public_key)])
        )
        assert_equal(shrincs_script, model.script_pubkey(public_key))

        node = self.nodes[0]
        wallet = MiniWallet(node)
        wallet.generate(101)

        funding_amount = 1_000_000
        stateful_funding = wallet.send_to(
            from_node=node,
            scriptPubKey=shrincs_script,
            amount=funding_amount,
            fee=2_000,
        )
        stateless_funding = wallet.send_to(
            from_node=node,
            scriptPubKey=shrincs_script,
            amount=funding_amount,
            fee=2_000,
        )
        wallet.generate(1)

        destination_script = bytes(wallet.get_output_script())
        stateful_transaction = self._build_spend(
            model=model,
            reference=reference,
            secret_key=secret_key,
            public_key=public_key,
            funding=stateful_funding,
            funding_amount=funding_amount,
            destination_script=destination_script,
            stateful=True,
        )
        stateless_transaction = self._build_spend(
            model=model,
            reference=reference,
            secret_key=secret_key,
            public_key=public_key,
            funding=stateless_funding,
            funding_amount=funding_amount,
            destination_script=destination_script,
            stateful=False,
        )

        for label, transaction in (
            ("stateful", stateful_transaction),
            ("stateless", stateless_transaction),
        ):
            raw = transaction.serialize().hex()
            accepted = node.testmempoolaccept([raw])[0]
            assert_equal(accepted["allowed"], True)

            mutated = CTransaction(transaction)
            bad_signature = bytearray(
                mutated.wit.vtxinwit[0].scriptWitness.stack[0]
            )
            bad_signature[len(bad_signature) // 2] ^= 1
            mutated.wit.vtxinwit[0].scriptWitness.stack[0] = bytes(
                bad_signature
            )
            rejected = node.testmempoolaccept(
                [mutated.serialize().hex()]
            )[0]
            assert_equal(rejected["allowed"], False)

            txid = node.sendrawtransaction(raw)
            assert_equal(txid, transaction.txid_hex)
            self.log.info(
                "Accepted %s SHRINCS spend %s (%d witness bytes)",
                label,
                txid,
                len(transaction.wit.vtxinwit[0].scriptWitness.stack[0]),
            )

        block_hash = wallet.generate(1)[0]
        block_txids = node.getblock(block_hash)["tx"]
        assert stateful_transaction.txid_hex in block_txids
        assert stateless_transaction.txid_hex in block_txids

        assert_equal(
            node.gettxout(
                stateful_funding["txid"],
                stateful_funding["sent_vout"],
            ),
            None,
        )
        assert_equal(
            node.gettxout(
                stateless_funding["txid"],
                stateless_funding["sent_vout"],
            ),
            None,
        )
        assert_equal(node.getblockcount(), 103)


if __name__ == "__main__":
    SHRINCSRegtestTest(__file__).main()
