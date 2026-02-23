#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PQSig helpers for functional tests."""

from __future__ import annotations

import configparser
from decimal import Decimal
import os
from pathlib import Path
import sys

from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    SEQUENCE_FINAL,
    tx_from_hex,
)
from test_framework.descriptors import descsum_create
from test_framework.script import (
    CScript,
    LegacySignatureHash,
    SegwitV0SignatureHash,
    OP_TRUE,
    SIGHASH_ALL,
)


def _resolve_ref_dir() -> Path:
    candidate_roots = []
    for env_name in ("SRCDIR", "BASE_ROOT_DIR"):
        env_value = os.environ.get(env_name)
        if env_value:
            candidate_roots.append(Path(env_value))

    # Functional tests executed from the build tree provide source paths in
    # build/test/config.ini.
    config_path = Path(__file__).resolve().parents[2] / "config.ini"
    if config_path.is_file():
        config = configparser.ConfigParser()
        config.read(config_path)
        srcdir = config.get("environment", "SRCDIR", fallback="")
        if srcdir:
            candidate_roots.append(Path(srcdir))

    candidate_roots.extend(Path(__file__).resolve().parents)

    seen = set()
    for root in candidate_roots:
        root = root.resolve()
        if root in seen:
            continue
        seen.add(root)
        ref_dir = root / "contrib" / "pqsig-ref"
        if (ref_dir / "pqsig_ref.py").is_file():
            return ref_dir

    raise ModuleNotFoundError("Unable to locate contrib/pqsig-ref/pqsig_ref.py")


REF_DIR = _resolve_ref_dir()
if str(REF_DIR) not in sys.path:
    sys.path.insert(0, str(REF_DIR))

from pqsig_ref import derive_pk_script, pqsig_sign  # type: ignore[import]  # noqa: E402


def build_pq_keypair(sk_seed: bytes) -> tuple[bytes, bytes]:
    return sk_seed, derive_pk_script(sk_seed)


def sign_legacy_input_pq(tx: CTransaction, input_scriptpubkey: CScript, sk_seed: bytes, pk_script33: bytes) -> bytes:
    sighash, err = LegacySignatureHash(input_scriptpubkey, tx, 0, SIGHASH_ALL)
    assert err is None
    return pqsig_sign(sighash, sk_seed, pk_script33)


def sign_segwitv0_input_pq(tx: CTransaction, witness_script: CScript, input_amount: int, sk_seed: bytes, pk_script33: bytes) -> bytes:
    sighash = SegwitV0SignatureHash(witness_script, tx, 0, SIGHASH_ALL, input_amount)
    return pqsig_sign(sighash, sk_seed, pk_script33)


def _ensure_pq_funding_utxos(node):
    utxos = node.__dict__.setdefault("_pqsig_funding_utxos", [])
    height = node.getblockcount()
    mature = [u for u in utxos if u["mature_height"] <= height]
    if mature:
        return utxos

    descriptor = descsum_create("raw(51)")  # OP_TRUE
    block_hashes = node.generatetodescriptor(101, descriptor, called_by_framework=True)
    for block_hash in block_hashes:
        block = node.getblock(block_hash, 2)
        coinbase = block["tx"][0]
        for vout in coinbase["vout"]:
            if vout["scriptPubKey"]["hex"] == "51":
                utxos.append({
                    "txid": coinbase["txid"],
                    "vout": vout["n"],
                    "value_sat": int(Decimal(str(vout["value"])) * COIN),
                    "mature_height": block["height"] + 100,
                })
                break

    return utxos


def _pop_mature_funding_utxo(node):
    utxos = _ensure_pq_funding_utxos(node)
    height = node.getblockcount()
    for idx, utxo in enumerate(utxos):
        if utxo["mature_height"] <= height:
            return utxos.pop(idx)
    raise AssertionError("No mature PQ funding UTXO available")


def create_wallet_funded_tx(node, destination_scriptpubkey: bytes, amount_sat: int, fee_sat: int = 1000) -> CTransaction:
    """Create a funding tx without relying on legacy wallet signing paths.

    v1 consensus has PQ-only CHECKSIG semantics, so functional funding must avoid
    ECDSA/Schnorr wallet authorization.
    """
    utxo = _pop_mature_funding_utxo(node)
    change_sat = utxo["value_sat"] - amount_sat - fee_sat
    assert change_sat > 0

    tx = CTransaction()
    tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), b"", SEQUENCE_FINAL - 1)]
    tx.vout = [
        CTxOut(amount_sat, destination_scriptpubkey),
        CTxOut(change_sat, CScript([OP_TRUE])),
    ]
    return tx_from_hex(tx.serialize().hex())
