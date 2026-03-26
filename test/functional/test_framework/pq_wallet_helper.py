#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpers for deterministic PQ wallet descriptor batches."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from test_framework.address import script_to_p2wsh
from test_framework.descriptors import descsum_create
from test_framework.pqsig import build_pq_keypair
from test_framework.script import CScript, OP_CHECKSIG
from test_framework.script_util import script_to_p2wsh_script


@dataclass(frozen=True)
class PQDescriptorEntry:
    index: int
    internal: bool
    sk_seed: bytes
    pk_script: bytes
    witness_script: CScript
    script_pub_key: CScript
    address: str
    descriptor: str
    label: str | None

    def import_request(self, timestamp: int | str) -> dict[str, object]:
        request: dict[str, object] = {
            "desc": self.descriptor,
            "timestamp": timestamp,
        }
        if self.internal:
            request["internal"] = True
        elif self.label is not None:
            request["label"] = self.label
        return request


def _derive_test_seed(root_seed: bytes, internal: bool, index: int) -> bytes:
    return hashlib.sha256(
        b"PQSIG-WALLET-POOL-v1"
        + root_seed
        + (b"\x01" if internal else b"\x00")
        + index.to_bytes(4, "little")
    ).digest()


def _derive_wallet_seed(root_seed: bytes, internal: bool, index: int) -> bytes:
    prk = hmac.new(b"PQSIG-WALLET-ROOT-v1", root_seed, hashlib.sha256).digest()
    info = f"branch={1 if internal else 0};index={index}".encode()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def _build_entry(root_seed: bytes, internal: bool, index: int, label_prefix: str) -> PQDescriptorEntry:
    sk_seed = _derive_test_seed(root_seed, internal, index)
    _, pk_script = build_pq_keypair(sk_seed)
    witness_script = CScript([pk_script, OP_CHECKSIG])
    return PQDescriptorEntry(
        index=index,
        internal=internal,
        sk_seed=sk_seed,
        pk_script=pk_script,
        witness_script=witness_script,
        script_pub_key=script_to_p2wsh_script(witness_script),
        address=script_to_p2wsh(witness_script),
        descriptor=descsum_create(f"pq({pk_script.hex()})"),
        label=None if internal else f"{label_prefix}-{index}",
    )


def build_bounded_pq_descriptor_batch(
    root_seed: bytes,
    *,
    external_count: int,
    internal_count: int,
    label_prefix: str = "pq-external",
) -> tuple[list[PQDescriptorEntry], list[PQDescriptorEntry]]:
    external_entries = [
        _build_entry(root_seed=root_seed, internal=False, index=index, label_prefix=label_prefix)
        for index in range(external_count)
    ]
    internal_entries = [
        _build_entry(root_seed=root_seed, internal=True, index=index, label_prefix=label_prefix)
        for index in range(internal_count)
    ]
    return external_entries, internal_entries


def make_pqpriv_descriptor(root_seed: bytes, internal: bool) -> str:
    return descsum_create(f"pqpriv({root_seed.hex()}/{1 if internal else 0}/*)")


def make_pqpriv_import_request(
    root_seed: bytes,
    *,
    internal: bool,
    active: bool,
    timestamp: int | str,
    range_end: int,
    next_index: int = 0,
) -> dict[str, object]:
    request: dict[str, object] = {
        "desc": make_pqpriv_descriptor(root_seed, internal),
        "active": active,
        "timestamp": timestamp,
        "range": [0, range_end],
        "next_index": next_index,
    }
    if internal:
        request["internal"] = True
    return request


def build_active_pq_descriptor_entry(root_seed: bytes, *, internal: bool, index: int, label: str | None = None) -> PQDescriptorEntry:
    sk_seed = _derive_wallet_seed(root_seed, internal, index)
    _, pk_script = build_pq_keypair(sk_seed)
    witness_script = CScript([pk_script, OP_CHECKSIG])
    return PQDescriptorEntry(
        index=index,
        internal=internal,
        sk_seed=sk_seed,
        pk_script=pk_script,
        witness_script=witness_script,
        script_pub_key=script_to_p2wsh_script(witness_script),
        address=script_to_p2wsh(witness_script),
        descriptor=descsum_create(f"pq({pk_script.hex()})"),
        label=label,
    )
