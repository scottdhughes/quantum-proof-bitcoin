#!/usr/bin/env python3
"""Reproduce known PQSig rc2 construction-level conformance failures.

This is a primitive-level audit. It does not claim a complete transaction
forgery. By default, detected nonconformance produces a failing exit status.
Use --expect-release-hold only when validating the checked-in hold evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pqsig_ref as ref


@dataclass(frozen=True)
class AuditResult:
    name: str
    nonconformant: bool
    detail: str


def _digit_sum(message: bytes) -> int:
    return sum(ref._message_nibble(message, i) for i in range(ref.L))


def audit_wots_fixed_sum() -> AuditResult:
    """Show that unrestricted WOTS digits retain the chain-extension attack."""
    sk_seed = bytes(range(32))
    pk_seed = ref.derive_pk_seed(sk_seed)
    layer = 0
    leaf_index = 0
    low_message = bytes(ref.N)
    high_message = bytes([0xFF]) * ref.N

    low_signature = ref._fill_wots_sig(sk_seed, pk_seed, low_message, layer, leaf_index)
    advanced_signature = bytearray(len(low_signature))

    for chunk_index in range(ref.L):
        low_digit = ref._message_nibble(low_message, chunk_index)
        high_digit = ref._message_nibble(high_message, chunk_index)
        chunk_start = chunk_index * ref.N
        chunk = low_signature[chunk_start : chunk_start + ref.N]
        advanced = ref._advance_chain(
            chunk,
            pk_seed,
            layer,
            leaf_index,
            chunk_index,
            low_digit,
            high_digit - low_digit,
        )
        advanced_signature[chunk_start : chunk_start + ref.N] = advanced

    low_public = ref._reconstruct_wots_public_chunks(
        low_signature, low_message, pk_seed, layer, leaf_index
    )
    high_public = ref._reconstruct_wots_public_chunks(
        bytes(advanced_signature), high_message, pk_seed, layer, leaf_index
    )
    low_sum = _digit_sum(low_message)
    high_sum = _digit_sum(high_message)
    nonconformant = (
        low_public == high_public
        and low_sum != ref.SWN
        and high_sum != ref.SWN
    )

    return AuditResult(
        name="WOTS+C fixed-sum encoding",
        nonconformant=nonconformant,
        detail=(
            f"same_public_key={low_public == high_public} "
            f"digit_sums={low_sum},{high_sum} required_sum={ref.SWN}"
        ),
    )


def audit_pors_distinct_indices() -> AuditResult:
    """Show that the rc2 index extractor does not enforce distinct indices."""
    indices = ref._derive_pors_indices(bytes(64))
    unique_count = len(set(indices))
    return AuditResult(
        name="PORS+FP distinct-index enforcement",
        nonconformant=unique_count != ref.K,
        detail=f"indices={indices} unique={unique_count} required={ref.K}",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect-release-hold",
        action="store_true",
        help="exit successfully only when all checked hold findings reproduce",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = [audit_wots_fixed_sum(), audit_pors_distinct_indices()]
    for result in results:
        status = "NONCONFORMANT" if result.nonconformant else "NOT_REPRODUCED"
        print(f"{result.name}: {status}")
        print(f"  {result.detail}")

    hold_reproduced = all(result.nonconformant for result in results)
    print(f"release_status={'HOLD' if hold_reproduced else 'REASSESS'}")

    if args.expect_release_hold:
        return 0 if hold_reproduced else 1
    return 1 if hold_reproduced else 0


if __name__ == "__main__":
    raise SystemExit(main())
