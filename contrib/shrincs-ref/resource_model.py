"""Exact SHA-256 compression bounds for the pinned PQBTC SHRINCS verifier.

The model counts compression-function invocations in the current portable C
implementation. It intentionally does not use the upstream report's
midstate-cached convention. The resulting bounds therefore describe the exact
one-shot SHA-256 implementation linked into the research verifier.
"""

from __future__ import annotations

from dataclasses import dataclass

SHA256_BLOCK_BYTES = 64
PUBLIC_KEY_BYTES = 48
STATEFUL_SIGNATURE_BASE_BYTES = 538
STATEFUL_MIN_DEPTH = 1
STATEFUL_MAX_DEPTH = 255
STATELESS_SIGNATURE_BYTES = 5776
MAX_MESSAGE_BYTES = 4096
MAX_CONTEXT_BYTES = 255

WOTS_C_CHAIN_COUNT = 32
WOTS_C_CHAIN_MAX = 15
WOTS_C_CONSTANT_SUM = 240
WOTS_TW_MESSAGE_CHAINS = 32
WOTS_TW_CHECKSUM_CHAINS = 3
WOTS_TW_CHAIN_MAX = 15
WOTS_TW_CHECKSUM_MAX = WOTS_TW_MESSAGE_CHAINS * WOTS_TW_CHAIN_MAX

SPHX_LAYER_COUNT = 5
SPHX_XMSS_HEIGHT = 9
SPHX_FORS_HEIGHT = 13
SPHX_FORS_COUNT = 10


@dataclass(frozen=True)
class CompressionEnvelope:
    minimum: int
    maximum: int


def sha256_compressions(input_bytes: int) -> int:
    """Return exact SHA-256 blocks for a one-shot message of input_bytes."""

    if input_bytes < 0:
        raise ValueError("input_bytes must be non-negative")
    full, remainder = divmod(input_bytes, SHA256_BLOCK_BYTES)
    padding_blocks = 1 if remainder < 56 else 2
    return full + padding_blocks


def hex_digit_sum(value: int) -> int:
    if value < 0:
        raise ValueError("value must be non-negative")
    if value == 0:
        return 0
    total = 0
    while value:
        total += value & 0xF
        value >>= 4
    return total


def wots_tw_verify_steps_from_checksum(checksum: int) -> int:
    """Exact WOTS-TW chain steps for a checksum in [0, 480].

    The 32 message digits have sum 480-checksum. The three checksum digits are
    the base-16 digits of checksum. Completing all 35 chains therefore costs
    525 - ((480-checksum) + digit_sum_16(checksum)).
    """

    if not 0 <= checksum <= WOTS_TW_CHECKSUM_MAX:
        raise ValueError("checksum out of range")
    return 45 + checksum - hex_digit_sum(checksum)


def wots_tw_step_envelope() -> CompressionEnvelope:
    values = [
        wots_tw_verify_steps_from_checksum(checksum)
        for checksum in range(WOTS_TW_CHECKSUM_MAX + 1)
    ]
    return CompressionEnvelope(min(values), max(values))


def stateful_signature_depth(signature_bytes: int) -> int:
    delta = signature_bytes - STATEFUL_SIGNATURE_BASE_BYTES
    if delta < STATEFUL_MIN_DEPTH * 16 or delta % 16:
        raise ValueError("non-canonical stateful signature length")
    depth = delta // 16
    if depth > STATEFUL_MAX_DEPTH:
        raise ValueError("stateful depth exceeds pinned profile")
    return depth


def stateful_compressions(message_bytes: int, context_bytes: int, depth: int) -> int:
    if not 0 <= message_bytes <= MAX_MESSAGE_BYTES:
        raise ValueError("message length out of range")
    if not 0 <= context_bytes <= MAX_CONTEXT_BYTES:
        raise ValueError("context length out of range")
    if not STATEFUL_MIN_DEPTH <= depth <= STATEFUL_MAX_DEPTH:
        raise ValueError("stateful depth out of range")

    # H_msg_sf: SHA256(R || PK.seed || PK.sf_root || ADRS[0:9] ||
    #                  0 || len(ctx) || ctx || PK.sl_root || message),
    # then SHA256(R || PK.seed || ADRS[0:9] || inner_hash).
    message_hash = sha256_compressions(75 + context_bytes + message_bytes)
    message_hash += sha256_compressions(73)

    # WOTS+C verification: one 112-byte grinding hash, exactly 240 remaining
    # chain steps (constant digit sum 240), then a 512-byte chain-tip thash.
    wots = sha256_compressions(112)
    wots += (WOTS_C_CHAIN_COUNT * WOTS_C_CHAIN_MAX - WOTS_C_CONSTANT_SUM) * sha256_compressions(102)
    wots += sha256_compressions(598)

    # One 32-byte Merkle-node thash per FXMSS authentication level.
    authentication = depth * sha256_compressions(118)
    return message_hash + wots + authentication


def stateful_global_maximum() -> int:
    return stateful_compressions(MAX_MESSAGE_BYTES, MAX_CONTEXT_BYTES, STATEFUL_MAX_DEPTH)


def stateless_compression_envelope(message_bytes: int, context_bytes: int) -> CompressionEnvelope:
    if not 0 <= message_bytes <= MAX_MESSAGE_BYTES:
        raise ValueError("message length out of range")
    if not 0 <= context_bytes <= MAX_CONTEXT_BYTES:
        raise ValueError("context length out of range")

    # H_msg: inner contextualized message hash and fixed 68-byte outer hash.
    digest = sha256_compressions(66 + context_bytes + message_bytes)
    digest += sha256_compressions(68)

    # FORS: ten leaf hashes, ten 13-level paths, and one ten-root thash.
    fors = SPHX_FORS_COUNT * (
        sha256_compressions(102)
        + SPHX_FORS_HEIGHT * sha256_compressions(118)
    )
    fors += sha256_compressions(246)

    # Each XMSS layer has one WOTS-TW chain-tip compression and nine Merkle
    # levels. The chain-walk term varies with the signer-controlled digest.
    xmss_fixed_per_layer = sha256_compressions(646)
    xmss_fixed_per_layer += SPHX_XMSS_HEIGHT * sha256_compressions(118)

    steps = wots_tw_step_envelope()
    minimum = digest + fors + SPHX_LAYER_COUNT * (
        xmss_fixed_per_layer + steps.minimum * sha256_compressions(102)
    )
    maximum = digest + fors + SPHX_LAYER_COUNT * (
        xmss_fixed_per_layer + steps.maximum * sha256_compressions(102)
    )
    return CompressionEnvelope(minimum, maximum)


def stateless_global_maximum() -> int:
    return stateless_compression_envelope(MAX_MESSAGE_BYTES, MAX_CONTEXT_BYTES).maximum


def model_summary() -> dict[str, object]:
    steps = wots_tw_step_envelope()
    return {
        "sha256_convention": "portable-one-shot-compression-blocks",
        "wots_tw_steps": {
            "minimum": steps.minimum,
            "maximum": steps.maximum,
            "maximum_checksum": 480,
            "maximum_checksum_hex": "1e0",
        },
        "stateful": {
            "global_maximum_compressions": stateful_global_maximum(),
            "maximum_depth": STATEFUL_MAX_DEPTH,
            "maximum_message_bytes": MAX_MESSAGE_BYTES,
            "maximum_context_bytes": MAX_CONTEXT_BYTES,
        },
        "stateless": {
            "global_maximum_compressions": stateless_global_maximum(),
            "maximum_message_bytes": MAX_MESSAGE_BYTES,
            "maximum_context_bytes": MAX_CONTEXT_BYTES,
        },
    }


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    summary = model_summary()
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
