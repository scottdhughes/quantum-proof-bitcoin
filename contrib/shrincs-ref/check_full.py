"""Exercise the strict dual-mode SHRINCS verifier against retained vectors."""

from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
from typing import Any

PUBLIC_KEY_BYTES = 48
STATEFUL_MIN = 554
STATEFUL_MAX = 4618
STATELESS_BYTES = 5776


class FullVerifierError(ValueError):
    """Raised when the strict full verifier violates the frozen research contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FullVerifierError(message)


def decode_hex(value: Any, field: str) -> bytes:
    require(isinstance(value, str), f"{field} must be hex text")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise FullVerifierError(f"{field} contains invalid hex") from exc


def read_corpus(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path} root must be an object")
    vectors = data.get("vectors")
    require(isinstance(vectors, list) and vectors, f"{path} must contain vectors")
    for vector in vectors:
        require(isinstance(vector, dict), f"{path} vector must be an object")
        require(isinstance(vector.get("name"), str), f"{path} vector name missing")
    return vectors


def load_verifier(path: Path):
    library = ctypes.CDLL(str(path.resolve()))
    verify = library.pqbtc_shrincs_verify
    verify.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    verify.restype = ctypes.c_int
    return verify


def c_buffer(data: bytes):
    if not data:
        return None
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


def call_verify(verify, public_key: bytes, signature: bytes, message: bytes, context: bytes) -> bool:
    return (
        verify(
            c_buffer(public_key),
            len(public_key),
            c_buffer(signature),
            len(signature),
            c_buffer(message),
            len(message),
            c_buffer(context),
            len(context),
        )
        == 1
    )


def unpack(vector: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    public_key = decode_hex(vector.get("public_key"), "public_key")
    signature = decode_hex(vector.get("signature"), "signature")
    message = decode_hex(vector.get("message"), "message")
    context = decode_hex(vector.get("context"), "context")
    require(len(public_key) == PUBLIC_KEY_BYTES, "public-key length drifted")
    return public_key, signature, message, context


def run(verify, stateful_vectors: list[dict[str, Any]], stateless_vectors: list[dict[str, Any]]) -> dict[str, int | str]:
    valid_stateful = 0
    valid_stateless = 0
    strict_negatives = 0

    for vector in stateful_vectors:
        public_key, signature, message, context = unpack(vector)
        require(STATEFUL_MIN <= len(signature) <= STATEFUL_MAX, "stateful signature length drifted")
        require(call_verify(verify, public_key, signature, message, context), f"stateful vector rejected: {vector['name']}")
        valid_stateful += 1

        # A valid stateful signature may not become the stateless mode merely by padding.
        padded = signature + bytes(STATELESS_BYTES - len(signature))
        require(not call_verify(verify, public_key, padded, message, context), f"padded stateful vector accepted: {vector['name']}")
        strict_negatives += 1

        # Adjacent non-canonical lengths must fail before any alternate mode can apply.
        require(not call_verify(verify, public_key, signature + b"\x00", message, context), f"extended stateful vector accepted: {vector['name']}")
        strict_negatives += 1

    for vector in stateless_vectors:
        public_key, signature, message, context = unpack(vector)
        require(len(signature) == STATELESS_BYTES, "stateless signature length drifted")
        require(call_verify(verify, public_key, signature, message, context), f"stateless vector rejected: {vector['name']}")
        valid_stateless += 1

        # Truncations that land inside or at the stateful envelope must never validate.
        for length in (STATEFUL_MIN, STATEFUL_MAX, STATELESS_BYTES - 1):
            require(not call_verify(verify, public_key, signature[:length], message, context), f"truncated stateless vector accepted at {length}: {vector['name']}")
            strict_negatives += 1

    # Global parser boundary checks using one valid vector of each mode.
    spk, ssig, smsg, sctx = unpack(stateful_vectors[0])
    require(not call_verify(verify, spk[:-1], ssig, smsg, sctx), "47-byte public key accepted")
    strict_negatives += 1
    require(not call_verify(verify, spk + b"\x00", ssig, smsg, sctx), "49-byte public key accepted")
    strict_negatives += 1
    require(not call_verify(verify, spk, ssig, smsg, bytes(256)), "256-byte context accepted")
    strict_negatives += 1
    require(not call_verify(verify, spk, ssig, bytes(4097), sctx), "oversize message accepted")
    strict_negatives += 1

    return {
        "valid_stateful": valid_stateful,
        "valid_stateless": valid_stateless,
        "strict_negatives": strict_negatives,
        "result": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--stateful-vectors", type=Path, required=True)
    parser.add_argument("--stateless-vectors", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run(
        load_verifier(args.library),
        read_corpus(args.stateful_vectors),
        read_corpus(args.stateless_vectors),
    )
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
