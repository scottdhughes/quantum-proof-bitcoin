"""Build a deterministic libFuzzer seed corpus for the full SHRINCS verifier."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

HEADER_BYTES = 7
MAX_PUBLIC_KEY_BYTES = 64
MAX_SIGNATURE_BYTES = 6000
MAX_MESSAGE_BYTES = 4097
MAX_CONTEXT_BYTES = 256


class FuzzCorpusError(ValueError):
    """Raised when a KAT cannot be converted into the fuzz input format."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FuzzCorpusError(message)


def decode_hex(value: Any, field: str) -> bytes:
    require(isinstance(value, str), f"{field} must be hex")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise FuzzCorpusError(f"{field} contains invalid hex") from exc


def load_vectors(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path} root must be an object")
    vectors = data.get("vectors")
    require(isinstance(vectors, list) and vectors, f"{path} must contain vectors")
    require(all(isinstance(vector, dict) for vector in vectors), f"{path} vector must be an object")
    return vectors


def encode(public_key: bytes, signature: bytes, message: bytes, context: bytes) -> bytes:
    require(len(public_key) <= MAX_PUBLIC_KEY_BYTES, "public key exceeds fuzz format")
    require(len(signature) <= MAX_SIGNATURE_BYTES, "signature exceeds fuzz format")
    require(len(message) <= MAX_MESSAGE_BYTES, "message exceeds fuzz format")
    require(len(context) <= MAX_CONTEXT_BYTES, "context exceeds fuzz format")
    header = bytes([len(public_key)])
    header += len(signature).to_bytes(2, "big")
    header += len(message).to_bytes(2, "big")
    header += len(context).to_bytes(2, "big")
    return header + public_key + signature + message + context


def unpack(vector: dict[str, Any]) -> tuple[str, bytes, bytes, bytes, bytes]:
    name = str(vector.get("name", "unnamed"))
    return (
        name,
        decode_hex(vector.get("public_key"), f"{name}.public_key"),
        decode_hex(vector.get("signature"), f"{name}.signature"),
        decode_hex(vector.get("message"), f"{name}.message"),
        decode_hex(vector.get("context"), f"{name}.context"),
    )


def safe_name(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value)


def flip(data: bytes, offset: int, mask: int = 1) -> bytes:
    require(0 <= offset < len(data), "mutation offset out of range")
    output = bytearray(data)
    output[offset] ^= mask
    return bytes(output)


def add_case(cases: dict[str, bytes], name: str, value: bytes) -> None:
    digest = hashlib.sha256(value).hexdigest()[:12]
    cases[f"{safe_name(name)}-{digest}"] = value


def build(stateful: list[dict[str, Any]], stateless: list[dict[str, Any]]) -> dict[str, bytes]:
    cases: dict[str, bytes] = {}
    all_vectors = stateful + stateless
    for vector in all_vectors:
        name, public_key, signature, message, context = unpack(vector)
        add_case(cases, f"valid-{name}", encode(public_key, signature, message, context))
        for label, offset in (
            ("sig-first", 0),
            ("sig-middle", len(signature) // 2),
            ("sig-last", len(signature) - 1),
        ):
            add_case(cases, f"{name}-{label}", encode(public_key, flip(signature, offset), message, context))
        add_case(cases, f"{name}-pk-first", encode(flip(public_key, 0), signature, message, context))
        if signature:
            add_case(cases, f"{name}-sig-truncated", encode(public_key, signature[:-1], message, context))
        if len(signature) < MAX_SIGNATURE_BYTES:
            add_case(cases, f"{name}-sig-extended", encode(public_key, signature + b"\x00", message, context))

    _name, public_key, signature, message, context = unpack(stateful[0])
    for length in (0, 1, 47, 49, 553, 555, 4619, 5775, 5777, 6000):
        add_case(cases, f"boundary-signature-{length}", encode(public_key, bytes(length), message, context))
    add_case(cases, "boundary-public-key-47", encode(public_key[:-1], signature, message, context))
    add_case(cases, "boundary-public-key-49", encode(public_key + b"\x00", signature, message, context))
    add_case(cases, "boundary-message-4097", encode(public_key, signature, bytes(4097), context))
    add_case(cases, "boundary-context-256", encode(public_key, signature, message, bytes(256)))

    for index in range(8):
        noise = hashlib.sha256(f"pqbtc-shrincs-fuzz-noise-{index}".encode()).digest()
        add_case(cases, f"noise-{index}", noise)
    return cases


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stateful", type=Path, required=True)
    parser.add_argument("--stateless", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    cases = build(load_vectors(args.stateful), load_vectors(args.stateless))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for old in args.output_dir.iterdir():
        if old.is_file():
            old.unlink()
    for name, value in sorted(cases.items()):
        (args.output_dir / name).write_bytes(value)

    result = {
        "result": "PASS",
        "corpus_files": len(cases),
        "corpus_bytes": sum(len(value) for value in cases.values()),
        "maximum_input_bytes": max(len(value) for value in cases.values()),
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
