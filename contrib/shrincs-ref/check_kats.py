"""Validate immutable hashes for regenerated current-draft SHRINCS KATs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = REPO_ROOT / "contrib" / "shrincs-ref" / "kat-lock.json"
EXPECTED_LOCK_PROFILE = "pqbtc-shrincs-current-draft-kat-lock-v0"
EXPECTED_DRAFT_COMMIT = "acc6bda51dc3b94848d118967247ad0f3cd7a80e"
EXPECTED_LIBSHRINCS_COMMIT = "53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5"
EXPECTED_RESOURCE_PROFILE = "pqbtc-shrincs-current-draft-resource-v0"
EXPECTED_RESOURCE_NAMES = [
    "stateful_max_depth_message_context",
    "stateless_max_message_context",
]


class KatError(ValueError):
    """Raised when locked SHRINCS KAT evidence drifts."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KatError(message)


def decode_hex(value: Any, field: str) -> bytes:
    require(isinstance(value, str), f"{field} must be hex text")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise KatError(f"{field} contains invalid hex") from exc


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_digest(value: object, field: str) -> None:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"{field} is invalid",
    )


def validate_signature_lengths(value: object, field: str) -> None:
    require(
        isinstance(value, list)
        and value
        and value == sorted(set(value))
        and all(isinstance(length, int) and length > 0 for length in value),
        f"{field} is invalid",
    )


def validate_lock_entry(kind: str, entry: object) -> None:
    require(isinstance(entry, dict), f"{kind} lock entry must be an object")
    validate_digest(entry.get("sha256"), f"{kind} locked SHA-256")
    require(isinstance(entry.get("profile"), str), f"{kind} profile missing")
    require(
        isinstance(entry.get("vector_count"), int) and entry["vector_count"] > 0,
        f"{kind} vector count invalid",
    )
    validate_signature_lengths(
        entry.get("signature_lengths"),
        f"{kind} signature-length lock",
    )


def validate_resource_lock(entry: object) -> None:
    validate_lock_entry("resource", entry)
    assert isinstance(entry, dict)
    require(entry.get("profile") == EXPECTED_RESOURCE_PROFILE, "resource profile lock drifted")
    require(entry.get("message_bytes") == 4096, "resource message-length lock drifted")
    require(entry.get("context_bytes") == 255, "resource context-length lock drifted")
    require(
        entry.get("vector_names") == EXPECTED_RESOURCE_NAMES,
        "resource vector-name lock drifted",
    )
    require(
        entry.get("signature_lengths") == [4618, 5776],
        "resource signature-length lock drifted",
    )


def load_lock(path: Path = DEFAULT_LOCK) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "KAT lock root must be an object")
    require(data.get("schema_version") == 1, "KAT lock schema drifted")
    require(data.get("profile") == EXPECTED_LOCK_PROFILE, "KAT lock profile drifted")
    require(data.get("draft_commit") == EXPECTED_DRAFT_COMMIT, "KAT draft pin drifted")
    require(
        data.get("libshrincs_commit") == EXPECTED_LIBSHRINCS_COMMIT,
        "KAT libshrincs pin drifted",
    )

    corpora = data.get("corpora")
    require(
        isinstance(corpora, dict) and set(corpora) == {"stateful", "stateless"},
        "KAT corpus set drifted",
    )
    for kind in ("stateful", "stateless"):
        validate_lock_entry(kind, corpora[kind])
    validate_resource_lock(data.get("resource_vectors"))
    return data


def validate_vector_common(
    vector: object,
    kind: str,
    index: int,
) -> tuple[str, bytes, bytes, bytes, bytes]:
    require(isinstance(vector, dict), f"{kind} vector {index} must be an object")
    name = vector.get("name")
    require(isinstance(name, str) and name, f"{kind} vector {index} name missing")

    public_key = decode_hex(vector.get("public_key"), f"{name}.public_key")
    signature = decode_hex(vector.get("signature"), f"{name}.signature")
    message = decode_hex(vector.get("message"), f"{name}.message")
    context = decode_hex(vector.get("context"), f"{name}.context")

    require(len(public_key) == 48, f"{name} public-key length drifted")
    require(
        hashlib.sha256(public_key).hexdigest() == vector.get("public_key_sha256"),
        f"{name} public-key digest drifted",
    )
    require(
        hashlib.sha256(signature).hexdigest() == vector.get("signature_sha256"),
        f"{name} signature digest drifted",
    )
    return name, public_key, signature, message, context


def validate_corpus(kind: str, path: Path, lock: dict[str, Any]) -> dict[str, object]:
    expected = lock["corpora"][kind]
    require(file_sha256(path) == expected["sha256"], f"{kind} corpus SHA-256 drifted")

    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{kind} corpus root must be an object")
    require(data.get("profile") == expected["profile"], f"{kind} profile drifted")
    require(data.get("draft_commit") == lock["draft_commit"], f"{kind} draft pin drifted")
    require(
        data.get("libshrincs_commit") == lock["libshrincs_commit"],
        f"{kind} libshrincs pin drifted",
    )

    vectors = data.get("vectors")
    require(isinstance(vectors, list), f"{kind} vectors must be a list")
    require(len(vectors) == expected["vector_count"], f"{kind} vector count drifted")

    names: set[str] = set()
    lengths: set[int] = set()
    for index, vector in enumerate(vectors):
        name, _public_key, signature, message, context = validate_vector_common(
            vector,
            kind,
            index,
        )
        require(name not in names, f"{kind} vector name repeated: {name}")
        names.add(name)
        require(len(message) <= 4096, f"{name} message exceeds verifier envelope")
        require(len(context) <= 255, f"{name} context exceeds verifier envelope")
        lengths.add(len(signature))

    require(
        sorted(lengths) == expected["signature_lengths"],
        f"{kind} signature-length coverage drifted",
    )
    return {
        "kind": kind,
        "sha256": expected["sha256"],
        "vectors": len(vectors),
        "signature_lengths": sorted(lengths),
    }


def validate_resource_corpus(path: Path, lock: dict[str, Any]) -> dict[str, object]:
    expected = lock["resource_vectors"]
    require(file_sha256(path) == expected["sha256"], "resource corpus SHA-256 drifted")

    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "resource corpus root must be an object")
    require(data.get("profile") == expected["profile"], "resource profile drifted")
    require(data.get("draft_commit") == lock["draft_commit"], "resource draft pin drifted")

    vectors = data.get("vectors")
    require(isinstance(vectors, list), "resource vectors must be a list")
    require(len(vectors) == expected["vector_count"], "resource vector count drifted")

    names: list[str] = []
    lengths: set[int] = set()
    for index, vector in enumerate(vectors):
        name, _public_key, signature, message, context = validate_vector_common(
            vector,
            "resource",
            index,
        )
        names.append(name)
        require(len(message) == expected["message_bytes"], f"{name} message length drifted")
        require(len(context) == expected["context_bytes"], f"{name} context length drifted")
        lengths.add(len(signature))

    require(names == expected["vector_names"], "resource vector-name coverage drifted")
    require(
        sorted(lengths) == expected["signature_lengths"],
        "resource signature-length coverage drifted",
    )
    return {
        "kind": "resource",
        "sha256": expected["sha256"],
        "vectors": len(vectors),
        "signature_lengths": sorted(lengths),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--stateful", type=Path)
    parser.add_argument("--stateless", type=Path)
    parser.add_argument("--resource", type=Path)
    parser.add_argument("--lock-only", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    lock = load_lock(args.lock)
    result: dict[str, Any] = {
        "lock_profile": lock["profile"],
        "result": "PASS",
    }
    if not args.lock_only:
        require(args.stateful is not None, "--stateful is required unless --lock-only is used")
        require(args.stateless is not None, "--stateless is required unless --lock-only is used")
        require(args.resource is not None, "--resource is required unless --lock-only is used")
        result["stateful"] = validate_corpus("stateful", args.stateful, lock)
        result["stateless"] = validate_corpus("stateless", args.stateless, lock)
        result["resource"] = validate_resource_corpus(args.resource, lock)

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
