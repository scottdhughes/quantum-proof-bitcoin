"""Load and authenticate the committed full-profile SHRINCS KAT corpora."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR_DIR = REPO_ROOT / "contrib" / "shrincs-ref" / "vectors"
DEFAULT_MANIFEST = DEFAULT_VECTOR_DIR / "manifest.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
EXPECTED_PROFILE = "pqbtc-shrincs-current-draft-full-kat-v0"
EXPECTED_DRAFT_COMMIT = "acc6bda51dc3b94848d118967247ad0f3cd7a80e"
EXPECTED_LIBSHRINCS_COMMIT = "53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5"
EXPECTED_CORPORA = {"stateful", "stateless"}


class KatError(ValueError):
    """Raised when committed KAT data violates its authenticated contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise KatError(message)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_hex(value: object, field: str) -> bytes:
    require(isinstance(value, str), f"{field} must be a hexadecimal string")
    require(len(value) % 2 == 0, f"{field} has odd-length hexadecimal data")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise KatError(f"{field} contains invalid hexadecimal data") from exc


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KatError(f"cannot load KAT manifest {path}") from exc

    require(isinstance(data, dict), "KAT manifest root must be an object")
    require(data.get("schema_version") == 1, "KAT schema_version must remain 1")
    require(data.get("profile") == EXPECTED_PROFILE, "full KAT profile drifted")
    require(data.get("draft_commit") == EXPECTED_DRAFT_COMMIT, "KAT draft pin drifted")
    require(
        data.get("libshrincs_commit") == EXPECTED_LIBSHRINCS_COMMIT,
        "KAT libshrincs pin drifted",
    )
    require(
        bool(COMMIT_RE.fullmatch(str(data.get("draft_commit", "")))),
        "KAT draft commit is malformed",
    )
    require(
        bool(COMMIT_RE.fullmatch(str(data.get("libshrincs_commit", "")))),
        "KAT libshrincs commit is malformed",
    )

    corpora = data.get("corpora")
    require(isinstance(corpora, dict), "KAT corpora must be an object")
    require(set(corpora) == EXPECTED_CORPORA, "KAT corpus set drifted")
    for name, entry in corpora.items():
        require(isinstance(entry, dict), f"KAT corpus {name} must be an object")
        parts = entry.get("parts")
        require(isinstance(parts, list) and parts, f"KAT corpus {name} has no parts")
        require(
            all(
                isinstance(part, str)
                and part
                and Path(part).name == part
                and part.startswith(f"{name}-vectors.json.gz.b64.part")
                for part in parts
            ),
            f"KAT corpus {name} has an unsafe or unexpected part name",
        )
        require(len(parts) == len(set(parts)), f"KAT corpus {name} repeats a part")
        require(parts == sorted(parts), f"KAT corpus {name} parts are not ordered")
        for field in ("base64_sha256", "gzip_sha256", "json_sha256"):
            require(
                bool(SHA256_RE.fullmatch(str(entry.get(field, "")))),
                f"KAT corpus {name}.{field} is malformed",
            )
        for field in ("base64_bytes", "gzip_bytes", "json_bytes", "vector_count"):
            require(
                isinstance(entry.get(field), int) and entry[field] > 0,
                f"KAT corpus {name}.{field} must be a positive integer",
            )
        require(
            isinstance(entry.get("profile"), str) and entry["profile"],
            f"KAT corpus {name}.profile is missing",
        )
    return data


def validate_vector(name: str, index: int, vector: object) -> None:
    require(isinstance(vector, dict), f"{name} vector {index} must be an object")
    prefix = f"{name} vector {index}"
    vector_name = vector.get("name")
    require(isinstance(vector_name, str) and vector_name, f"{prefix}.name is missing")

    public_key = decode_hex(vector.get("public_key"), f"{prefix}.public_key")
    signature = decode_hex(vector.get("signature"), f"{prefix}.signature")
    decode_hex(vector.get("message"), f"{prefix}.message")
    context = decode_hex(vector.get("context"), f"{prefix}.context")
    require(len(public_key) == 48, f"{prefix} public-key size drifted")
    require(len(context) <= 255, f"{prefix} context exceeds the draft limit")

    require(
        vector.get("public_key_sha256") == sha256_hex(public_key),
        f"{prefix} public-key digest drifted",
    )
    require(
        vector.get("signature_sha256") == sha256_hex(signature),
        f"{prefix} signature digest drifted",
    )

    if name == "stateful":
        require(554 <= len(signature) <= 4618, f"{prefix} stateful signature size drifted")
        require((len(signature) - 538) % 16 == 0, f"{prefix} stateful signature step drifted")
        leaf_depth = vector.get("leaf_depth")
        leaf_index = vector.get("leaf_index")
        state = vector.get("state")
        require(isinstance(leaf_depth, int) and 1 <= leaf_depth <= 255, f"{prefix}.leaf_depth is invalid")
        require(isinstance(leaf_index, int) and leaf_index >= 0, f"{prefix}.leaf_index is invalid")
        require(isinstance(state, int) and state >= 0, f"{prefix}.state is invalid")
        require(
            len(signature) == 538 + 16 * leaf_depth,
            f"{prefix} signature length does not encode leaf_depth",
        )
        structure = decode_hex(vector.get("structure"), f"{prefix}.structure")
        require(len(structure) == 2, f"{prefix}.structure size drifted")
    else:
        require(len(signature) == 5776, f"{prefix} stateless signature size drifted")
        mode = vector.get("mode")
        require(mode in {"deterministic", "fixed-randomizer"}, f"{prefix}.mode is invalid")
        opt_rand = vector.get("opt_rand")
        if mode == "deterministic":
            require(opt_rand is None, f"{prefix}.opt_rand must be null in deterministic mode")
        else:
            randomizer = decode_hex(opt_rand, f"{prefix}.opt_rand")
            require(len(randomizer) == 16, f"{prefix}.opt_rand size drifted")


def load_corpus(
    name: str,
    vector_dir: Path = DEFAULT_VECTOR_DIR,
    manifest: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    require(name in EXPECTED_CORPORA, f"unknown KAT corpus {name!r}")
    manifest_data = load_manifest(vector_dir / "manifest.json") if manifest is None else manifest
    corpora = manifest_data["corpora"]
    entry = corpora[name]

    encoded_parts: list[str] = []
    for part_name in entry["parts"]:
        part_path = vector_dir / part_name
        try:
            text = part_path.read_text(encoding="ascii")
        except OSError as exc:
            raise KatError(f"cannot read KAT part {part_path}") from exc
        canonical = "".join(text.split())
        require(canonical, f"KAT part {part_name} is empty")
        require(bool(BASE64_RE.fullmatch(canonical)), f"KAT part {part_name} is not canonical base64")
        encoded_parts.append(canonical)

    encoded = "".join(encoded_parts).encode("ascii")
    require(len(encoded) == entry["base64_bytes"], f"KAT corpus {name} base64 size drifted")
    require(sha256_hex(encoded) == entry["base64_sha256"], f"KAT corpus {name} base64 digest drifted")
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KatError(f"KAT corpus {name} base64 decoding failed") from exc

    require(len(compressed) == entry["gzip_bytes"], f"KAT corpus {name} gzip size drifted")
    require(sha256_hex(compressed) == entry["gzip_sha256"], f"KAT corpus {name} gzip digest drifted")
    try:
        raw = gzip.decompress(compressed)
    except (OSError, EOFError) as exc:
        raise KatError(f"KAT corpus {name} gzip decompression failed") from exc

    require(len(raw) == entry["json_bytes"], f"KAT corpus {name} JSON size drifted")
    require(sha256_hex(raw) == entry["json_sha256"], f"KAT corpus {name} JSON digest drifted")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KatError(f"KAT corpus {name} contains invalid JSON") from exc

    require(isinstance(data, dict), f"KAT corpus {name} root must be an object")
    require(data.get("profile") == entry["profile"], f"KAT corpus {name} profile drifted")
    require(data.get("draft_commit") == manifest_data["draft_commit"], f"KAT corpus {name} draft pin drifted")
    require(
        data.get("libshrincs_commit") == manifest_data["libshrincs_commit"],
        f"KAT corpus {name} libshrincs pin drifted",
    )
    vectors = data.get("vectors")
    require(isinstance(vectors, list), f"KAT corpus {name}.vectors must be an array")
    require(len(vectors) == entry["vector_count"], f"KAT corpus {name} vector count drifted")
    names: set[str] = set()
    for index, vector in enumerate(vectors):
        validate_vector(name, index, vector)
        vector_name = vector["name"]
        require(vector_name not in names, f"KAT corpus {name} repeats vector name {vector_name!r}")
        names.add(vector_name)
    return raw, data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector-dir", type=Path, default=DEFAULT_VECTOR_DIR)
    parser.add_argument("--extract-dir", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest(args.vector_dir / "manifest.json")
    result: dict[str, Any] = {
        "profile": manifest["profile"],
        "draft_commit": manifest["draft_commit"],
        "libshrincs_commit": manifest["libshrincs_commit"],
        "corpora": {},
        "result": "PASS",
    }
    for name in sorted(EXPECTED_CORPORA):
        raw, data = load_corpus(name, args.vector_dir, manifest)
        if args.extract_dir is not None:
            args.extract_dir.mkdir(parents=True, exist_ok=True)
            (args.extract_dir / f"{name}-vectors.json").write_bytes(raw)
        result["corpora"][name] = {
            "json_bytes": len(raw),
            "json_sha256": sha256_hex(raw),
            "vectors": len(data["vectors"]),
        }

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "SHRINCS full-profile KATs: PASS "
            f"(stateful={result['corpora']['stateful']['vectors']}, "
            f"stateless={result['corpora']['stateless']['vectors']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
