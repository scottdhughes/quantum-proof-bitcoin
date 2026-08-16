"""Differentially test an independent C stateless SHRINCS verifier."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"
VECTOR_PROFILE = "pqbtc-shrincs-current-draft-stateless-kat-v0"


class StatelessOracleError(ValueError):
    """Raised when the independent stateless verifier disagrees with the draft."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StatelessOracleError(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "manifest root must be an object")
    return data


def git_head(path: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def kdf(label: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(label + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def load_verifier(path: Path):
    library = ctypes.CDLL(str(path.resolve()))
    verify = library.pqbtc_shrincs_stateless_verify
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


def verify_with_c(verify, public_key: bytes, signature: bytes, message: bytes, context: bytes) -> bool:
    public_key_buffer = c_buffer(public_key)
    signature_buffer = c_buffer(signature)
    message_buffer = c_buffer(message)
    context_buffer = c_buffer(context)
    return (
        verify(
            public_key_buffer,
            len(public_key),
            signature_buffer,
            len(signature),
            message_buffer,
            len(message),
            context_buffer,
            len(context),
        )
        == 1
    )


def create_vectors(reference: ModuleType) -> list[dict[str, Any]]:
    seed = kdf(b"pqbtc-shrincs-stateless/seed", 48)
    structure = bytes([reference.FXMSS_SHAPE_UNBALANCED, 0])
    secret_key, public_key = reference.shrincs_keygen(seed, structure)

    definitions = (
        {
            "name": "stateless_deterministic_empty_context",
            "message": kdf(b"pqbtc-shrincs-stateless/message/0", 32),
            "context": b"",
            "opt_rand": None,
        },
        {
            "name": "stateless_fixed_randomizer_context",
            "message": kdf(b"pqbtc-shrincs-stateless/message/1", 47),
            "context": b"PQBTC/SHRINCS/stateless-recovery-v0",
            "opt_rand": kdf(b"pqbtc-shrincs-stateless/opt-rand/1", 16),
        },
    )

    vectors: list[dict[str, Any]] = []
    for definition in definitions:
        name = definition["name"]
        message = definition["message"]
        context = definition["context"]
        opt_rand = definition["opt_rand"]
        signature = reference.shrincs_sign(message, context, secret_key, None, opt_rand)
        require(signature is not None, f"{name}: reference stateless signing failed")
        require(len(signature) == reference.SPHX_SIGNATURE_SIZE, f"{name}: signature size drifted")
        require(
            reference.shrincs_verify(message, signature, context, public_key),
            f"{name}: reference rejected its own stateless signature",
        )
        vectors.append(
            {
                "name": name,
                "mode": "deterministic" if opt_rand is None else "fixed-randomizer",
                "opt_rand": None if opt_rand is None else opt_rand.hex(),
                "message": message.hex(),
                "context": context.hex(),
                "public_key": public_key.hex(),
                "signature": signature.hex(),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
            }
        )
    return vectors


def write_vectors(path: Path, manifest: dict[str, Any], vectors: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "profile": VECTOR_PROFILE,
                "draft_commit": manifest["upstream"]["draft_specification"]["commit"],
                "libshrincs_commit": manifest["upstream"]["libshrincs_wotsc"]["commit"],
                "vectors": vectors,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_vectors(path: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "vector corpus root must be an object")
    require(data.get("profile") == VECTOR_PROFILE, "vector profile drifted")
    require(
        data.get("draft_commit") == manifest["upstream"]["draft_specification"]["commit"],
        "vector draft pin drifted",
    )
    require(
        data.get("libshrincs_commit") == manifest["upstream"]["libshrincs_wotsc"]["commit"],
        "vector libshrincs pin drifted",
    )
    vectors = data.get("vectors")
    require(isinstance(vectors, list) and len(vectors) == 2, "stateless vector set drifted")
    return vectors


def bytes_from_vector(vector: dict[str, Any], field: str) -> bytes:
    value = vector.get(field)
    require(isinstance(value, str), f"{vector.get('name')}.{field} must be hex")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise StatelessOracleError(f"{vector.get('name')}.{field} is invalid hex") from exc


def require_rejects(verify, vector: dict[str, Any], public_key: bytes, signature: bytes, message: bytes, context: bytes, label: str) -> None:
    require(
        not verify_with_c(verify, public_key, signature, message, context),
        f"{vector['name']}: independent verifier accepted {label}",
    )


def selected_signature_offsets(signature_len: int) -> list[int]:
    offsets = {
        0,
        15,
        16,
        16 + 1120,
        16 + 2239,
        2256,
        2256 + 703,
        2256 + 704,
        2256 + 2 * 704,
        2256 + 3 * 704,
        2256 + 4 * 704,
        signature_len - 1,
    }
    require(all(0 <= offset < signature_len for offset in offsets), "selected mutation offset is invalid")
    require(len(offsets) == 12, "selected mutation offset set drifted")
    return sorted(offsets)


def exercise_negative_cases(verify, vector: dict[str, Any], exhaustive: bool) -> tuple[int, int, int]:
    public_key = bytes_from_vector(vector, "public_key")
    signature = bytes_from_vector(vector, "signature")
    message = bytes_from_vector(vector, "message")
    context = bytes_from_vector(vector, "context")

    require_rejects(verify, vector, public_key[:-1], signature, message, context, "short public key")
    require_rejects(verify, vector, public_key + b"\x00", signature, message, context, "long public key")
    require_rejects(verify, vector, public_key, signature[:-1], message, context, "truncated signature")
    require_rejects(verify, vector, public_key, signature + b"\x00", message, context, "extended signature")

    wrong_message = bytearray(message)
    wrong_message[0] ^= 1
    require_rejects(verify, vector, public_key, signature, bytes(wrong_message), context, "wrong message")
    wrong_context = context + b"\x00" if context else b"wrong-context"
    require_rejects(verify, vector, public_key, signature, message, wrong_context, "wrong context")

    signature_mutations = 0
    offsets = range(len(signature)) if exhaustive else selected_signature_offsets(len(signature))
    for offset in offsets:
        for bit in range(8):
            mutated = bytearray(signature)
            mutated[offset] ^= 1 << bit
            require_rejects(
                verify,
                vector,
                public_key,
                bytes(mutated),
                message,
                context,
                f"signature bit mutation offset={offset} bit={bit}",
            )
            signature_mutations += 1

    public_key_mutations = 0
    if exhaustive:
        for offset in range(len(public_key)):
            for bit in range(8):
                mutated = bytearray(public_key)
                mutated[offset] ^= 1 << bit
                require_rejects(
                    verify,
                    vector,
                    bytes(mutated),
                    signature,
                    message,
                    context,
                    f"public-key bit mutation offset={offset} bit={bit}",
                )
                public_key_mutations += 1

    return signature_mutations, public_key_mutations, 6


def validate_pins(manifest: dict[str, Any], shrincs_bip: Path, libshrincs: Path) -> None:
    upstream = manifest.get("upstream")
    require(isinstance(upstream, dict), "manifest upstream object is missing")
    draft = upstream.get("draft_specification")
    lib = upstream.get("libshrincs_wotsc")
    require(isinstance(draft, dict), "draft specification pin is missing")
    require(isinstance(lib, dict), "libshrincs pin is missing")
    require(git_head(shrincs_bip) == draft.get("commit"), "shrincs-bip checkout does not match manifest")
    require(git_head(libshrincs) == lib.get("commit"), "libshrincs checkout does not match manifest")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--shrincs-bip", type=Path, required=True)
    parser.add_argument("--libshrincs", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--vectors-in", type=Path)
    parser.add_argument("--vectors-out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    require(not (args.vectors_in and args.vectors_out), "use only one of --vectors-in and --vectors-out")
    manifest = load_manifest(args.manifest)
    validate_pins(manifest, args.shrincs_bip, args.libshrincs)
    verify = load_verifier(args.library)

    if args.vectors_in is not None:
        vectors = read_vectors(args.vectors_in, manifest)
    else:
        reference = load_module(args.shrincs_bip / "impl" / "shrincs.py", "pqbtc_stateless_reference")
        vectors = create_vectors(reference)
        if args.vectors_out is not None:
            write_vectors(args.vectors_out, manifest, vectors)

    signature_mutations = 0
    public_key_mutations = 0
    structural_negatives = 0
    for index, vector in enumerate(vectors):
        public_key = bytes_from_vector(vector, "public_key")
        signature = bytes_from_vector(vector, "signature")
        message = bytes_from_vector(vector, "message")
        context = bytes_from_vector(vector, "context")
        require(len(public_key) == 48, f"{vector['name']}: public-key size drifted")
        require(len(signature) == 5776, f"{vector['name']}: signature size drifted")
        require(
            verify_with_c(verify, public_key, signature, message, context),
            f"{vector['name']}: independent C verifier rejected a valid reference signature",
        )
        sig_count, pk_count, structural_count = exercise_negative_cases(
            verify,
            vector,
            exhaustive=index == 0,
        )
        signature_mutations += sig_count
        public_key_mutations += pk_count
        structural_negatives += structural_count

    result = {
        "cases": len(vectors),
        "valid_signatures": len(vectors),
        "signature_bit_mutations_rejected": signature_mutations,
        "public_key_bit_mutations_rejected": public_key_mutations,
        "structural_negatives_rejected": structural_negatives,
        "result": "PASS",
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "stateless SHRINCS differential verifier: PASS "
            f"(cases={len(vectors)}, signature_bit_mutations={signature_mutations}, "
            f"public_key_bit_mutations={public_key_mutations})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
