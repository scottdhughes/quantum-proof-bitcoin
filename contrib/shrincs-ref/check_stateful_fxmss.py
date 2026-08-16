"""Differentially test an independent C stateful SHRINCS/FXMSS verifier."""

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


class StatefulOracleError(ValueError):
    """Raised when the independent stateful verifier disagrees with the draft."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StatefulOracleError(message)


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
    verify = library.pqbtc_shrincs_stateful_verify
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
    result = verify(
        public_key_buffer,
        len(public_key),
        signature_buffer,
        len(signature),
        message_buffer,
        len(message),
        context_buffer,
        len(context),
    )
    return result == 1


def vector_definitions(reference: ModuleType):
    return (
        {
            "name": "uxmss_depth4_state0",
            "structure": bytes([reference.FXMSS_SHAPE_UNBALANCED, 4]),
            "state": 0,
            "context": b"",
        },
        {
            "name": "uxmss_depth4_state1",
            "structure": bytes([reference.FXMSS_SHAPE_UNBALANCED, 4]),
            "state": 1,
            "context": b"PQBTC/SHRINCS/stateful-v0",
        },
        {
            "name": "uxmss_depth4_state3",
            "structure": bytes([reference.FXMSS_SHAPE_UNBALANCED, 4]),
            "state": 3,
            "context": b"context-3",
        },
        {
            "name": "uxmss_depth4_state4",
            "structure": bytes([reference.FXMSS_SHAPE_UNBALANCED, 4]),
            "state": 4,
            "context": b"terminal-leaf",
        },
        {
            "name": "bxmss_depth3_state0",
            "structure": bytes([reference.FXMSS_SHAPE_BALANCED, 3]),
            "state": 0,
            "context": b"",
        },
        {
            "name": "bxmss_depth3_state3",
            "structure": bytes([reference.FXMSS_SHAPE_BALANCED, 3]),
            "state": 3,
            "context": b"balanced-middle",
        },
        {
            "name": "bxmss_depth3_state7",
            "structure": bytes([reference.FXMSS_SHAPE_BALANCED, 3]),
            "state": 7,
            "context": b"balanced-final",
        },
    )


def create_vectors(reference: ModuleType) -> list[dict[str, Any]]:
    key_cache: dict[bytes, tuple[bytes, bytes]] = {}
    vectors: list[dict[str, Any]] = []

    for definition in vector_definitions(reference):
        name = definition["name"]
        structure = definition["structure"]
        state = definition["state"]
        context = definition["context"]
        cache_key = structure

        if cache_key not in key_cache:
            label = b"pqbtc-shrincs-stateful/" + structure.hex().encode()
            seed = kdf(label + b"/seed", 48)
            sk_seed = seed[0:16]
            sk_prf = seed[16:32]
            pk_seed = seed[32:48]
            stateless_root = kdf(label + b"/synthetic-stateless-root", 16)
            stateful_root = reference.fxmss_node(
                sk_seed,
                0,
                reference.FXMSS_HEIGHT,
                pk_seed,
                structure,
                bytearray(22),
            )
            secret_key = sk_seed + sk_prf + pk_seed + stateless_root + structure + stateful_root
            public_key = pk_seed + stateless_root + stateful_root
            key_cache[cache_key] = (secret_key, public_key)

        secret_key, public_key = key_cache[cache_key]
        message = kdf(b"pqbtc-shrincs-stateful/message/" + name.encode(), 32)
        position = reference.shrincs_sf_leaf_select(structure, state)
        require(position is not None, f"{name}: reference selected no stateful leaf")
        leaf_index, leaf_height = position
        leaf_depth = reference.FXMSS_HEIGHT - leaf_height

        signature = reference.shrincs_sign(message, context, secret_key, state, None)
        require(signature is not None, f"{name}: reference signing failed")
        require(
            reference.shrincs_verify(message, signature, context, public_key),
            f"{name}: reference rejected its own signature",
        )

        vectors.append(
            {
                "name": name,
                "structure": structure.hex(),
                "state": state,
                "leaf_index": leaf_index,
                "leaf_depth": leaf_depth,
                "message": message.hex(),
                "context": context.hex(),
                "public_key": public_key.hex(),
                "signature": signature.hex(),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "signature_sha256": hashlib.sha256(signature).hexdigest(),
            }
        )

    return vectors


def bytes_from_vector(vector: dict[str, Any], field: str) -> bytes:
    value = vector[field]
    require(isinstance(value, str), f"{vector['name']}.{field} must be hex")
    return bytes.fromhex(value)


def require_rejects(verify, vector: dict[str, Any], public_key: bytes, signature: bytes, message: bytes, context: bytes, label: str) -> None:
    require(
        not verify_with_c(verify, public_key, signature, message, context),
        f"{vector['name']}: independent verifier accepted {label}",
    )


def exercise_negative_cases(verify, vector: dict[str, Any]) -> tuple[int, int, int]:
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
    for offset in range(len(signature)):
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
    parser.add_argument("--vectors-out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    validate_pins(manifest, args.shrincs_bip, args.libshrincs)
    reference = load_module(args.shrincs_bip / "impl" / "shrincs.py", "pqbtc_stateful_reference")
    verify = load_verifier(args.library)
    vectors = create_vectors(reference)

    signature_mutations = 0
    public_key_mutations = 0
    structural_negatives = 0
    for vector in vectors:
        public_key = bytes_from_vector(vector, "public_key")
        signature = bytes_from_vector(vector, "signature")
        message = bytes_from_vector(vector, "message")
        context = bytes_from_vector(vector, "context")
        require(
            verify_with_c(verify, public_key, signature, message, context),
            f"{vector['name']}: independent C verifier rejected a valid reference signature",
        )
        sig_count, pk_count, structural_count = exercise_negative_cases(verify, vector)
        signature_mutations += sig_count
        public_key_mutations += pk_count
        structural_negatives += structural_count

    if args.vectors_out is not None:
        args.vectors_out.parent.mkdir(parents=True, exist_ok=True)
        args.vectors_out.write_text(
            json.dumps(
                {
                    "profile": "pqbtc-shrincs-current-draft-stateful-kat-v0",
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
            "stateful SHRINCS differential verifier: PASS "
            f"(cases={len(vectors)}, signature_bit_mutations={signature_mutations}, "
            f"public_key_bit_mutations={public_key_mutations})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
