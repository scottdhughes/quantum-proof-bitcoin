"""Differentially test an independent C stateless SHRINCS verifier."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"
VECTOR_PROFILE = "pqbtc-shrincs-current-draft-stateless-kat-v0"
MAX_CORPUS_BYTES = 64 * 1024


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
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


WOTSC_CHECKER = load_module(Path(__file__).with_name("check_libshrincs_wotsc.py"),
                            "pqbtc_stateless_source_checks")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        return WOTSC_CHECKER.load_manifest(path)
    except WOTSC_CHECKER.CompatibilityError as exc:
        raise StatelessOracleError(str(exc)) from exc


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
    status = verify(
            public_key_buffer,
            len(public_key),
            signature_buffer,
            len(signature),
            message_buffer,
            len(message),
            context_buffer,
            len(context),
        )
    require(status in (0, 1), f"native verifier returned invalid ABI status: {status}")
    return status == 1


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
    with path.open("rb") as stream:
        raw = stream.read(MAX_CORPUS_BYTES + 1)
    require(len(raw) <= MAX_CORPUS_BYTES, "retained vector corpus exceeds size limit")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise StatelessOracleError("invalid retained vector JSON") from exc
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
    validate_vectors(vectors)
    return vectors


def bytes_from_vector(vector: dict[str, Any], field: str) -> bytes:
    value = vector.get(field)
    require(isinstance(value, str), f"{vector.get('name')}.{field} must be hex")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise StatelessOracleError(f"{vector.get('name')}.{field} is invalid hex") from exc


def validate_vectors(vectors: Any) -> None:
    require(isinstance(vectors, list) and len(vectors) == 2, "stateless vector set drifted")
    definitions = (
        ("stateless_deterministic_empty_context", "deterministic",
         kdf(b"pqbtc-shrincs-stateless/message/0", 32), b"", None),
        ("stateless_fixed_randomizer_context", "fixed-randomizer",
         kdf(b"pqbtc-shrincs-stateless/message/1", 47),
         b"PQBTC/SHRINCS/stateless-recovery-v0",
         kdf(b"pqbtc-shrincs-stateless/opt-rand/1", 16).hex()),
    )
    keys = []
    for vector, (name, mode, message, context, randomizer) in zip(vectors, definitions):
        require(isinstance(vector, dict), "stateless vector must be an object")
        require(vector.get("name") == name, "stateless case identity/order drifted")
        require(vector.get("mode") == mode, f"{name}: mode drifted")
        require(vector.get("opt_rand") == randomizer, f"{name}: randomizer drifted")
        require(bytes_from_vector(vector, "message") == message, f"{name}: message drifted")
        require(bytes_from_vector(vector, "context") == context, f"{name}: context drifted")
        for field, size in (("public_key", 48), ("signature", 5776)):
            value = bytes_from_vector(vector, field)
            require(len(value) == size, f"{name}: {field} size drifted")
            require(vector.get(f"{field}_sha256") == hashlib.sha256(value).hexdigest(),
                    f"{name}: {field} hash differs from retained bytes")
        keys.append(bytes_from_vector(vector, "public_key"))
    require(keys[0] == keys[1], "stateless vectors must share the generated public key")


def exercise_native_abi_cases(verify, vector: dict[str, Any]) -> int:
    """Exercise pointer/length guards through the real ABI, including under sanitizers."""
    key = bytes_from_vector(vector, "public_key")
    signature = bytes_from_vector(vector, "signature")
    message = bytes_from_vector(vector, "message")
    context = bytes_from_vector(vector, "context")
    # Back even the deliberately oversized lengths with readable storage.
    key_buffer = c_buffer(key + b"\0")
    signature_buffer = c_buffer(signature + b"\0")
    message_buffer = c_buffer(message)
    context_buffer = c_buffer(context)
    oversized_message = c_buffer(bytes(4097))
    oversized_context = c_buffer(bytes(256))
    valid = (key_buffer, len(key), signature_buffer, len(signature),
             message_buffer, len(message), context_buffer, len(context))
    require(verify(*valid) == 1, "native ABI valid baseline rejected")
    cases = []
    for pointer in (0, 2):
        args = list(valid)
        args[pointer] = None
        cases.append(tuple(args))
    for length in (0, 47, 49):
        args = list(valid)
        args[1] = length
        cases.append(tuple(args))
    for length in (0, 554, 5775, 5777):
        args = list(valid)
        args[3] = length
        cases.append(tuple(args))
    for pointer in (4, 6):
        args = list(valid)
        args[pointer:pointer + 2] = (None, 1)
        cases.append(tuple(args))
    for pointer, buffer, size in ((4, oversized_message, 4097), (6, oversized_context, 256)):
        args = list(valid)
        args[pointer:pointer + 2] = (buffer, size)
        cases.append(tuple(args))
    for index, args in enumerate(cases):
        require(verify(*args) == 0, f"native ABI boundary case {index} did not reject with zero")
    return 1 + len(cases)


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
    try:
        WOTSC_CHECKER.validate_paths(manifest, libshrincs, shrincs_bip)
    except WOTSC_CHECKER.CompatibilityError as exc:
        raise StatelessOracleError(str(exc)) from exc


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
    validate_vectors(vectors)

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
    }
    expected = manifest["component_evidence"]["stateless_hypertree"]
    for field, manifest_field in (("cases", "kat_case_count"),
                                  ("valid_signatures", "valid_signatures_verified"),
                                  ("signature_bit_mutations_rejected", "signature_bit_mutations_rejected"),
                                  ("public_key_bit_mutations_rejected", "public_key_bit_mutations_rejected"),
                                  ("structural_negatives_rejected", "structural_negatives_rejected")):
        require(result[field] == expected[manifest_field],
                f"incomplete stateless campaign: {field}={result[field]}")
    result["native_abi_checks"] = exercise_native_abi_cases(verify, vectors[0])
    require(result["native_abi_checks"] == 14, "incomplete native ABI campaign")
    if args.vectors_out is not None:
        write_vectors(args.vectors_out, manifest, vectors)
    result["result"] = "PASS"
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
