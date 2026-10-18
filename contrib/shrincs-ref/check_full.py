"""Exercise the strict dual-mode SHRINCS verifier against retained vectors."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

PUBLIC_KEY_BYTES = 48
STATEFUL_MIN = 554
STATEFUL_MAX = 4618
STATELESS_BYTES = 5776
MAX_CORPUS_BYTES = 64 * 1024
DEFAULT_MANIFEST = Path(__file__).resolve().parents[2] / "contrib/shrincs/manifest.json"

# Independently reproduced deterministic retained bytes at the frozen upstream pins.
# These identity locks are evidence commitments, not a cryptographic-security claim.
_UNBALANCED_KEY = "8280aff03f7871cb7730cfa263c7bfb9c5d37b4520fc67c2043b7343e5829433"
_BALANCED_KEY = "b76c947077dcb9936da88efac9b3b0250a9d64a5bbf796417a36060f8c9a0f9d"
_STATELESS_KEY = "9d12ad91a235b729e9246a7dc0a9b3b6b42d2178e987949e333f6a8c431eafa3"
FROZEN_VECTOR_HASHES = {
    "uxmss_depth4_state0": (_UNBALANCED_KEY, "ba6102dc63d3cb5a3e46416a96cf3bbf5658058e917a30252f18b6d8f1190f73"),
    "uxmss_depth4_state1": (_UNBALANCED_KEY, "38e72efa1f408626dd7975226dde1a11f1815a905e2fc852dd652e62098a1ba2"),
    "uxmss_depth4_state3": (_UNBALANCED_KEY, "1be2c5ba49ab46266ade1136e6a79ca1345ad4c2220b35c178b3c71240e7cce7"),
    "uxmss_depth4_state4": (_UNBALANCED_KEY, "4103a0731fb927b0bf54fcd61bf55ab1f9ee617b2deb74eeb26699049fe6ed5b"),
    "bxmss_depth3_state0": (_BALANCED_KEY, "bd4e4ded566ecf36055fa393616bb58be8ab449b15603c6523e6e3c0ad48f9c6"),
    "bxmss_depth3_state3": (_BALANCED_KEY, "56572714dce4fec395a64744620b91132c1d53911dbf2af6d0b42bce7320544d"),
    "bxmss_depth3_state7": (_BALANCED_KEY, "dce7d81ce385e8d87f90083367131bdcaee26925c9641940ce31808c753556ec"),
    "stateless_deterministic_empty_context": (_STATELESS_KEY, "f9f6f4ee342d83a5cf858ef307c34d67fd8cc7db932aa561fdbb3df5b03b2819"),
    "stateless_fixed_randomizer_context": (_STATELESS_KEY, "aef848f6daed79c84607e0a9489a2c0a4c2b4ff96f3a9293a4f6e9c4b6b622c0"),
}


def load_module(filename: str, name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load project checker: {path}")
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
    return module


# These are project-owned checkers, not upstream reference implementations.
STATEFUL_CHECKER = load_module("check_stateful_fxmss.py", "pqbtc_full_stateful")
STATELESS_CHECKER = load_module("check_stateless.py", "pqbtc_full_stateless")


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


def validate_vectors(vectors: Any, mode: str) -> None:
    require(isinstance(vectors, list) and vectors, "corpus must contain vectors")
    if mode == "stateless":
        try:
            STATELESS_CHECKER.validate_vectors(vectors)
        except STATELESS_CHECKER.StatelessOracleError as exc:
            raise FullVerifierError(str(exc)) from exc
        validate_frozen_identity(vectors)
        return
    require(mode == "stateful", "unknown corpus mode")
    require(len(vectors) == 7, "stateful vector set drifted")
    definitions = STATEFUL_CHECKER.vector_definitions(
        SimpleNamespace(FXMSS_SHAPE_UNBALANCED=0, FXMSS_SHAPE_BALANCED=1))
    keys: dict[str, bytes] = {}
    for vector, definition, (index, depth) in zip(
            vectors, definitions, ((1, 1), (1, 2), (1, 4), (0, 4), (0, 3), (3, 3), (7, 3))):
        require(isinstance(vector, dict), "stateful vector must be an object")
        name = definition["name"]
        require(vector.get("name") == name, "stateful case identity/order drifted")
        structure = definition["structure"].hex()
        require(vector.get("structure") == structure, f"{name}: structure drifted")
        for field, expected in (("state", definition["state"]), ("leaf_index", index), ("leaf_depth", depth)):
            require(type(vector.get(field)) is int and vector[field] == expected, f"{name}: {field} drifted")
        key, signature, message, context = unpack(vector)
        require(message == STATEFUL_CHECKER.kdf(b"pqbtc-shrincs-stateful/message/" + name.encode(), 32),
                f"{name}: message drifted")
        require(context == definition["context"], f"{name}: context drifted")
        require(len(signature) == 538 + 16 * depth, f"{name}: signature length drifted")
        require(int.from_bytes(signature[16:24], "big") == index, f"{name}: serialized index drifted")
        for field, value in (("public_key", key), ("signature", signature)):
            require(vector.get(f"{field}_sha256") == hashlib.sha256(value).hexdigest(),
                    f"{name}: {field} hash differs from retained bytes")
        require(structure not in keys or keys[structure] == key, f"{name}: shared public key drifted")
        keys[structure] = key
    validate_frozen_identity(vectors)


def validate_frozen_identity(vectors: list[dict[str, Any]]) -> None:
    for vector in vectors:
        observed = (vector["public_key_sha256"], vector["signature_sha256"])
        require(observed == FROZEN_VECTOR_HASHES.get(vector["name"]),
                f"{vector['name']}: frozen retained-vector identity drifted")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        return STATELESS_CHECKER.load_manifest(path)
    except STATELESS_CHECKER.StatelessOracleError as exc:
        raise FullVerifierError(str(exc)) from exc


def read_corpus(path: Path, mode: str | None = None,
                manifest: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    manifest = load_manifest(DEFAULT_MANIFEST) if manifest is None else manifest
    with path.open("rb") as stream:
        raw = stream.read(MAX_CORPUS_BYTES + 1)
    require(len(raw) <= MAX_CORPUS_BYTES, "retained corpus exceeds size limit")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise FullVerifierError("invalid retained corpus JSON") from exc
    require(isinstance(data, dict), f"{path} root must be an object")
    vectors = data.get("vectors")
    require(isinstance(vectors, list) and vectors, f"{path} must contain vectors")
    profiles = {f"pqbtc-shrincs-current-draft-{kind}-kat-v0": kind for kind in ("stateful", "stateless")}
    kind = profiles.get(data.get("profile"))
    require(kind is not None and (mode is None or kind == mode), "corpus profile/mode drifted")
    for field, component in (("draft_commit", "draft_specification"), ("libshrincs_commit", "libshrincs_wotsc")):
        require(data.get(field) == manifest["upstream"][component]["commit"], f"corpus {field} drifted")
    validate_vectors(vectors, kind)
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
    status = verify(
            c_buffer(public_key),
            len(public_key),
            c_buffer(signature),
            len(signature),
            c_buffer(message),
            len(message),
            c_buffer(context),
            len(context),
        )
    require(status in (0, 1), f"native verifier returned invalid ABI status: {status}")
    return status == 1


def unpack(vector: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    public_key = decode_hex(vector.get("public_key"), "public_key")
    signature = decode_hex(vector.get("signature"), "signature")
    message = decode_hex(vector.get("message"), "message")
    context = decode_hex(vector.get("context"), "context")
    require(len(public_key) == PUBLIC_KEY_BYTES, "public-key length drifted")
    return public_key, signature, message, context


def run(verify, stateful_vectors: list[dict[str, Any]], stateless_vectors: list[dict[str, Any]]) -> dict[str, int | str]:
    validate_vectors(stateful_vectors, "stateful")
    validate_vectors(stateless_vectors, "stateless")
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

    for vector in stateful_vectors + stateless_vectors:
        key, signature, message, context = unpack(vector)
        for field, data in enumerate((key, signature, message, context)):
            changed = bytes([data[0] ^ 1]) + data[1:] if data else b"\0"
            args = [key, signature, message, context]
            args[field] = changed
            require(not call_verify(verify, *args), f"binding mutation accepted: {vector['name']} field={field}")
            strict_negatives += 1

    native_abi_checks = sum(exercise_native_abi_cases(verify, vectors[0])
                            for vectors in (stateful_vectors, stateless_vectors))
    require((valid_stateful, valid_stateless, strict_negatives, native_abi_checks) == (7, 2, 60, 28),
            "incomplete full-verifier campaign")
    return {
        "valid_stateful": valid_stateful,
        "valid_stateless": valid_stateless,
        "strict_negatives": strict_negatives,
        "native_abi_checks": native_abi_checks,
        "result": "PASS",
    }


def exercise_native_abi_cases(verify, vector: dict[str, Any]) -> int:
    checker = STATELESS_CHECKER if len(unpack(vector)[1]) == STATELESS_BYTES else STATEFUL_CHECKER
    try:
        return checker.exercise_native_abi_cases(verify, vector)
    except (STATEFUL_CHECKER.StatefulOracleError, STATELESS_CHECKER.StatelessOracleError) as exc:
        raise FullVerifierError(str(exc)) from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--stateful-vectors", type=Path, required=True)
    parser.add_argument("--stateless-vectors", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    stateful = read_corpus(args.stateful_vectors, "stateful", manifest)
    stateless = read_corpus(args.stateless_vectors, "stateless", manifest)
    result = run(load_verifier(args.library), stateful, stateless)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
