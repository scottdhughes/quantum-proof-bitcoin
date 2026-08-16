"""Validate the strict combined SHRINCS verifier against committed KATs."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import time
from pathlib import Path
from types import ModuleType
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR_DIR = REPO_ROOT / "contrib" / "shrincs-ref" / "vectors"
MODE_INVALID = 0
MODE_STATEFUL = 1
MODE_STATELESS = 2
PUBLIC_KEY_BYTES = 48
STATEFUL_BASE_BYTES = 538
STATEFUL_MIN_BYTES = 554
STATEFUL_MAX_BYTES = 4618
STATEFUL_STEP_BYTES = 16
STATELESS_BYTES = 5776
MAX_TESTED_SIGNATURE_BYTES = 6000


class FullProfileError(ValueError):
    """Raised when the strict full-profile verifier violates its contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FullProfileError(message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def deterministic_bytes(label: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(label + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def decode_hex(value: object, field: str) -> bytes:
    require(isinstance(value, str), f"{field} must be hexadecimal")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise FullProfileError(f"{field} contains invalid hexadecimal data") from exc


def expected_mode(signature_len: int) -> int:
    if signature_len == STATELESS_BYTES:
        return MODE_STATELESS
    if not STATEFUL_MIN_BYTES <= signature_len <= STATEFUL_MAX_BYTES:
        return MODE_INVALID
    if (signature_len - STATEFUL_BASE_BYTES) % STATEFUL_STEP_BYTES != 0:
        return MODE_INVALID
    return MODE_STATEFUL


class Verifier:
    def __init__(self, path: Path):
        self.library = ctypes.CDLL(str(path.resolve()))
        self.verify = self.library.pqbtc_shrincs_verify
        self.verify.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        self.verify.restype = ctypes.c_int

        self.mode = self.library.pqbtc_shrincs_signature_mode
        self.mode.argtypes = [ctypes.c_size_t]
        self.mode.restype = ctypes.c_uint32

        self.reset = self.library.pqbtc_sha256_metrics_reset
        self.reset.argtypes = []
        self.reset.restype = None

        self.calls = self.library.pqbtc_sha256_metrics_calls
        self.calls.argtypes = []
        self.calls.restype = ctypes.c_uint64

        self.compressions = self.library.pqbtc_sha256_metrics_compressions
        self.compressions.argtypes = []
        self.compressions.restype = ctypes.c_uint64

    @staticmethod
    def buffer(data: bytes):
        if not data:
            return None
        return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)

    def run(
        self,
        public_key: bytes,
        signature: bytes,
        message: bytes,
        context: bytes,
    ) -> dict[str, int | bool]:
        public_key_buffer = self.buffer(public_key)
        signature_buffer = self.buffer(signature)
        message_buffer = self.buffer(message)
        context_buffer = self.buffer(context)
        self.reset()
        started = time.perf_counter_ns()
        accepted = (
            self.verify(
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
        duration_ns = time.perf_counter_ns() - started
        return {
            "accepted": accepted,
            "sha256_calls": int(self.calls()),
            "sha256_compressions": int(self.compressions()),
            "duration_ns": duration_ns,
        }


def vector_bytes(vector: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    name = str(vector.get("name", "unnamed"))
    return (
        decode_hex(vector.get("public_key"), f"{name}.public_key"),
        decode_hex(vector.get("signature"), f"{name}.signature"),
        decode_hex(vector.get("message"), f"{name}.message"),
        decode_hex(vector.get("context"), f"{name}.context"),
    )


def validate_valid_vectors(
    verifier: Verifier,
    corpora: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for corpus_name in ("stateful", "stateless"):
        expected = MODE_STATEFUL if corpus_name == "stateful" else MODE_STATELESS
        for vector in corpora[corpus_name]["vectors"]:
            public_key, signature, message, context = vector_bytes(vector)
            require(verifier.mode(len(signature)) == expected, f"{vector['name']}: mode classification drifted")
            metrics = verifier.run(public_key, signature, message, context)
            require(metrics["accepted"] is True, f"{vector['name']}: full verifier rejected a committed KAT")
            require(metrics["sha256_calls"] > 0, f"{vector['name']}: valid verification did no hash work")
            require(
                metrics["sha256_compressions"] >= metrics["sha256_calls"],
                f"{vector['name']}: compression accounting is inconsistent",
            )
            records.append(
                {
                    "name": vector["name"],
                    "mode": corpus_name,
                    "signature_bytes": len(signature),
                    **metrics,
                }
            )
    return records


def validate_length_contract(verifier: Verifier) -> dict[str, int]:
    public_key = deterministic_bytes(b"pqbtc/full-profile/length/pk", PUBLIC_KEY_BYTES)
    message = deterministic_bytes(b"pqbtc/full-profile/length/message", 32)
    context = b"length-contract"
    invalid = 0
    stateful = 0
    stateless = 0
    shaped_rejections = 0

    for signature_len in range(MAX_TESTED_SIGNATURE_BYTES + 1):
        expected = expected_mode(signature_len)
        actual = int(verifier.mode(signature_len))
        require(actual == expected, f"signature length {signature_len}: mode classification drifted")

        signature = deterministic_bytes(
            b"pqbtc/full-profile/length/signature/" + signature_len.to_bytes(2, "big"),
            signature_len,
        )
        metrics = verifier.run(public_key, signature, message, context)
        if expected == MODE_INVALID:
            invalid += 1
            require(metrics["accepted"] is False, f"invalid signature length {signature_len} was accepted")
            require(metrics["sha256_calls"] == 0, f"invalid signature length {signature_len} performed hash work")
            require(
                metrics["sha256_compressions"] == 0,
                f"invalid signature length {signature_len} performed compression work",
            )
        else:
            shaped_rejections += 1
            require(metrics["accepted"] is False, f"random canonical-shaped signature {signature_len} was accepted")
            require(metrics["sha256_calls"] > 0, f"canonical-shaped signature {signature_len} did no hash work")
            if expected == MODE_STATEFUL:
                stateful += 1
            else:
                stateless += 1

    require(stateful == 255, "canonical stateful length count drifted")
    require(stateless == 1, "canonical stateless length count drifted")
    require(invalid + shaped_rejections == MAX_TESTED_SIGNATURE_BYTES + 1, "length accounting drifted")
    return {
        "tested_lengths": MAX_TESTED_SIGNATURE_BYTES + 1,
        "invalid_lengths": invalid,
        "canonical_stateful_lengths": stateful,
        "canonical_stateless_lengths": stateless,
        "canonical_random_rejections": shaped_rejections,
    }


def validate_public_key_lengths(
    verifier: Verifier,
    vector: dict[str, Any],
) -> dict[str, int]:
    public_key, signature, message, context = vector_bytes(vector)
    tested = 0
    for public_key_len in range(65):
        if public_key_len == PUBLIC_KEY_BYTES:
            continue
        candidate = deterministic_bytes(
            b"pqbtc/full-profile/public-key-length/" + public_key_len.to_bytes(1, "big"),
            public_key_len,
        )
        metrics = verifier.run(candidate, signature, message, context)
        require(metrics["accepted"] is False, f"public-key length {public_key_len} was accepted")
        require(metrics["sha256_calls"] == 0, f"public-key length {public_key_len} performed hash work")
        require(metrics["sha256_compressions"] == 0, f"public-key length {public_key_len} performed compression work")
        tested += 1
    require(len(public_key) == PUBLIC_KEY_BYTES, "committed public-key size drifted")
    return {"tested_invalid_public_key_lengths": tested}


def validate_binding_and_mode_confusion(
    verifier: Verifier,
    corpora: dict[str, dict[str, Any]],
) -> dict[str, int]:
    stateful_vector = corpora["stateful"]["vectors"][0]
    stateless_vector = corpora["stateless"]["vectors"][0]
    stateful_pk, stateful_sig, stateful_message, stateful_context = vector_bytes(stateful_vector)
    stateless_pk, stateless_sig, stateless_message, stateless_context = vector_bytes(stateless_vector)
    rejected = 0

    cases = [
        (
            "stateful-padded-to-stateless",
            stateful_pk,
            stateful_sig + bytes(STATELESS_BYTES - len(stateful_sig)),
            stateful_message,
            stateful_context,
        ),
        (
            "stateless-truncated-to-stateful",
            stateless_pk,
            stateless_sig[:STATEFUL_MIN_BYTES],
            stateless_message,
            stateless_context,
        ),
        (
            "stateful-wrong-message",
            stateful_pk,
            stateful_sig,
            bytes([stateful_message[0] ^ 1]) + stateful_message[1:],
            stateful_context,
        ),
        (
            "stateless-wrong-context",
            stateless_pk,
            stateless_sig,
            stateless_message,
            stateless_context + b"\x00",
        ),
        (
            "stateful-overlong-context",
            stateful_pk,
            stateful_sig,
            stateful_message,
            bytes(256),
        ),
        (
            "stateless-overlong-message",
            stateless_pk,
            stateless_sig,
            bytes(4097),
            stateless_context,
        ),
    ]
    for label, public_key, signature, message, context in cases:
        metrics = verifier.run(public_key, signature, message, context)
        require(metrics["accepted"] is False, f"mode/binding case {label} was accepted")
        rejected += 1

    legacy_lengths = {
        "schnorr": 64,
        "ecdsa-max": 73,
        "ml-dsa-44": 2420,
        "held-rc2": 4480,
    }
    for label, signature_len in legacy_lengths.items():
        require(expected_mode(signature_len) == MODE_INVALID, f"{label} unexpectedly has a canonical SHRINCS length")
        signature = deterministic_bytes(label.encode(), signature_len)
        metrics = verifier.run(stateful_pk, signature, stateful_message, stateful_context)
        require(metrics["accepted"] is False, f"{label} payload was accepted")
        require(metrics["sha256_calls"] == 0, f"{label} payload reached a cryptographic backend")
        rejected += 1
    return {"mode_and_binding_cases_rejected": rejected}


def summarize_metrics(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for mode in ("stateful", "stateless"):
        selected = [record for record in records if record["mode"] == mode]
        require(selected, f"no {mode} metric records")
        summary[mode] = {
            "vectors": len(selected),
            "sha256_calls_min": min(int(record["sha256_calls"]) for record in selected),
            "sha256_calls_max": max(int(record["sha256_calls"]) for record in selected),
            "sha256_compressions_min": min(int(record["sha256_compressions"]) for record in selected),
            "sha256_compressions_max": max(int(record["sha256_compressions"]) for record in selected),
            "duration_ns_min": min(int(record["duration_ns"]) for record in selected),
            "duration_ns_max": max(int(record["duration_ns"]) for record in selected),
        }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--vector-dir", type=Path, default=DEFAULT_VECTOR_DIR)
    parser.add_argument("--report-out", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    kat_loader = load_module(
        REPO_ROOT / "contrib" / "shrincs-ref" / "kat_loader.py",
        "pqbtc_full_profile_kat_loader",
    )
    kat_manifest = kat_loader.load_manifest(args.vector_dir / "manifest.json")
    corpora: dict[str, dict[str, Any]] = {}
    kat_records: dict[str, dict[str, Any]] = {}
    for name in ("stateful", "stateless"):
        raw, data = kat_loader.load_corpus(name, args.vector_dir, kat_manifest)
        corpora[name] = data
        kat_records[name] = {
            "json_bytes": len(raw),
            "json_sha256": hashlib.sha256(raw).hexdigest(),
            "vectors": len(data["vectors"]),
        }

    verifier = Verifier(args.library)
    valid_records = validate_valid_vectors(verifier, corpora)
    report: dict[str, Any] = {
        "profile": kat_manifest["profile"],
        "draft_commit": kat_manifest["draft_commit"],
        "libshrincs_commit": kat_manifest["libshrincs_commit"],
        "kats": kat_records,
        "valid_vectors": valid_records,
        "metrics": summarize_metrics(valid_records),
        "length_contract": validate_length_contract(verifier),
        "public_key_contract": validate_public_key_lengths(
            verifier,
            corpora["stateful"]["vectors"][0],
        ),
        "negative_contract": validate_binding_and_mode_confusion(verifier, corpora),
        "result": "PASS",
    }

    if args.report_out is not None:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            "SHRINCS full-profile verifier: PASS "
            f"(vectors={len(valid_records)}, lengths={report['length_contract']['tested_lengths']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
