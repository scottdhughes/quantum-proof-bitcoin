"""Measure and enforce the pinned SHRINCS verifier resource envelope."""

from __future__ import annotations

import argparse
import ctypes
import json
import statistics
import time
from pathlib import Path
from typing import Any

import resource_model


class ResourceError(ValueError):
    """Raised when measured verifier behavior exceeds the analytical envelope."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ResourceError(message)


def decode_hex(value: Any, field: str) -> bytes:
    require(isinstance(value, str), f"{field} must be hex text")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ResourceError(f"{field} contains invalid hex") from exc


def load_vectors(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path} root must be an object")
    vectors = data.get("vectors")
    require(isinstance(vectors, list) and vectors, f"{path} must contain vectors")
    return vectors


def c_buffer(data: bytes):
    if not data:
        return None
    return (ctypes.c_uint8 * len(data)).from_buffer_copy(data)


class InstrumentedVerifier:
    def __init__(self, path: Path):
        library = ctypes.CDLL(str(path.resolve()))
        self.verify = library.pqbtc_shrincs_verify
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

        self.reset_sha = library.pqbtc_shrincs_resource_reset_sha256
        self.reset_sha.argtypes = []
        self.reset_sha.restype = None
        self.sha_calls = library.pqbtc_shrincs_resource_sha256_calls
        self.sha_calls.argtypes = []
        self.sha_calls.restype = ctypes.c_uint64
        self.sha_compressions = library.pqbtc_shrincs_resource_sha256_compressions
        self.sha_compressions.argtypes = []
        self.sha_compressions.restype = ctypes.c_uint64

        self.reset_alloc = library.pqbtc_shrincs_resource_reset_allocations
        self.reset_alloc.argtypes = []
        self.reset_alloc.restype = None
        self.malloc_calls = library.pqbtc_shrincs_resource_malloc_calls
        self.malloc_calls.argtypes = []
        self.malloc_calls.restype = ctypes.c_uint64
        self.free_calls = library.pqbtc_shrincs_resource_free_calls
        self.free_calls.argtypes = []
        self.free_calls.restype = ctypes.c_uint64
        self.malloc_bytes = library.pqbtc_shrincs_resource_malloc_bytes
        self.malloc_bytes.argtypes = []
        self.malloc_bytes.restype = ctypes.c_uint64
        self.max_malloc = library.pqbtc_shrincs_resource_max_malloc_request
        self.max_malloc.argtypes = []
        self.max_malloc.restype = ctypes.c_size_t

    def call(
        self,
        public_key: bytes,
        signature: bytes,
        message: bytes,
        context: bytes,
    ) -> dict[str, int | bool]:
        self.reset_sha()
        self.reset_alloc()
        result = self.verify(
            c_buffer(public_key),
            len(public_key),
            c_buffer(signature),
            len(signature),
            c_buffer(message),
            len(message),
            c_buffer(context),
            len(context),
        )
        return {
            "valid": result == 1,
            "sha256_calls": int(self.sha_calls()),
            "sha256_compressions": int(self.sha_compressions()),
            "malloc_calls": int(self.malloc_calls()),
            "free_calls": int(self.free_calls()),
            "malloc_bytes": int(self.malloc_bytes()),
            "max_malloc_request": int(self.max_malloc()),
        }


def unpack(vector: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes]:
    name = str(vector.get("name", "unnamed"))
    return (
        decode_hex(vector.get("public_key"), f"{name}.public_key"),
        decode_hex(vector.get("signature"), f"{name}.signature"),
        decode_hex(vector.get("message"), f"{name}.message"),
        decode_hex(vector.get("context"), f"{name}.context"),
    )


def time_verification(
    verifier: InstrumentedVerifier,
    values: tuple[bytes, bytes, bytes, bytes],
    iterations: int,
) -> dict[str, int]:
    samples: list[int] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        metrics = verifier.call(*values)
        elapsed = time.perf_counter_ns() - start
        require(bool(metrics["valid"]), "timed valid vector was rejected")
        samples.append(elapsed)
    return {
        "iterations": iterations,
        "median_ns": int(statistics.median(samples)),
        "maximum_ns": max(samples),
    }


def validate_valid_vector(
    verifier: InstrumentedVerifier,
    vector: dict[str, Any],
    iterations: int,
) -> dict[str, Any]:
    name = str(vector.get("name", "unnamed"))
    public_key, signature, message, context = unpack(vector)
    metrics = verifier.call(public_key, signature, message, context)
    require(bool(metrics["valid"]), f"valid vector rejected: {name}")
    require(metrics["malloc_calls"] == 1, f"{name}: expected exactly one bounded allocation")
    require(metrics["free_calls"] == 1, f"{name}: allocation was not paired with one free")

    if len(signature) == resource_model.STATELESS_SIGNATURE_BYTES:
        mode = "stateless"
        envelope = resource_model.stateless_compression_envelope(len(message), len(context))
        require(
            envelope.minimum <= metrics["sha256_compressions"] <= envelope.maximum,
            f"{name}: stateless compression count outside analytical envelope",
        )
        expected_allocation = 66 + len(context) + len(message)
        analytical: dict[str, int] = {
            "minimum_compressions": envelope.minimum,
            "maximum_compressions": envelope.maximum,
        }
    else:
        mode = "stateful"
        depth = resource_model.stateful_signature_depth(len(signature))
        exact = resource_model.stateful_compressions(len(message), len(context), depth)
        require(
            metrics["sha256_compressions"] == exact,
            f"{name}: stateful compression count disagrees with exact model",
        )
        expected_allocation = 75 + len(context) + len(message)
        analytical = {"exact_compressions": exact, "depth": depth}

    require(metrics["malloc_bytes"] == expected_allocation, f"{name}: allocation-byte count drifted")
    require(
        metrics["max_malloc_request"] == expected_allocation,
        f"{name}: maximum allocation request drifted",
    )

    return {
        "name": name,
        "mode": mode,
        "signature_bytes": len(signature),
        "message_bytes": len(message),
        "context_bytes": len(context),
        "measured": metrics,
        "analytical": analytical,
        "timing": time_verification(
            verifier,
            (public_key, signature, message, context),
            iterations,
        ),
    }


def validate_early_rejections(
    verifier: InstrumentedVerifier,
    vector: dict[str, Any],
) -> list[dict[str, Any]]:
    public_key, signature, message, context = unpack(vector)
    cases = {
        "public_key_empty": (b"", signature, message, context),
        "public_key_47": (public_key[:-1], signature, message, context),
        "public_key_49": (public_key + b"\x00", signature, message, context),
        "signature_empty": (public_key, b"", message, context),
        "signature_553": (public_key, bytes(553), message, context),
        "signature_555": (public_key, bytes(555), message, context),
        "signature_4619": (public_key, bytes(4619), message, context),
        "signature_5775": (public_key, bytes(5775), message, context),
        "signature_5777": (public_key, bytes(5777), message, context),
        "message_4097": (public_key, signature, bytes(4097), context),
        "context_256": (public_key, signature, message, bytes(256)),
    }
    results: list[dict[str, Any]] = []
    for name, values in cases.items():
        metrics = verifier.call(*values)
        require(not bool(metrics["valid"]), f"early-rejection case accepted: {name}")
        require(metrics["sha256_calls"] == 0, f"{name}: parser performed SHA-256 work")
        require(metrics["sha256_compressions"] == 0, f"{name}: parser performed compression work")
        require(metrics["malloc_calls"] == 0, f"{name}: parser allocated memory")
        require(metrics["free_calls"] == 0, f"{name}: parser freed memory unexpectedly")
        results.append({"name": name, "measured": metrics})
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--stateful-kats", type=Path, required=True)
    parser.add_argument("--stateless-kats", type=Path, required=True)
    parser.add_argument("--resource-vectors", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    require(args.iterations >= 1, "iterations must be positive")

    verifier = InstrumentedVerifier(args.library)
    stateful = load_vectors(args.stateful_kats)
    stateless = load_vectors(args.stateless_kats)
    resource = load_vectors(args.resource_vectors)

    observations = [
        validate_valid_vector(verifier, vector, args.iterations)
        for vector in stateful + stateless + resource
    ]
    by_name = {entry["name"]: entry for entry in observations}
    stateful_max = by_name.get("stateful_max_depth_message_context")
    require(stateful_max is not None, "maximum-depth stateful resource vector missing")
    require(
        stateful_max["measured"]["sha256_compressions"]
        == resource_model.stateful_global_maximum(),
        "maximum-depth stateful vector did not attain the global stateful bound",
    )

    early = validate_early_rejections(verifier, stateful[0])
    result: dict[str, Any] = {
        "result": "PASS",
        "model": resource_model.model_summary(),
        "valid_observations": observations,
        "early_rejections": early,
        "valid_vector_count": len(observations),
        "early_rejection_count": len(early),
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        summary = {
            "result": "PASS",
            "valid_vector_count": len(observations),
            "early_rejection_count": len(early),
            "stateful_global_maximum_compressions": resource_model.stateful_global_maximum(),
            "stateless_global_maximum_compressions": resource_model.stateless_global_maximum(),
        }
        print(json.dumps(summary, sort_keys=True))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
