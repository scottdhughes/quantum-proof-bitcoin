#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Produce fail-closed direct-verifier resource observations.

The measured target is the isolated production-shaped
``pqbtc_mldsa44_verify_strict`` wrapper.  This lane is test-only: it does not
define a consensus, block-validation, activation, or production admission
limit.  Pull-request observations are never promotion evidence, and numeric
timing/RSS acceptance thresholds intentionally remain unset until a separate
review of trusted main observations.
"""

import argparse
import copy
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable

import run_verifier_fuzz as verifier
import run_wrapper_tests as wrapper


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
POLICY_PATH = HERE / "verifier_resource_policy.json"
PROBE_SOURCE = HERE / "pqbtc_mldsa44_resource_probe.c"
WRAPPER_HEADER = HERE / "pqbtc_mldsa44.h"
WRAPPER_TEST_HEADER = HERE / "pqbtc_mldsa44_test.h"
WRAPPER_CONFIG = HERE / "pqbtc_mldsa44_config.h"
UPSTREAM_SIGN = (
    HERE / "vendor" / "mldsa-native" / "mldsa" / "src" / "sign.c"
)
UPSTREAM_HEADER = (
    HERE / "vendor" / "mldsa-native" / "mldsa" / "mldsa_native.h"
)
RESOURCE_WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-resource-envelope.yml"
)
RESOURCE_TEST = REPO_ROOT / "ci" / "test" / "test_ml_dsa_resource_envelope.py"
BASELINE_POINTER = (
    REPO_ROOT / "contrib" / "ml-dsa-ref" / "review_baseline_commit.txt"
)

POLICY_SHA256 = "24813510a2fdd13e3496e2f24f557a89ff0bde408296839243346f978228bb9f"
GITHUB_REPOSITORY = "scottdhughes/quantum-proof-bitcoin"
GITHUB_REPOSITORY_ID = "1136579990"
GITHUB_WORKFLOW_NAME = "ML-DSA-44 verifier resource envelope"
GITHUB_WORKFLOW_PATH = ".github/workflows/ml-dsa-44-resource-envelope.yml"
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
HEX_16 = re.compile(r"[0-9a-f]{16}")
STACK_USAGE_LINE = re.compile(
    r"^(?P<source>.+?):(?P<line>[0-9]+):(?:(?P<column>[0-9]+):)?"
    r"(?P<symbol>[^\t]+)\t(?P<bytes>[0-9]+)\t(?P<qualifier>[^\t\r\n]+)$"
)

BUNDLE_MAGIC = b"PQRSC001"
BUNDLE_HEADER = struct.Struct("<8sII")
RECORD_HEADER = struct.Struct("<IiI")
FLAG_VALID = 0x01
FLAG_DEEP_REJECT = 0x02
FLAG_SAME_KEY = 0x04
FLAG_FIRST_CALL = 0x08
FLAG_MASK = FLAG_VALID | FLAG_DEEP_REJECT | FLAG_SAME_KEY | FLAG_FIRST_CALL

OWNER_FILE = "evidence-owner.txt"
OWNER_CONTENT = "pqbtc-ml-dsa-44-resource-envelope-v1\n"
PLAN_FILE = "resource-plan.json"
POLICY_FILE = "verifier-resource-policy.json"
BUNDLE_FILE = "verifier-corpus.bundle"
INVENTORY_FILE = "verifier-corpus-inventory.json"
OBSERVATION_FILE = "probe-observation.json"
PROBE_STDERR_FILE = "probe-stderr.log"
COMPILER_VERSION_FILE = "compiler-version.txt"
COMPILER_TARGET_FILE = "compiler-target.txt"
BUILD_COMMANDS_FILE = "build-commands.json"
HOST_FILE = "host-observation.json"
LIBRARY_FILE = "libpqbtc_mldsa44.so"
PROBE_FILE = "pqbtc_mldsa44-resource-probe"
WRAPPER_STACK_FILE = "wrapper-stack-usage.su"
PROBE_STACK_FILE = "probe-stack-usage.su"
STACK_REPORT_FILE = "stack-usage.json"
SYMBOLS_FILE = "production-symbols.txt"
LINKED_FILE = "linked-libraries.txt"
GIT_HEAD_FILE = "git-head.txt"
GIT_STATUS_FILE = "git-status.txt"
BASELINE_DIFF_FILE = "baseline-diff.txt"
CONTROLS_FILE = "detector-controls.json"
REPORT_FILE = "resource-envelope-report.json"
JOB_STATUS_FILE = "job-status.txt"
CHECKSUM_FILE = "SHA256SUMS"

SUCCESS_FILES = {
    OWNER_FILE,
    PLAN_FILE,
    POLICY_FILE,
    BUNDLE_FILE,
    INVENTORY_FILE,
    OBSERVATION_FILE,
    PROBE_STDERR_FILE,
    COMPILER_VERSION_FILE,
    COMPILER_TARGET_FILE,
    BUILD_COMMANDS_FILE,
    HOST_FILE,
    LIBRARY_FILE,
    PROBE_FILE,
    WRAPPER_STACK_FILE,
    PROBE_STACK_FILE,
    STACK_REPORT_FILE,
    SYMBOLS_FILE,
    LINKED_FILE,
    GIT_HEAD_FILE,
    GIT_STATUS_FILE,
    BASELINE_DIFF_FILE,
    CONTROLS_FILE,
    REPORT_FILE,
    JOB_STATUS_FILE,
    CHECKSUM_FILE,
}
FAILURE_REQUIRED_FILES = {
    OWNER_FILE,
    PLAN_FILE,
    POLICY_FILE,
    REPORT_FILE,
    JOB_STATUS_FILE,
    CHECKSUM_FILE,
}
MAX_EVIDENCE_FILES = 32
MAX_EVIDENCE_BYTES = 12 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 65536

RESULT_NAMES = {
    verifier.OK: "ok",
    verifier.ERR_INVALID_ARGUMENT: "invalid_argument",
    verifier.ERR_VERIFY: "verify_rejection",
}
OUTCOME_KEYS = ("ok", "invalid_argument", "verify_rejection")
EXPECTED_CORPUS_SUMMARY = {
    "total_cases": 245,
    "unique_frames": 240,
    "source_counts": {
        "project": 27,
        "wycheproof": 180,
        "promoted": 38,
    },
    "expected_counts": {
        "ok": 81,
        "invalid_argument": 36,
        "verify_rejection": 128,
    },
    "aggregate_sha256": (
        "6ee1368b01bfd758dd1c78a79bb7789769137f8d93055dfe9c4d040706597979"
    ),
}
FORBIDDEN_FLAG_CLAIMS = [
    "-march=native",
    "-flto",
    "-DPQBTC_MLDSA44_TESTING=1 (measured objects)",
    "-fsanitize",
]

GUARDED_PATHS = (
    ".github/workflows/ml-dsa-44-resource-envelope.yml",
    ".github/workflows/ml-dsa-44-review-reproduction.yml",
    "contrib/ml-dsa-engineering",
    "contrib/ml-dsa-ref/vectors.json",
    "ci/test/test_ml_dsa_resource_envelope.py",
    "ci/test/test_ml_dsa_wrapper_prototype.py",
)


class ResourceEnvelopeError(RuntimeError):
    """Raised when resource evidence cannot be trusted."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def fnv1a64_bytes(value: bytes) -> str:
    result = 14695981039346656037
    for byte in value:
        result ^= byte
        result = (result * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{result:016x}"


def canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ResourceEnvelopeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value):
    raise ResourceEnvelopeError(f"non-finite JSON value: {value}")


def _require_regular_file(
    path: Path, label: str, maximum: int, *, allow_empty: bool = False
) -> None:
    try:
        status = path.lstat()
    except OSError as exc:
        raise ResourceEnvelopeError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise ResourceEnvelopeError(f"{label} must be a regular non-symlink file")
    if status.st_size > maximum or (not allow_empty and status.st_size == 0):
        raise ResourceEnvelopeError(f"{label} size is outside the frozen bound")


def load_json_object(path: Path, label: str, maximum: int = MAX_JSON_BYTES) -> dict:
    _require_regular_file(path, label, maximum)
    try:
        value = json.loads(
            path.read_text(encoding="utf8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ResourceEnvelopeError(f"cannot parse {label}: {exc}") from exc
    if type(value) is not dict:
        raise ResourceEnvelopeError(f"{label} must contain one JSON object")
    return value


def _read_text_file(
    path: Path,
    label: str,
    *,
    encoding: str = "utf8",
    maximum: int = MAX_JSON_BYTES,
    allow_empty: bool = False,
) -> str:
    _require_regular_file(path, label, maximum, allow_empty=allow_empty)
    try:
        return path.read_text(encoding=encoding)
    except (OSError, UnicodeError) as exc:
        raise ResourceEnvelopeError(f"cannot read {label}: {exc}") from exc


def _require_exact_keys(value: object, keys: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != keys:
        actual = sorted(value) if type(value) is dict else type(value).__name__
        raise ResourceEnvelopeError(
            f"{label} fields differ: expected {sorted(keys)}, got {actual}"
        )
    return value


def _require_int(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ResourceEnvelopeError(f"{label} must be an integer >= {minimum}")
    return value


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ResourceEnvelopeError(f"{label} must be a boolean")
    return value


def _require_string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ResourceEnvelopeError(f"{label} must be a non-empty string")
    return value


def load_policy() -> dict:
    policy = load_json_object(POLICY_PATH, "resource policy", 16384)
    _require_exact_keys(
        policy,
        {
            "schema_version",
            "phase",
            "target",
            "profile",
            "batch",
            "enforced_limits",
            "acceptance_limits",
            "stack_evidence",
            "promotion",
            "scope",
        },
        "resource policy",
    )
    _require_int(policy["schema_version"], "resource policy schema")
    if policy["schema_version"] != 1:
        raise ResourceEnvelopeError("unsupported resource policy schema")
    if policy["phase"] != "TRUSTED_MAIN_OBSERVATION_REQUIRED":
        raise ResourceEnvelopeError("resource policy phase drifted")
    if policy["target"] != "pqbtc_mldsa44_verify_strict":
        raise ResourceEnvelopeError("resource policy target drifted")

    profile = _require_exact_keys(
        policy["profile"],
        {
            "system",
            "machine",
            "measurement_target",
            "backend",
            "optimization",
            "thread_model",
            "allocation_model",
        },
        "resource profile",
    )
    expected_profile = {
        "system": "Linux",
        "machine": "x86_64",
        "measurement_target": "isolated-production-shaped-direct-verifier",
        "backend": "mldsa-native-portable-c",
        "optimization": "-O2",
        "thread_model": "one guarded pthread",
        "allocation_model": "default upstream stack allocation",
    }
    if profile != expected_profile:
        raise ResourceEnvelopeError("resource profile drifted")

    batch = _require_exact_keys(
        policy["batch"],
        {
            "source",
            "unique_frames",
            "full_corpus_rounds",
            "prefix_frames",
            "verification_calls",
            "sample_count",
            "first_call_separate",
            "batches",
            "derivation",
            "capacity_basis",
            "capacity_scope",
            "required_accept_cases",
            "required_deep_reject_cases",
            "same_key_cases",
        },
        "resource batch",
    )
    expected_batches = [
        "mixed_rotating",
        "valid_rotating",
        "deep_reject_rotating",
        "same_key_mixed",
    ]
    if (
        batch["unique_frames"] != 240
        or batch["full_corpus_rounds"] != 17
        or batch["prefix_frames"] != 207
        or batch["verification_calls"] != 4287
        or batch["sample_count"] != 31
        or batch["first_call_separate"] is not True
        or batch["batches"] != expected_batches
        or batch["verification_calls"]
        != batch["full_corpus_rounds"] * batch["unique_frames"]
        + batch["prefix_frames"]
    ):
        raise ResourceEnvelopeError("resource batch arithmetic or sampling drifted")
    if batch["source"] != "SHA256-sorted unique verifier_fuzz_corpus.json frames":
        raise ResourceEnvelopeError("resource batch source drifted")
    if batch["capacity_scope"] != (
        "research workload only; not a transaction, block-validation, "
        "consensus, or activation limit"
    ):
        raise ResourceEnvelopeError("resource batch capacity scope drifted")
    expected_accepts = [
        "valid_empty_message_context",
        "valid_frozen_vector",
        "valid_max_context",
        "valid_max_fuzz_message",
    ]
    expected_deep_rejects = [
        "reject_context_flip",
        "reject_ctilde_bit_flip",
        "reject_hint_counter_backwards",
        "reject_hint_nonzero_padding",
        "reject_message_flip",
        "reject_public_key_rho_flip",
        "reject_public_key_t1_flip",
    ]
    if batch["required_accept_cases"] != expected_accepts:
        raise ResourceEnvelopeError("required accept taxonomy drifted")
    if batch["required_deep_reject_cases"] != expected_deep_rejects:
        raise ResourceEnvelopeError("required deep-reject taxonomy drifted")
    expected_same_key = [
        "reject_context_flip",
        "reject_ctilde_bit_flip",
        "reject_hint_counter_backwards",
        "reject_hint_nonzero_padding",
        "reject_message_flip",
        *expected_accepts,
    ]
    if batch["same_key_cases"] != expected_same_key:
        raise ResourceEnvelopeError("same-key taxonomy drifted")

    limits = _require_exact_keys(
        policy["enforced_limits"],
        {
            "thread_stack_bytes",
            "thread_guard_bytes",
            "address_space_bytes",
            "open_files",
            "output_file_bytes",
            "core_file_bytes",
            "project_heap_calls",
            "cpu_watchdog_seconds",
            "wall_watchdog_seconds",
        },
        "resource safety limits",
    )
    if limits != {
        "thread_stack_bytes": 131072,
        "thread_guard_bytes": 4096,
        "address_space_bytes": 268435456,
        "open_files": 64,
        "output_file_bytes": 65536,
        "core_file_bytes": 0,
        "project_heap_calls": 0,
        "cpu_watchdog_seconds": 120,
        "wall_watchdog_seconds": 180,
    }:
        raise ResourceEnvelopeError("resource safety limits drifted")

    acceptance = _require_exact_keys(
        policy["acceptance_limits"],
        {"cpu_seconds", "wall_seconds", "peak_rss_kib", "status"},
        "resource acceptance limits",
    )
    if acceptance != {
        "cpu_seconds": None,
        "wall_seconds": None,
        "peak_rss_kib": None,
        "status": "UNSET_PENDING_SEPARATE_REVIEW_OF_TRUSTED_MAIN_OBSERVATION",
    }:
        raise ResourceEnvelopeError(
            "numeric acceptance limits must remain unset in this tranche"
        )

    stack = _require_exact_keys(
        policy["stack_evidence"],
        {
            "upstream_mld_total_alloc_44_verify_bytes",
            "required_symbols",
            "require_static_stack_usage",
            "call_chain_claim",
        },
        "stack evidence policy",
    )
    if (
        stack["upstream_mld_total_alloc_44_verify_bytes"] != 24448
        or stack["required_symbols"]
        != ["pqbtc_mldsa44_upstream_verify", "pqbtc_mldsa44_verify_strict"]
        or stack["require_static_stack_usage"] is not True
        or "not summed into a formal call-chain bound"
        not in stack["call_chain_claim"]
    ):
        raise ResourceEnvelopeError("stack evidence policy drifted")

    promotion = _require_exact_keys(
        policy["promotion"],
        {
            "requires_trusted_main_push",
            "requires_both_compilers",
            "requires_separate_policy_change",
            "pull_request_evidence",
            "trusted_main_evidence",
            "timing_threshold_bootstrap_forbidden",
        },
        "resource promotion policy",
    )
    if promotion != {
        "requires_trusted_main_push": True,
        "requires_both_compilers": ["clang", "gcc"],
        "requires_separate_policy_change": True,
        "pull_request_evidence": "UNTRUSTED_PR_OBSERVATION",
        "trusted_main_evidence": "TRUSTED_MAIN_OBSERVATION",
        "timing_threshold_bootstrap_forbidden": True,
    }:
        raise ResourceEnvelopeError("resource promotion policy drifted")

    scope = _require_exact_keys(
        policy["scope"],
        {
            "isolated_test_only",
            "production_integration",
            "production_backend",
            "simd256_admitted",
            "release_hold",
            "release_hold_changed",
            "batch_limit_is_not_consensus_policy",
            "closes_issue",
        },
        "resource scope",
    )
    if scope != {
        "isolated_test_only": True,
        "production_integration": False,
        "production_backend": "NONE",
        "simd256_admitted": False,
        "release_hold": True,
        "release_hold_changed": False,
        "batch_limit_is_not_consensus_policy": True,
        "closes_issue": False,
    }:
        raise ResourceEnvelopeError("resource scope drifted")
    if sha256_file(POLICY_PATH) != POLICY_SHA256:
        raise ResourceEnvelopeError("resource policy byte-level hash drifted")
    return policy


def _plan_inputs() -> dict[str, str]:
    paths = {
        "policy": POLICY_PATH,
        "runner": Path(__file__).resolve(),
        "probe": PROBE_SOURCE,
        "wrapper_source": wrapper.WRAPPER_SOURCE,
        "wrapper_header": WRAPPER_HEADER,
        "wrapper_test_header": WRAPPER_TEST_HEADER,
        "wrapper_config": WRAPPER_CONFIG,
        "source_manifest": wrapper.SOURCE_MANIFEST,
        "fuzz_driver": Path(verifier.__file__).resolve(),
        "fuzz_manifest": verifier.CORPUS_MANIFEST,
        "vectors": wrapper.VECTORS,
        "wycheproof_source": verifier.WYCHEPROOF_SOURCE,
        "promoted_source": verifier.PROMOTED_SOURCE,
        "workflow": RESOURCE_WORKFLOW,
        "resource_test": RESOURCE_TEST,
    }
    for label, path in paths.items():
        _require_regular_file(path, f"plan input {label}", MAX_JSON_BYTES)
    return {label: sha256_file(path) for label, path in sorted(paths.items())}


def build_plan(policy: dict) -> dict:
    batch = policy["batch"]
    return {
        "schema_version": 1,
        "target": policy["target"],
        "host": {
            "system": policy["profile"]["system"],
            "machine": policy["profile"]["machine"],
        },
        "measurement": {
            "profile": policy["profile"]["measurement_target"],
            "batch_ids": batch["batches"],
            "sample_count": batch["sample_count"],
            "raw_sample_count": batch["sample_count"],
            "retain_raw_samples": True,
            "subtract_control_samples": False,
            "first_call_separate": batch["first_call_separate"],
            "wall_clock": "CLOCK_MONOTONIC",
            "cpu_clock": "CLOCK_THREAD_CPUTIME_ID",
            "control_loop": "reported separately and never subtracted",
            "numeric_acceptance": (
                "unset pending a separate review of trusted main observations"
            ),
        },
        "policy": copy.deepcopy(policy),
        "policy_sha256": sha256_file(POLICY_PATH),
        "inputs": _plan_inputs(),
    }


def _percentile(samples: list[int], percentile: int) -> int:
    ordered = sorted(samples)
    index = max(0, math.ceil(percentile * len(ordered) / 100) - 1)
    return ordered[index]


def summarize_samples(samples: list[int]) -> dict[str, int]:
    ordered = sorted(samples)
    return {
        "min": ordered[0],
        "median": ordered[len(ordered) // 2],
        "p95": _percentile(ordered, 95),
        "p99": _percentile(ordered, 99),
        "max": ordered[-1],
    }


def _validate_sample_array(
    value: object, label: str, count: int, *, allow_zero: bool
) -> list[int]:
    if type(value) is not list or len(value) != count:
        raise ResourceEnvelopeError(f"{label} must contain exactly {count} samples")
    minimum = 0 if allow_zero else 1
    for index, sample in enumerate(value):
        _require_int(sample, f"{label}[{index}]", minimum)
        if sample > 10**15:
            raise ResourceEnvelopeError(f"{label}[{index}] is implausibly large")
    return value


def validate_probe_observation(
    observation: dict,
    plan: dict,
    *,
    expected_input_fnv1a64: str | None = None,
) -> dict:
    policy = plan["policy"]
    batch_policy = policy["batch"]
    limits = policy["enforced_limits"]
    _require_exact_keys(
        observation,
        {
            "schema_version",
            "status",
            "records",
            "sample_count",
            "batch_calls",
            "completed_calls",
            "selection_counts",
            "first_call",
            "batches",
            "control",
            "heap_calls",
            "thread_stack_bytes",
            "thread_guard_bytes",
            "peak_rss_kib",
            "clock_resolution_ns",
            "input_fnv1a64_before",
            "input_fnv1a64_after",
            "result_accumulator",
        },
        "probe observation",
    )
    for field in (
        "schema_version",
        "records",
        "sample_count",
        "batch_calls",
        "completed_calls",
    ):
        _require_int(observation[field], f"probe observation {field}")
    if (
        observation["schema_version"] != 1
        or observation["status"] != "PASS"
        or observation["records"] != batch_policy["unique_frames"]
        or observation["sample_count"] != batch_policy["sample_count"]
        or observation["batch_calls"] != batch_policy["verification_calls"]
        or observation["completed_calls"]
        != 1 + len(batch_policy["batches"]) * batch_policy["verification_calls"]
    ):
        raise ResourceEnvelopeError("probe observation cardinality drifted")

    selections = _require_exact_keys(
        observation["selection_counts"],
        set(batch_policy["batches"]),
        "probe selection counts",
    )
    if selections["mixed_rotating"] != batch_policy["unique_frames"]:
        raise ResourceEnvelopeError("mixed batch does not select every unique frame")
    for batch_id, count in selections.items():
        if type(count) is not int or not 1 <= count <= batch_policy["unique_frames"]:
            raise ResourceEnvelopeError(f"invalid selection count for {batch_id}")

    first = _require_exact_keys(
        observation["first_call"],
        {"record", "result", "wall_ns", "cpu_ns"},
        "first-call observation",
    )
    _require_int(first["record"], "first-call record")
    _require_int(first["result"], "first-call result")
    if (
        not 0 <= first["record"] < batch_policy["unique_frames"]
        or first["result"] != verifier.OK
    ):
        raise ResourceEnvelopeError("first-call record/result drifted")
    _require_int(first["wall_ns"], "first-call wall time", 1)
    _require_int(first["cpu_ns"], "first-call CPU time", 1)

    batches = observation["batches"]
    if type(batches) is not list or len(batches) != len(batch_policy["batches"]):
        raise ResourceEnvelopeError("probe batch list cardinality drifted")
    summaries = {"first_call": {"wall_ns": first["wall_ns"], "cpu_ns": first["cpu_ns"]}}
    total_wall_ns = first["wall_ns"]
    total_cpu_ns = first["cpu_ns"]
    for index, (batch_id, batch) in enumerate(zip(batch_policy["batches"], batches)):
        _require_exact_keys(
            batch,
            {"id", "calls", "outcomes", "wall_samples_ns", "cpu_samples_ns"},
            f"probe batch {index}",
        )
        _require_int(batch["calls"], f"{batch_id} call count")
        if batch["id"] != batch_id or batch["calls"] != batch_policy["verification_calls"]:
            raise ResourceEnvelopeError(f"probe batch identity drifted at index {index}")
        outcomes = _require_exact_keys(
            batch["outcomes"], set(OUTCOME_KEYS), f"{batch_id} outcomes"
        )
        for name in OUTCOME_KEYS:
            _require_int(outcomes[name], f"{batch_id}.{name}")
        if sum(outcomes.values()) != batch["calls"]:
            raise ResourceEnvelopeError(f"{batch_id} outcome accounting differs")
        if batch_id == "valid_rotating" and outcomes != {
            "ok": batch["calls"],
            "invalid_argument": 0,
            "verify_rejection": 0,
        }:
            raise ResourceEnvelopeError("valid batch contains a non-accept outcome")
        if batch_id == "deep_reject_rotating" and outcomes != {
            "ok": 0,
            "invalid_argument": 0,
            "verify_rejection": batch["calls"],
        }:
            raise ResourceEnvelopeError("deep-reject batch outcome differs")
        if batch_id == "same_key_mixed" and (
            outcomes["invalid_argument"] != 0
            or outcomes["ok"] == 0
            or outcomes["verify_rejection"] == 0
        ):
            raise ResourceEnvelopeError("same-key mixed batch taxonomy differs")
        wall = _validate_sample_array(
            batch["wall_samples_ns"],
            f"{batch_id} wall samples",
            batch_policy["sample_count"],
            allow_zero=False,
        )
        cpu = _validate_sample_array(
            batch["cpu_samples_ns"],
            f"{batch_id} CPU samples",
            batch_policy["sample_count"],
            allow_zero=False,
        )
        total_wall_ns += sum(wall)
        total_cpu_ns += sum(cpu)
        summaries[batch_id] = {
            "wall_ns": summarize_samples(wall),
            "cpu_ns": summarize_samples(cpu),
            "outcomes": copy.deepcopy(outcomes),
        }

    control = _require_exact_keys(
        observation["control"],
        {"iterations", "wall_samples_ns", "cpu_samples_ns"},
        "probe control loop",
    )
    _require_int(control["iterations"], "control-loop iteration count")
    if control["iterations"] != batch_policy["verification_calls"]:
        raise ResourceEnvelopeError("control-loop iteration count drifted")
    control_wall = _validate_sample_array(
        control["wall_samples_ns"],
        "control wall samples",
        batch_policy["sample_count"],
        allow_zero=True,
    )
    control_cpu = _validate_sample_array(
        control["cpu_samples_ns"],
        "control CPU samples",
        batch_policy["sample_count"],
        allow_zero=True,
    )
    total_wall_ns += sum(control_wall)
    total_cpu_ns += sum(control_cpu)
    summaries["control"] = {
        "wall_ns": summarize_samples(control_wall),
        "cpu_ns": summarize_samples(control_cpu),
        "subtracted_from_verifier_samples": False,
    }

    heap = _require_exact_keys(
        observation["heap_calls"],
        {"malloc", "calloc", "realloc", "free", "aligned_alloc", "posix_memalign"},
        "probe heap counters",
    )
    for name, count in heap.items():
        _require_int(count, f"probe heap counter {name}")
        if count != limits["project_heap_calls"]:
            raise ResourceEnvelopeError(f"nonzero instrumented project heap calls: {name}")
    _require_int(observation["thread_stack_bytes"], "thread stack bytes", 1)
    _require_int(observation["thread_guard_bytes"], "thread guard bytes", 1)
    if (
        observation["thread_stack_bytes"] != limits["thread_stack_bytes"]
        or observation["thread_guard_bytes"] != limits["thread_guard_bytes"]
    ):
        raise ResourceEnvelopeError("guarded pthread configuration drifted")
    peak_rss_kib = _require_int(observation["peak_rss_kib"], "peak RSS", 1)
    if peak_rss_kib > limits["address_space_bytes"] // 1024:
        raise ResourceEnvelopeError("peak RSS is incompatible with the address-space cap")
    if total_wall_ns > limits["wall_watchdog_seconds"] * 1_000_000_000:
        raise ResourceEnvelopeError("reported wall time exceeds the enforced watchdog")
    if total_cpu_ns > limits["cpu_watchdog_seconds"] * 1_000_000_000:
        raise ResourceEnvelopeError("reported CPU time exceeds the enforced limit")

    resolution = _require_exact_keys(
        observation["clock_resolution_ns"],
        {"monotonic", "thread_cpu"},
        "clock resolution",
    )
    _require_int(resolution["monotonic"], "monotonic clock resolution", 1)
    _require_int(resolution["thread_cpu"], "thread CPU clock resolution", 1)
    before = observation["input_fnv1a64_before"]
    after = observation["input_fnv1a64_after"]
    if (
        type(before) is not str
        or type(after) is not str
        or HEX_16.fullmatch(before) is None
        or before != after
        or (
            expected_input_fnv1a64 is not None
            and before != expected_input_fnv1a64
        )
    ):
        raise ResourceEnvelopeError("input immutability hash differs")
    if type(observation["result_accumulator"]) is not int:
        raise ResourceEnvelopeError("result accumulator must be an integer")

    validated = copy.deepcopy(observation)
    validated["derived_summaries"] = summaries
    return validated


def parse_stack_usage(paths: Iterable[Path]) -> dict[str, dict[str, object]]:
    required = set(load_policy()["stack_evidence"]["required_symbols"])
    found: dict[str, dict[str, object]] = {}
    saw_file = False
    for raw_path in paths:
        path = Path(raw_path)
        _require_regular_file(path, "compiler stack-usage record", 1024 * 1024)
        saw_file = True
        try:
            lines = path.read_text(encoding="utf8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ResourceEnvelopeError(f"cannot read stack-usage record: {exc}") from exc
        if not lines:
            raise ResourceEnvelopeError(f"empty stack-usage record: {path.name}")
        for line in lines:
            match = STACK_USAGE_LINE.fullmatch(line)
            if match is None:
                raise ResourceEnvelopeError(
                    f"malformed compiler stack-usage row in {path.name}"
                )
            observed_symbol = match.group("symbol")
            canonical_symbol = None
            for required_symbol in required:
                if re.fullmatch(
                    re.escape(required_symbol)
                    + r"(?:\.(?:constprop|isra)(?:\.[0-9]+)?)?",
                    observed_symbol,
                ):
                    canonical_symbol = required_symbol
                    break
            if canonical_symbol is None:
                continue
            if canonical_symbol in found:
                raise ResourceEnvelopeError(
                    f"duplicate stack-usage symbol: {canonical_symbol}"
                )
            qualifier = match.group("qualifier")
            if qualifier != "static":
                raise ResourceEnvelopeError(
                    f"required stack-usage symbol is not static: {canonical_symbol}"
                )
            size = int(match.group("bytes"))
            if size <= 0:
                raise ResourceEnvelopeError(
                    "required stack-usage symbol has no static bytes: "
                    f"{canonical_symbol}"
                )
            found[canonical_symbol] = {
                "bytes": size,
                "qualifier": qualifier,
                "observed_symbol": observed_symbol,
                "source": (
                    f"{Path(match.group('source')).name}:{match.group('line')}"
                    + (
                        f":{match.group('column')}"
                        if match.group("column") is not None
                        else ""
                    )
                ),
            }
    if not saw_file:
        raise ResourceEnvelopeError("no compiler stack-usage records supplied")
    missing = sorted(required - set(found))
    if missing:
        raise ResourceEnvelopeError(f"missing stack-usage symbols: {missing}")
    return {key: found[key] for key in sorted(found)}


def _minimal_environment(extra_path: Path | None = None) -> dict[str, str]:
    path_parts = []
    if extra_path is not None:
        path_parts.append(str(extra_path))
    path_parts.extend(["/usr/local/bin", "/usr/bin", "/bin"])
    return {
        "PATH": ":".join(path_parts),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }


def _run_bounded(
    arguments: list[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 60,
    maximum: int = MAX_LOG_BYTES,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    if not arguments or any(type(value) is not str or not value for value in arguments):
        raise ResourceEnvelopeError("subprocess argv must be a non-empty string list")
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment or _minimal_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ResourceEnvelopeError(f"cannot complete {arguments[0]}: {exc}") from exc
    if len(completed.stdout) > maximum or len(completed.stderr) > maximum:
        raise ResourceEnvelopeError(f"{arguments[0]} output exceeded the frozen bound")
    return completed


def _require_command_success(
    arguments: list[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 60,
    environment: dict[str, str] | None = None,
) -> tuple[str, str]:
    completed = _run_bounded(
        arguments, cwd=cwd, timeout=timeout, environment=environment
    )
    stdout = completed.stdout.decode("utf8", errors="strict")
    stderr = completed.stderr.decode("utf8", errors="strict")
    if completed.returncode != 0:
        raise ResourceEnvelopeError(
            f"command exited {completed.returncode}: {arguments[0]}: "
            f"{stderr.strip() or stdout.strip()}"
        )
    return stdout, stderr


def _run_git(*arguments: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise ResourceEnvelopeError("Git is required")
    stdout, _ = _require_command_success(
        [str(Path(git).resolve()), "-C", str(REPO_ROOT), *arguments],
        timeout=30,
        environment=_minimal_environment(Path(git).resolve().parent),
    )
    return stdout


def _require_positive_decimal(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise ResourceEnvelopeError(f"{label} must be a positive decimal string")
    return value


def _local_ci_context() -> dict:
    return {
        "github_actions": False,
        "server_url": "",
        "api_url": "",
        "repository": "",
        "repository_id": "",
        "event_name": "local",
        "ref": "local",
        "ref_protected": False,
        "sha": "",
        "workflow": "",
        "workflow_ref": "",
        "workflow_sha": "",
        "run_id": "",
        "run_attempt": "",
        "run_number": "",
        "job": "",
        "head_ref": "",
        "base_ref": "",
        "expected_checkout_head": "",
    }


def _validate_github_context(context: dict, head: str) -> dict:
    _require_exact_keys(context, set(_local_ci_context()), "GitHub Actions context")
    if (
        context["github_actions"] is not True
        or context["server_url"] != "https://github.com"
        or context["api_url"] != "https://api.github.com"
        or context["repository"] != GITHUB_REPOSITORY
        or context["repository_id"] != GITHUB_REPOSITORY_ID
        or context["workflow"] != GITHUB_WORKFLOW_NAME
        or context["job"] != "observe"
    ):
        raise ResourceEnvelopeError("GitHub Actions identity differs")
    for field in (
        "event_name",
        "ref",
        "sha",
        "workflow_ref",
        "workflow_sha",
        "head_ref",
        "base_ref",
        "expected_checkout_head",
    ):
        if type(context[field]) is not str:
            raise ResourceEnvelopeError(f"GitHub Actions {field} must be a string")
    if type(context["ref_protected"]) is not bool:
        raise ResourceEnvelopeError("GitHub Actions ref protection must be boolean")
    for field in ("run_id", "run_attempt", "run_number"):
        _require_positive_decimal(context[field], f"GitHub Actions {field}")
    if (
        HEX_40.fullmatch(context["sha"]) is None
        or HEX_40.fullmatch(context["workflow_sha"]) is None
        or context["expected_checkout_head"] != head
    ):
        raise ResourceEnvelopeError("GitHub Actions commit identity differs")

    workflow_prefix = f"{GITHUB_REPOSITORY}/{GITHUB_WORKFLOW_PATH}@"
    if not context["workflow_ref"].startswith(workflow_prefix):
        raise ResourceEnvelopeError("GitHub Actions workflow ref differs")
    event_name = context["event_name"]
    ref = context["ref"]
    if event_name == "pull_request":
        if (
            re.fullmatch(r"refs/pull/[1-9][0-9]*/merge", ref) is None
            or not context["head_ref"]
            or context["base_ref"] != "main"
        ):
            raise ResourceEnvelopeError("pull-request context differs")
        workflow_source_ref = context["workflow_ref"][len(workflow_prefix) :]
        if workflow_source_ref not in {ref, "refs/heads/main"}:
            raise ResourceEnvelopeError("pull-request workflow source ref differs")
    elif event_name in {"push", "workflow_dispatch"}:
        if (
            re.fullmatch(r"refs/heads/[A-Za-z0-9._/-]+", ref) is None
            or context["head_ref"]
            or context["base_ref"]
            or context["sha"] != head
            or context["workflow_sha"] != head
            or context["workflow_ref"] != workflow_prefix + ref
        ):
            raise ResourceEnvelopeError("branch-run context differs")
        if event_name == "push" and ref != "refs/heads/main":
            raise ResourceEnvelopeError("resource push execution is restricted to main")
        if ref == "refs/heads/main" and context["ref_protected"] is not True:
            raise ResourceEnvelopeError("main resource observation requires a protected ref")
    else:
        raise ResourceEnvelopeError("unsupported GitHub Actions event")
    return context


def _ci_context_from_environment(head: str) -> dict:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if not event_name:
        if os.environ.get("GITHUB_ACTIONS", "") == "true":
            raise ResourceEnvelopeError("GitHub Actions event metadata is incomplete")
        return _local_ci_context()
    protected = os.environ.get("GITHUB_REF_PROTECTED", "")
    if protected not in {"true", "false"}:
        raise ResourceEnvelopeError("GitHub ref-protection metadata is incomplete")
    context = {
        "github_actions": os.environ.get("GITHUB_ACTIONS", "") == "true",
        "server_url": os.environ.get("GITHUB_SERVER_URL", ""),
        "api_url": os.environ.get("GITHUB_API_URL", ""),
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", ""),
        "event_name": event_name,
        "ref": os.environ.get("GITHUB_REF", ""),
        "ref_protected": protected == "true",
        "sha": os.environ.get("GITHUB_SHA", ""),
        "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER", ""),
        "job": os.environ.get("GITHUB_JOB", ""),
        "head_ref": os.environ.get("GITHUB_HEAD_REF", ""),
        "base_ref": os.environ.get("GITHUB_BASE_REF", ""),
        "expected_checkout_head": os.environ.get(
            "PQBTC_RESOURCE_EXPECTED_HEAD", ""
        ),
    }
    if os.environ.get("RUNNER_OS", "") != "Linux" or os.environ.get(
        "RUNNER_ARCH", ""
    ) != "X64":
        raise ResourceEnvelopeError("GitHub runner identity differs")
    return _validate_github_context(context, head)


def _classify_trust(
    context: dict, baseline_guard_matches: bool
) -> tuple[str, bool, str]:
    event_name = context["event_name"]
    ref = context["ref"]
    if event_name == "pull_request":
        return (
            "UNTRUSTED_PR_OBSERVATION",
            False,
            "pull-request code cannot produce trusted promotion evidence",
        )
    if ref == "refs/heads/main" and event_name == "push":
        if baseline_guard_matches:
            return (
                "TRUSTED_MAIN_OBSERVATION",
                True,
                "exact clean main head matches the separately advanced "
                "guarded review baseline",
            )
        return (
            "PENDING_BASELINE_OBSERVATION",
            False,
            "main observation predates a separate guarded baseline-pointer "
            "advance",
        )
    if event_name == "local":
        return (
            "LOCAL_OBSERVATION",
            False,
            "local observations are diagnostic only",
        )
    if event_name == "workflow_dispatch":
        return (
            "UNTRUSTED_MANUAL_OBSERVATION",
            False,
            "manual observations are diagnostic only; trusted evidence "
            "requires a protected main push",
        )
    raise ResourceEnvelopeError(
        "resource execution is restricted to pull requests or branch observations"
    )


def _build_trust(context: dict, baseline_guard_matches: bool) -> dict:
    label, trusted_observation, reason = _classify_trust(
        context, baseline_guard_matches
    )
    return {
        "label": label,
        "trusted_observation": trusted_observation,
        "promotion_eligible": False,
        "reason": reason,
        "ci": copy.deepcopy(context),
        "requires_external_workflow_provenance": True,
        "requires_companion_compilers": ["clang", "gcc"],
        "requires_separate_numeric_policy_change": True,
    }


def _require_first_parent_baseline(head: str, baseline: str) -> None:
    object_type = _run_git("cat-file", "-t", baseline).strip()
    if object_type != "commit":
        raise ResourceEnvelopeError("review baseline pointer is not a commit")
    git_command = shutil.which("git")
    if git_command is None:
        raise ResourceEnvelopeError("Git is required")
    git_path = Path(git_command).resolve()
    ancestry = _run_bounded(
        [
            str(git_path),
            "-C",
            str(REPO_ROOT),
            "merge-base",
            "--is-ancestor",
            baseline,
            head,
        ],
        timeout=30,
        environment=_minimal_environment(git_path.parent),
    )
    if ancestry.returncode != 0:
        raise ResourceEnvelopeError("review baseline is not an ancestor of HEAD")
    first_parent_distance_text = _run_git(
        "rev-list", "--first-parent", "--count", f"{baseline}..{head}"
    ).strip()
    if not first_parent_distance_text.isdigit():
        raise ResourceEnvelopeError("cannot determine review baseline distance")
    first_parent_distance = int(first_parent_distance_text)
    first_parent_commit = _run_git(
        "rev-parse", f"{head}~{first_parent_distance}"
    ).strip()
    if baseline == head or first_parent_commit != baseline:
        raise ResourceEnvelopeError(
            "review baseline is not an earlier first-parent commit"
        )


def _repository_and_trust(output_dir: Path) -> tuple[dict, dict]:
    shallow = _run_git("rev-parse", "--is-shallow-repository").strip()
    if shallow != "false":
        raise ResourceEnvelopeError("full Git history is required")
    head = _run_git("rev-parse", "HEAD").strip()
    if HEX_40.fullmatch(head) is None:
        raise ResourceEnvelopeError("Git HEAD is not a lowercase SHA-1")
    status_text = _run_git(
        "status", "--porcelain=v1", "--untracked-files=all"
    )
    if status_text:
        raise ResourceEnvelopeError("repository must be clean for resource execution")
    (output_dir / GIT_HEAD_FILE).write_text(head + "\n", encoding="utf8")
    (output_dir / GIT_STATUS_FILE).write_text(status_text, encoding="utf8")

    pointer_bytes = BASELINE_POINTER.read_bytes()
    if re.fullmatch(rb"[0-9a-f]{40}\n", pointer_bytes) is None:
        raise ResourceEnvelopeError("review baseline pointer is malformed")
    baseline = pointer_bytes[:-1].decode("ascii")
    _require_first_parent_baseline(head, baseline)
    diff_names = _run_git(
        "diff", "--name-only", baseline, head, "--", *GUARDED_PATHS
    )
    (output_dir / BASELINE_DIFF_FILE).write_text(diff_names, encoding="utf8")
    baseline_guard_matches = not bool(diff_names)

    ci_context = _ci_context_from_environment(head)

    repository = {
        "head": head,
        "clean": True,
        "full_history": True,
        "baseline_pointer": baseline,
        "baseline_guard_matches": baseline_guard_matches,
    }
    trust = _build_trust(ci_context, baseline_guard_matches)
    return repository, trust


def _validate_source_contract() -> dict:
    capsule = wrapper.validate_source_capsule()
    wycheproof = verifier.validate_wycheproof_source()
    promoted = verifier.validate_promoted_source()
    config = WRAPPER_CONFIG.read_text(encoding="utf8")
    for required in (
        "#define MLD_CONFIG_PARAMETER_SET 44",
        "#define MLD_CONFIG_NO_ASM",
        "#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static",
        "#define MLD_CONFIG_INTERNAL_API_QUALIFIER static",
    ):
        if config.count(required) != 1:
            raise ResourceEnvelopeError(f"wrapper configuration drifted: {required}")
    for forbidden in ("MLD_CONFIG_CUSTOM_ALLOC_FREE", "MLD_CONFIG_REDUCE_RAM"):
        if forbidden in config:
            raise ResourceEnvelopeError(
                f"default-stack verifier configuration drifted: {forbidden}"
            )
    header = UPSTREAM_HEADER.read_text(encoding="utf8")
    if header.count("#define MLD_TOTAL_ALLOC_44_VERIFY 24448") != 1:
        raise ResourceEnvelopeError("upstream verifier allocation constant drifted")
    sign_text = UPSTREAM_SIGN.read_text(encoding="utf8")
    start = sign_text.find("int mld_sign_verify_internal(")
    end = sign_text.find("\nint mld_sign_verify(", start)
    if start < 0 or end < 0:
        raise ResourceEnvelopeError("cannot isolate upstream verifier implementation")
    allocation_sites = re.findall(r"\bMLD_ALLOC\s*\(", sign_text[start:end])
    if len(allocation_sites) != 9:
        raise ResourceEnvelopeError("upstream verifier MLD_ALLOC site count drifted")
    return {
        "source_capsule_hash": capsule["capsule_hash"]["value"],
        "wycheproof_tests": wycheproof["numberOfTests"],
        "promoted_cases": len(promoted),
        "upstream_verify_mld_alloc_sites": len(allocation_sites),
        "upstream_verify_mld_alloc_bytes": 24448,
        "allocation_interpretation": (
            "accumulative upstream MLD_ALLOC scratch only; not total stack"
        ),
    }


def _compiler_path(compiler_name: str) -> Path:
    if compiler_name not in {"gcc", "clang"}:
        raise ResourceEnvelopeError("compiler must be exactly gcc or clang")
    compiler = shutil.which(compiler_name)
    if compiler is None:
        raise ResourceEnvelopeError(f"compiler is unavailable: {compiler_name}")
    resolved = Path(compiler).resolve()
    _require_regular_file(resolved, f"{compiler_name} executable", 100 * 1024 * 1024)
    return resolved


def _common_compile_flags(compiler: Path) -> list[str]:
    return [
        str(compiler),
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-function",
        "-Wno-unknown-pragmas",
        "-fvisibility=hidden",
        "-fno-lto",
        "-O2",
        f"-I{HERE}",
    ]


def _normalize_commands(commands: list[list[str]], build_dir: Path) -> dict:
    prefix = str(build_dir)
    normalized = []
    for command in commands:
        normalized.append(
            [
                argument.replace(prefix, "$BUILD_DIR")
                if argument.startswith(prefix)
                else argument
                for argument in command
            ]
        )
    return {
        "schema_version": 1,
        "shell_used": False,
        "commands": normalized,
        "forbidden_flags_absent": FORBIDDEN_FLAG_CLAIMS,
    }


def _expected_normalized_commands(compiler: str) -> list[list[str]]:
    common = _common_compile_flags(Path(compiler))
    wrapper_object = "$BUILD_DIR/wrapper.o"
    probe_object = "$BUILD_DIR/probe.o"
    return [
        common
        + [
            "-fPIC",
            "-shared",
            str(wrapper.WRAPPER_SOURCE),
            "-o",
            f"$BUILD_DIR/{LIBRARY_FILE}",
        ],
        common
        + [
            "-fPIC",
            "-shared",
            "-DPQBTC_MLDSA44_TESTING=1",
            str(wrapper.WRAPPER_SOURCE),
            "-o",
            "$BUILD_DIR/libpqbtc_mldsa44_test.so",
        ],
        common
        + [
            "-fstack-usage",
            "-c",
            str(wrapper.WRAPPER_SOURCE),
            "-o",
            wrapper_object,
        ],
        common
        + [
            "-fstack-usage",
            "-fno-builtin-malloc",
            "-fno-builtin-calloc",
            "-fno-builtin-realloc",
            "-fno-builtin-free",
            "-fno-builtin-aligned_alloc",
            "-fno-builtin-posix_memalign",
            "-c",
            str(PROBE_SOURCE),
            "-o",
            probe_object,
        ],
        [
            compiler,
            "-O2",
            "-fno-lto",
            wrapper_object,
            probe_object,
            "-pthread",
            "-Wl,--no-undefined",
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=calloc",
            "-Wl,--wrap=realloc",
            "-Wl,--wrap=free",
            "-Wl,--wrap=aligned_alloc",
            "-Wl,--wrap=posix_memalign",
            "-o",
            f"$BUILD_DIR/{PROBE_FILE}",
        ],
    ]


def _compile(
    compiler_name: str, compiler: Path, build_dir: Path, output_dir: Path
) -> tuple[dict, Path, Path, Path]:
    environment = _minimal_environment(compiler.parent)
    version, version_stderr = _require_command_success(
        [str(compiler), "--version"], environment=environment
    )
    target, target_stderr = _require_command_success(
        [str(compiler), "-dumpmachine"], environment=environment
    )
    if version_stderr or target_stderr:
        raise ResourceEnvelopeError("compiler identity commands wrote to stderr")
    target = target.strip()
    if "x86_64" not in target.lower():
        raise ResourceEnvelopeError(f"compiler target is not x86_64: {target}")
    (output_dir / COMPILER_VERSION_FILE).write_text(version, encoding="utf8")
    (output_dir / COMPILER_TARGET_FILE).write_text(target + "\n", encoding="utf8")

    production_library = build_dir / LIBRARY_FILE
    test_library = build_dir / "libpqbtc_mldsa44_test.so"
    wrapper_object = build_dir / "wrapper.o"
    probe_object = build_dir / "probe.o"
    probe_binary = build_dir / PROBE_FILE
    commands: list[list[str]] = []

    production_shared = _common_compile_flags(compiler) + [
        "-fPIC",
        "-shared",
        str(wrapper.WRAPPER_SOURCE),
        "-o",
        str(production_library),
    ]
    test_shared = _common_compile_flags(compiler) + [
        "-fPIC",
        "-shared",
        "-DPQBTC_MLDSA44_TESTING=1",
        str(wrapper.WRAPPER_SOURCE),
        "-o",
        str(test_library),
    ]
    wrapper_compile = _common_compile_flags(compiler) + [
        "-fstack-usage",
        "-c",
        str(wrapper.WRAPPER_SOURCE),
        "-o",
        str(wrapper_object),
    ]
    probe_compile = _common_compile_flags(compiler) + [
        "-fstack-usage",
        "-fno-builtin-malloc",
        "-fno-builtin-calloc",
        "-fno-builtin-realloc",
        "-fno-builtin-free",
        "-fno-builtin-aligned_alloc",
        "-fno-builtin-posix_memalign",
        "-c",
        str(PROBE_SOURCE),
        "-o",
        str(probe_object),
    ]
    link = [
        str(compiler),
        "-O2",
        "-fno-lto",
        str(wrapper_object),
        str(probe_object),
        "-pthread",
        "-Wl,--no-undefined",
        "-Wl,--wrap=malloc",
        "-Wl,--wrap=calloc",
        "-Wl,--wrap=realloc",
        "-Wl,--wrap=free",
        "-Wl,--wrap=aligned_alloc",
        "-Wl,--wrap=posix_memalign",
        "-o",
        str(probe_binary),
    ]
    for command in (
        production_shared,
        test_shared,
        wrapper_compile,
        probe_compile,
        link,
    ):
        commands.append(command)
        _require_command_success(
            command, cwd=build_dir, timeout=180, environment=environment
        )

    nm = shutil.which("nm", path=environment["PATH"])
    if nm is None:
        raise ResourceEnvelopeError("nm is required for symbol auditing")
    nm_path = str(Path(nm).resolve())
    symbols, symbol_stderr = _require_command_success(
        [nm_path, "-D", "--defined-only", str(production_library)],
        environment=environment,
    )
    if symbol_stderr:
        raise ResourceEnvelopeError("nm symbol audit wrote to stderr")
    exported = sorted(
        fields[-1]
        for line in symbols.splitlines()
        if (fields := line.split())
    )
    if exported != [
        "pqbtc_mldsa44_sign_hedged",
        "pqbtc_mldsa44_verify_strict",
    ]:
        raise ResourceEnvelopeError(f"production symbol surface drifted: {exported}")
    (output_dir / SYMBOLS_FILE).write_text(
        "".join(f"{symbol}\n" for symbol in exported), encoding="utf8"
    )

    undefined, undefined_stderr = _require_command_success(
        [nm_path, "-u", str(wrapper_object)], environment=environment
    )
    if undefined_stderr:
        raise ResourceEnvelopeError("nm undefined-symbol audit wrote to stderr")
    allocator_names = {
        "malloc",
        "calloc",
        "realloc",
        "free",
        "aligned_alloc",
        "posix_memalign",
    }
    undefined_names = {
        line.split()[-1].lstrip("_")
        for line in undefined.splitlines()
        if line.split()
    }
    unexpected_allocators = sorted(undefined_names & allocator_names)
    if unexpected_allocators:
        raise ResourceEnvelopeError(
            f"production wrapper references heap allocators: {unexpected_allocators}"
        )

    ldd = shutil.which("ldd", path=environment["PATH"])
    if ldd is None:
        raise ResourceEnvelopeError("ldd is required for linked-library inventory")
    linked, linked_stderr = _require_command_success(
        [str(Path(ldd).resolve()), str(probe_binary)], environment=environment
    )
    if linked_stderr:
        raise ResourceEnvelopeError("ldd wrote to stderr")
    (output_dir / LINKED_FILE).write_text(linked, encoding="utf8")
    (output_dir / BUILD_COMMANDS_FILE).write_text(
        canonical_json(_normalize_commands(commands, build_dir)), encoding="utf8"
    )

    wrapper_stack = build_dir / "wrapper.su"
    probe_stack = build_dir / "probe.su"
    _require_regular_file(wrapper_stack, "wrapper stack-usage output", 1024 * 1024)
    _require_regular_file(probe_stack, "probe stack-usage output", 1024 * 1024)
    shutil.copyfile(wrapper_stack, output_dir / WRAPPER_STACK_FILE)
    shutil.copyfile(probe_stack, output_dir / PROBE_STACK_FILE)
    stack_report = {
        "schema_version": 1,
        "records": parse_stack_usage([wrapper_stack, probe_stack]),
        "upstream_mld_total_alloc_44_verify_bytes": 24448,
        "claim": (
            "compiler-specific per-function observations corroborated by guarded "
            "execution; values are not summed into a formal call-chain bound"
        ),
    }
    (output_dir / STACK_REPORT_FILE).write_text(
        canonical_json(stack_report), encoding="utf8"
    )

    shutil.copyfile(production_library, output_dir / LIBRARY_FILE)
    shutil.copyfile(probe_binary, output_dir / PROBE_FILE)
    (output_dir / PROBE_FILE).chmod(0o755)
    build = {
        "compiler_name": compiler_name,
        "compiler_path": str(compiler),
        "compiler_version_sha256": sha256_file(output_dir / COMPILER_VERSION_FILE),
        "compiler_target": target,
        "production_library_sha256": sha256_file(production_library),
        "probe_sha256": sha256_file(probe_binary),
        "production_wrapper_undefined_heap_allocators": [],
        "production_exported_symbols": exported,
        "optimization": "-O2",
        "lto": False,
        "sanitizers": False,
        "testing_define_in_measured_objects": False,
        "assembly": False,
    }
    return build, production_library, test_library, probe_binary


def _selection_outcomes(records: list[dict], indices: list[int], calls: int) -> dict:
    outcomes = {name: 0 for name in OUTCOME_KEYS}
    for cursor in range(calls):
        expected = records[indices[cursor % len(indices)]]["expected"]
        outcomes[RESULT_NAMES[expected]] += 1
    return outcomes


def _materialize_corpus(
    test_library: Path, production_library: Path, output_dir: Path, policy: dict
) -> dict:
    wycheproof = verifier.validate_wycheproof_source()
    promoted = verifier.validate_promoted_source()
    cases = (
        verifier.project_corpus(test_library)
        + verifier.wycheproof_corpus(wycheproof)
        + promoted
    )
    summary = verifier.validate_corpus_manifest(cases)
    verifier.replay_corpus(production_library, cases)

    by_digest: dict[str, dict[str, object]] = {}
    for case in cases:
        digest = sha256_bytes(case.frame)
        record = by_digest.setdefault(
            digest,
            {
                "frame": case.frame,
                "expected": case.expected,
                "aliases": [],
            },
        )
        if record["frame"] != case.frame or record["expected"] != case.expected:
            raise ResourceEnvelopeError("duplicate corpus frame has conflicting meaning")
        record["aliases"].append({"name": case.name, "source": case.source})

    if len(by_digest) != policy["batch"]["unique_frames"]:
        raise ResourceEnvelopeError("unique verifier frame count drifted")
    all_names = {case.name for case in cases}
    required_accepts = set(policy["batch"]["required_accept_cases"])
    required_rejects = set(policy["batch"]["required_deep_reject_cases"])
    if not required_accepts <= all_names or not required_rejects <= all_names:
        raise ResourceEnvelopeError("required resource case taxonomy is incomplete")

    project_by_name = {
        case.name: case for case in cases if case.source == "project"
    }
    reference_key = verifier.decode_frame(
        project_by_name["valid_frozen_vector"].frame
    ).public_key
    same_key_names = set(policy["batch"]["same_key_cases"])

    records = []
    bundle = bytearray(BUNDLE_HEADER.pack(BUNDLE_MAGIC, 1, len(by_digest)))
    for index, digest in enumerate(sorted(by_digest)):
        source = by_digest[digest]
        frame = source["frame"]
        expected = source["expected"]
        aliases = sorted(
            source["aliases"], key=lambda alias: (alias["source"], alias["name"])
        )
        names = sorted(alias["name"] for alias in aliases)
        sources = sorted(set(alias["source"] for alias in aliases))
        decoded = verifier.decode_frame(frame)
        flags = 0
        if expected == verifier.OK:
            flags |= FLAG_VALID
        if required_rejects & set(names):
            flags |= FLAG_DEEP_REJECT
        if (
            same_key_names & set(names)
            and not (decoded.null_flags & verifier.NULL_PUBLIC_KEY)
            and decoded.public_key == reference_key
        ):
            flags |= FLAG_SAME_KEY
        if "valid_frozen_vector" in names:
            flags |= FLAG_FIRST_CALL
        bundle.extend(RECORD_HEADER.pack(len(frame), expected, flags))
        bundle.extend(frame)
        records.append(
            {
                "index": index,
                "sha256": digest,
                "size": len(frame),
                "expected": expected,
                "expected_name": RESULT_NAMES[expected],
                "flags": flags,
                "aliases": aliases,
                "names": names,
                "sources": sources,
            }
        )

    first_indices = [
        record["index"] for record in records if record["flags"] & FLAG_FIRST_CALL
    ]
    selections = {
        "mixed_rotating": [record["index"] for record in records],
        "valid_rotating": [
            record["index"] for record in records if record["flags"] & FLAG_VALID
        ],
        "deep_reject_rotating": [
            record["index"]
            for record in records
            if record["flags"] & FLAG_DEEP_REJECT
        ],
        "same_key_mixed": [
            record["index"] for record in records if record["flags"] & FLAG_SAME_KEY
        ],
    }
    if len(first_indices) != 1:
        raise ResourceEnvelopeError("frozen first-call selection is not unique")
    if len(selections["deep_reject_rotating"]) != len(required_rejects):
        raise ResourceEnvelopeError("deep-reject selection count drifted")
    selected_same_key_names = {
        alias["name"]
        for index in selections["same_key_mixed"]
        for alias in records[index]["aliases"]
        if alias["name"] in same_key_names
    }
    if (
        selected_same_key_names != same_key_names
        or len(selections["same_key_mixed"]) != len(same_key_names)
    ):
        raise ResourceEnvelopeError("same-key selection coverage drifted")
    if any(not values for values in selections.values()):
        raise ResourceEnvelopeError("resource batch selection is empty")
    same_key_records = [records[index] for index in selections["same_key_mixed"]]
    if (
        any(record["expected"] == verifier.ERR_INVALID_ARGUMENT for record in same_key_records)
        or not any(record["expected"] == verifier.OK for record in same_key_records)
        or not any(record["expected"] == verifier.ERR_VERIFY for record in same_key_records)
    ):
        raise ResourceEnvelopeError("same-key mixed selection taxonomy drifted")

    bundle_path = output_dir / BUNDLE_FILE
    bundle_path.write_bytes(bytes(bundle))
    batch_calls = policy["batch"]["verification_calls"]
    expected_outcomes = {
        batch_id: _selection_outcomes(records, indices, batch_calls)
        for batch_id, indices in selections.items()
    }
    inventory = {
        "schema_version": 1,
        "frame_format": "verifier-fuzz-frame-v1",
        "record_order": "strictly ascending SHA-256(frame)",
        "records": records,
        "record_count": len(records),
        "total_frame_bytes": sum(record["size"] for record in records),
        "bundle_size": len(bundle),
        "bundle_sha256": sha256_bytes(bytes(bundle)),
        "source_summary": summary,
        "selection_indices": selections,
        "selection_counts": {
            batch_id: len(indices) for batch_id, indices in selections.items()
        },
        "expected_outcomes": expected_outcomes,
        "first_call_record": first_indices[0],
        "private_key_material_retained": False,
    }
    (output_dir / INVENTORY_FILE).write_text(
        canonical_json(inventory), encoding="utf8"
    )
    return inventory


def _validate_inventory_bundle(
    inventory: dict, bundle_path: Path, policy: dict
) -> dict:
    _require_exact_keys(
        inventory,
        {
            "schema_version",
            "frame_format",
            "record_order",
            "records",
            "record_count",
            "total_frame_bytes",
            "bundle_size",
            "bundle_sha256",
            "source_summary",
            "selection_indices",
            "selection_counts",
            "expected_outcomes",
            "first_call_record",
            "private_key_material_retained",
        },
        "corpus inventory",
    )
    _require_int(inventory["schema_version"], "corpus inventory schema")
    _require_int(inventory["record_count"], "corpus inventory record count")
    _require_int(inventory["total_frame_bytes"], "corpus total frame bytes", 1)
    _require_int(inventory["bundle_size"], "corpus bundle size", 1)
    records = inventory["records"]
    if (
        inventory["schema_version"] != 1
        or inventory["frame_format"] != "verifier-fuzz-frame-v1"
        or inventory["record_order"] != "strictly ascending SHA-256(frame)"
        or type(records) is not list
        or len(records) != policy["batch"]["unique_frames"]
        or inventory["record_count"] != len(records)
        or inventory["private_key_material_retained"] is not False
        or canonical_json(inventory["source_summary"])
        != canonical_json(EXPECTED_CORPUS_SUMMARY)
    ):
        raise ResourceEnvelopeError("corpus inventory header drifted")
    manifest = load_json_object(
        verifier.CORPUS_MANIFEST, "verifier fuzz corpus manifest", 16384
    )
    if canonical_json(manifest.get("generated_corpus")) != canonical_json(
        EXPECTED_CORPUS_SUMMARY
    ):
        raise ResourceEnvelopeError("frozen verifier corpus summary drifted")
    _require_regular_file(bundle_path, "verifier corpus bundle", 4 * 1024 * 1024)
    bundle = bundle_path.read_bytes()
    if (
        type(inventory["bundle_sha256"]) is not str
        or HEX_64.fullmatch(inventory["bundle_sha256"]) is None
        or inventory["bundle_size"] != len(bundle)
        or inventory["bundle_sha256"] != sha256_bytes(bundle)
    ):
        raise ResourceEnvelopeError("corpus bundle identity differs")
    if len(bundle) < BUNDLE_HEADER.size:
        raise ResourceEnvelopeError("corpus bundle is truncated")
    magic, schema, count = BUNDLE_HEADER.unpack_from(bundle)
    if magic != BUNDLE_MAGIC or schema != 1 or count != len(records):
        raise ResourceEnvelopeError("corpus bundle header differs")
    cursor = BUNDLE_HEADER.size
    digests = []
    decoded_frames = []
    total_frame_bytes = 0
    alias_rows = []
    alias_names = set()
    alias_identities = set()
    source_counts = {name: 0 for name in ("project", "wycheproof", "promoted")}
    expected_counts = {name: 0 for name in OUTCOME_KEYS}
    for expected_index, record in enumerate(records):
        _require_exact_keys(
            record,
            {
                "index",
                "sha256",
                "size",
                "expected",
                "expected_name",
                "flags",
                "aliases",
                "names",
                "sources",
            },
            f"corpus record {expected_index}",
        )
        _require_int(record["index"], f"corpus record {expected_index} index")
        _require_int(record["size"], f"corpus record {expected_index} size", 1)
        _require_int(
            record["expected"],
            f"corpus record {expected_index} result",
            min(RESULT_NAMES),
        )
        _require_int(record["flags"], f"corpus record {expected_index} flags")
        if record["expected"] not in RESULT_NAMES:
            raise ResourceEnvelopeError(
                f"corpus record {expected_index} result differs"
            )
        aliases = record["aliases"]
        if type(aliases) is not list or not aliases:
            raise ResourceEnvelopeError(
                f"corpus record {expected_index} aliases differ"
            )
        normalized_aliases = []
        for alias_index, alias in enumerate(aliases):
            _require_exact_keys(
                alias,
                {"name", "source"},
                f"corpus record {expected_index} alias {alias_index}",
            )
            name = _require_string(
                alias["name"],
                f"corpus record {expected_index} alias {alias_index} name",
            )
            source = _require_string(
                alias["source"],
                f"corpus record {expected_index} alias {alias_index} source",
            )
            if source not in source_counts:
                raise ResourceEnvelopeError("corpus alias source differs")
            identity = (source, name)
            if identity in alias_identities or name in alias_names:
                raise ResourceEnvelopeError("corpus aliases are not globally unique")
            alias_identities.add(identity)
            alias_names.add(name)
            source_counts[source] += 1
            expected_counts[RESULT_NAMES[record["expected"]]] += 1
            normalized_aliases.append({"name": name, "source": source})
            alias_rows.append(
                (source, name, record["expected_name"], record["sha256"])
            )
        normalized_aliases.sort(key=lambda alias: (alias["source"], alias["name"]))
        names = sorted(alias["name"] for alias in normalized_aliases)
        sources = sorted(set(alias["source"] for alias in normalized_aliases))
        if (
            record["index"] != expected_index
            or type(record["sha256"]) is not str
            or HEX_64.fullmatch(record["sha256"]) is None
            or record["expected"] not in RESULT_NAMES
            or record["expected_name"] != RESULT_NAMES[record["expected"]]
            or record["flags"] & ~FLAG_MASK
            or aliases != normalized_aliases
            or record["names"] != names
            or record["sources"] != sources
        ):
            raise ResourceEnvelopeError(f"corpus record {expected_index} drifted")
        if cursor + RECORD_HEADER.size > len(bundle):
            raise ResourceEnvelopeError("corpus bundle record header is truncated")
        size, expected, flags = RECORD_HEADER.unpack_from(bundle, cursor)
        cursor += RECORD_HEADER.size
        if (
            size != record["size"]
            or expected != record["expected"]
            or flags != record["flags"]
            or size <= 0
            or cursor + size > len(bundle)
        ):
            raise ResourceEnvelopeError("corpus bundle record metadata differs")
        frame = bundle[cursor : cursor + size]
        cursor += size
        if sha256_bytes(frame) != record["sha256"]:
            raise ResourceEnvelopeError("corpus bundle frame hash differs")
        try:
            decoded = verifier.decode_frame(frame)
        except (verifier.FuzzHarnessError, ValueError) as exc:
            raise ResourceEnvelopeError("corpus bundle frame is invalid") from exc
        if (
            verifier.encode_frame(
                decoded.signature,
                decoded.public_key,
                decoded.context,
                decoded.message,
                decoded.null_flags,
            )
            != frame
        ):
            raise ResourceEnvelopeError("corpus bundle frame is not canonical")
        digests.append(record["sha256"])
        decoded_frames.append(decoded)
        total_frame_bytes += size
    if cursor != len(bundle) or digests != sorted(set(digests)):
        raise ResourceEnvelopeError("corpus bundle order/trailing-byte contract differs")
    if inventory["total_frame_bytes"] != total_frame_bytes:
        raise ResourceEnvelopeError("corpus frame-byte accounting differs")
    aggregate = hashlib.sha256()
    for source, name, expected_name, frame_sha256 in sorted(alias_rows):
        aggregate.update(
            f"{source}\0{name}\0{expected_name}\0{frame_sha256}\n".encode()
        )
    recomputed_summary = {
        "total_cases": len(alias_rows),
        "unique_frames": len(records),
        "source_counts": source_counts,
        "expected_counts": expected_counts,
        "aggregate_sha256": aggregate.hexdigest(),
    }
    if canonical_json(recomputed_summary) != canonical_json(EXPECTED_CORPUS_SUMMARY):
        raise ResourceEnvelopeError("corpus alias/frame semantics differ")

    required_accepts = set(policy["batch"]["required_accept_cases"])
    required_rejects = set(policy["batch"]["required_deep_reject_cases"])
    same_key_names = set(policy["batch"]["same_key_cases"])
    if not required_accepts <= alias_names or not required_rejects <= alias_names:
        raise ResourceEnvelopeError("required corpus taxonomy is incomplete")
    alias_to_record = {
        alias["name"]: index
        for index, record in enumerate(records)
        for alias in record["aliases"]
    }
    for name in required_accepts:
        record = records[alias_to_record[name]]
        if record["expected"] != verifier.OK or "project" not in record["sources"]:
            raise ResourceEnvelopeError("required accept taxonomy differs")
    for name in required_rejects:
        record = records[alias_to_record[name]]
        if record["expected"] != verifier.ERR_VERIFY or "project" not in record["sources"]:
            raise ResourceEnvelopeError("required deep-reject taxonomy differs")
    first_records = [
        alias_to_record[name] for name in alias_names if name == "valid_frozen_vector"
    ]
    if len(first_records) != 1:
        raise ResourceEnvelopeError("frozen first-call taxonomy differs")
    first_record = first_records[0]
    reference_key = decoded_frames[first_record].public_key

    expected_selections = {
        "mixed_rotating": list(range(len(records))),
        "valid_rotating": [
            index
            for index, record in enumerate(records)
            if record["expected"] == verifier.OK
        ],
        "deep_reject_rotating": sorted(
            {alias_to_record[name] for name in required_rejects}
        ),
        "same_key_mixed": sorted(
            {alias_to_record[name] for name in same_key_names}
        ),
    }
    if len(expected_selections["deep_reject_rotating"]) != len(required_rejects):
        raise ResourceEnvelopeError("deep-reject records are not distinct")
    if len(expected_selections["same_key_mixed"]) != len(same_key_names):
        raise ResourceEnvelopeError("same-key records are not distinct")
    for index, (record, decoded) in enumerate(zip(records, decoded_frames)):
        names = set(record["names"])
        expected_flags = 0
        if record["expected"] == verifier.OK:
            expected_flags |= FLAG_VALID
        if names & required_rejects:
            expected_flags |= FLAG_DEEP_REJECT
        if names & same_key_names:
            if (
                decoded.null_flags & verifier.NULL_PUBLIC_KEY
                or decoded.public_key != reference_key
            ):
                raise ResourceEnvelopeError("same-key record public key differs")
            expected_flags |= FLAG_SAME_KEY
        if "valid_frozen_vector" in names:
            expected_flags |= FLAG_FIRST_CALL
        if record["flags"] != expected_flags:
            raise ResourceEnvelopeError(f"corpus record {index} flags differ")

    selections = _require_exact_keys(
        inventory["selection_indices"],
        set(policy["batch"]["batches"]),
        "corpus selections",
    )
    selection_counts = _require_exact_keys(
        inventory["selection_counts"],
        set(policy["batch"]["batches"]),
        "corpus selection counts",
    )
    expected_outcomes = _require_exact_keys(
        inventory["expected_outcomes"],
        set(policy["batch"]["batches"]),
        "corpus expected outcomes",
    )
    for batch_id in policy["batch"]["batches"]:
        indices = selections[batch_id]
        if (
            type(indices) is not list
            or not indices
            or any(type(index) is not int or not 0 <= index < len(records) for index in indices)
            or indices != expected_selections[batch_id]
            or type(selection_counts[batch_id]) is not int
            or selection_counts[batch_id] != len(indices)
        ):
            raise ResourceEnvelopeError(f"corpus selection drifted: {batch_id}")
        calculated = _selection_outcomes(
            records, indices, policy["batch"]["verification_calls"]
        )
        batch_outcomes = _require_exact_keys(
            expected_outcomes[batch_id],
            set(OUTCOME_KEYS),
            f"corpus expected outcomes {batch_id}",
        )
        for name in OUTCOME_KEYS:
            _require_int(
                batch_outcomes[name],
                f"corpus expected outcomes {batch_id}.{name}",
            )
        if canonical_json(batch_outcomes) != canonical_json(calculated):
            raise ResourceEnvelopeError(
                f"corpus expected outcomes drifted: {batch_id}"
            )
    _require_int(inventory["first_call_record"], "corpus first-call record")
    if inventory["first_call_record"] != first_record:
        raise ResourceEnvelopeError("corpus first-call record drifted")
    return inventory


def _run_positive_controls(probe: Path, compiler: Path) -> dict:
    environment = _minimal_environment(compiler.parent)
    records = []
    for mode, expected in (
        ("--heap-positive-control", {"returncodes": [0], "marker": "heap_interposition"}),
        ("--stack-positive-control", {"returncodes": [0], "marker": "undersized_stack_rejection"}),
        (
            "--cpu-positive-control",
            {"returncodes": [-signal.SIGXCPU], "marker": None},
        ),
        (
            "--wall-positive-control",
            {"returncodes": [-signal.SIGALRM], "marker": None},
        ),
    ):
        started = time.monotonic_ns()
        completed = _run_bounded(
            [str(probe), mode],
            cwd=probe.parent,
            timeout=8,
            maximum=4096,
            environment=environment,
        )
        elapsed = time.monotonic_ns() - started
        stdout = completed.stdout.decode("utf8", errors="strict")
        stderr = completed.stderr.decode("utf8", errors="strict")
        if completed.returncode not in expected["returncodes"]:
            raise ResourceEnvelopeError(
                f"detector positive control {mode} exited {completed.returncode}"
            )
        if expected["marker"] is not None:
            control = json.loads(
                stdout,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonfinite_json,
            )
            expected_control = {
                "control": expected["marker"],
                "status": "PASS",
            }
            if mode == "--heap-positive-control":
                expected_control["calls"] = 1
            if control != expected_control:
                raise ResourceEnvelopeError(
                    f"detector positive control {mode} marker drifted"
                )
        elif stdout or stderr:
            raise ResourceEnvelopeError(
                f"signal detector positive control {mode} produced output"
            )
        records.append(
            {
                "mode": mode,
                "status": "PASS",
                "returncode": completed.returncode,
                "signal": (
                    signal.Signals(-completed.returncode).name
                    if completed.returncode < 0
                    else None
                ),
                "elapsed_ns": elapsed,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
    return {
        "schema_version": 1,
        "status": "PASS",
        "controls": records,
        "scope": (
            "calibrates allocator interposition, undersized-stack rejection, "
            "RLIMIT_CPU, and alarm-based wall containment"
        ),
    }


def _run_probe(
    probe: Path, bundle: Path, output_dir: Path, compiler: Path, policy: dict
) -> dict:
    stdout_path = output_dir / OBSERVATION_FILE
    stderr_path = output_dir / PROBE_STDERR_FILE
    environment = _minimal_environment(compiler.parent)
    with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
        try:
            process = subprocess.Popen(
                [str(probe), str(bundle)],
                cwd=probe.parent,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except OSError as exc:
            raise ResourceEnvelopeError(f"cannot start resource probe: {exc}") from exc
        try:
            returncode = process.wait(
                timeout=policy["enforced_limits"]["wall_watchdog_seconds"] + 10
            )
        except subprocess.TimeoutExpired as exc:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ResourceEnvelopeError("resource probe exceeded the outer wall limit") from exc
    for path, label in (
        (stdout_path, "probe stdout"),
        (stderr_path, "probe stderr"),
    ):
        _require_regular_file(
            path,
            label,
            policy["enforced_limits"]["output_file_bytes"],
            allow_empty=True,
        )
    stderr = stderr_path.read_text(encoding="utf8")
    if returncode != 0 or stderr or stdout_path.stat().st_size == 0:
        raise ResourceEnvelopeError(
            f"resource probe exited {returncode}: "
            f"{stderr.strip() or 'stdout was empty'}"
        )
    return load_json_object(stdout_path, "probe observation", MAX_LOG_BYTES)


def _read_host_observation() -> dict:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ResourceEnvelopeError(
            f"resource execution requires Linux x86_64, got "
            f"{platform.system()} {platform.machine()}"
        )
    cpu_model = ""
    microcode = ""
    cpuinfo_path = Path("/proc/cpuinfo")
    if cpuinfo_path.is_file() and not cpuinfo_path.is_symlink():
        text = cpuinfo_path.read_text(encoding="utf8", errors="strict")
        for line in text.splitlines():
            if not cpu_model and line.lower().startswith("model name") and ":" in line:
                cpu_model = line.split(":", 1)[1].strip()[:160]
            if not microcode and line.lower().startswith("microcode") and ":" in line:
                microcode = line.split(":", 1)[1].strip()[:64]
    def read_cgroup(name: str) -> str:
        path = Path("/sys/fs/cgroup") / name
        if not path.is_file() or path.is_symlink():
            return "unavailable"
        value = path.read_text(encoding="ascii", errors="strict").strip()
        return value[:128] if value else "empty"

    affinity_count = None
    if hasattr(os, "sched_getaffinity"):
        affinity_count = len(os.sched_getaffinity(0))
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "cpu_model": cpu_model or "unavailable",
        "microcode": microcode or "unavailable",
        "logical_cpu_count": os.cpu_count(),
        "affinity_cpu_count": affinity_count,
        "cgroup_cpu_max": read_cgroup("cpu.max"),
        "cgroup_memory_max": read_cgroup("memory.max"),
        "hostname_recorded": False,
        "environment_recorded": False,
    }


def _claim_output_directory(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise ResourceEnvelopeError("evidence output directory must not be a symlink")
    if output_dir.exists() and not output_dir.is_dir():
        raise ResourceEnvelopeError("evidence output path must be a directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ResourceEnvelopeError("evidence output directory must be empty")
    (output_dir / OWNER_FILE).write_text(OWNER_CONTENT, encoding="utf8")


def _resolve_evidence_directory(output_dir: Path, *, must_exist: bool) -> Path:
    original = Path(output_dir)
    try:
        status = original.lstat()
    except FileNotFoundError:
        if must_exist:
            raise ResourceEnvelopeError("evidence directory does not exist")
    except OSError as exc:
        raise ResourceEnvelopeError(f"cannot inspect evidence directory: {exc}") from exc
    else:
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise ResourceEnvelopeError(
                "evidence path must be a regular non-symlink directory"
            )
    try:
        return original.resolve()
    except OSError as exc:
        raise ResourceEnvelopeError(f"cannot resolve evidence directory: {exc}") from exc


def write_evidence_hashes(output_dir: Path) -> None:
    checksum_path = output_dir / CHECKSUM_FILE
    if checksum_path.exists() or checksum_path.is_symlink():
        raise ResourceEnvelopeError("evidence checksum manifest already exists")
    rows = []
    for path in sorted(output_dir.iterdir(), key=lambda value: value.name):
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode):
            raise ResourceEnvelopeError(f"evidence entry is not regular: {path.name}")
        rows.append(f"{sha256_file(path)}  {path.name}\n")
    checksum_path.write_text("".join(rows), encoding="ascii")


def _base_report(plan: dict) -> dict:
    return {
        "schema_version": 1,
        "status": "INCOMPLETE",
        "error": "execution did not start",
        "repository": None,
        "trust": None,
        "scope": {
            **copy.deepcopy(plan["policy"]["scope"]),
            "measurement_target": plan["policy"]["profile"]["measurement_target"],
            "target_symbol": plan["target"],
        },
        "plan_sha256": None,
        "policy_sha256": plan["policy_sha256"],
        "source_contract": None,
        "compiler": None,
        "host": None,
        "corpus": None,
        "build": None,
        "stack_usage": None,
        "detector_controls": None,
        "observation_sha256": None,
        "timing_summaries": None,
        "limitations": [
            "Linux x86_64 only",
            "sequential direct-verifier calls only",
            "hosted-runner timing and RSS are observations, not acceptance limits",
            "no node, wallet, script, consensus, block-scheduler, or concurrency claim",
            "project-object allocator interposition does not measure dynamic-libc internals",
            "compiler .su rows are per-function observations, not a formal call-chain sum",
            "production backend remains NONE and the release hold remains active",
        ],
    }


def _finalize_failure(output_dir: Path, report: dict, error: Exception) -> None:
    for filename in (CHECKSUM_FILE, OBSERVATION_FILE):
        path = output_dir / filename
        if path.exists() or path.is_symlink():
            path.unlink()
    report["status"] = "FAIL"
    report["error"] = str(error)[:2000] or type(error).__name__
    (output_dir / REPORT_FILE).write_text(canonical_json(report), encoding="utf8")
    (output_dir / JOB_STATUS_FILE).write_text("failure\n", encoding="ascii")
    write_evidence_hashes(output_dir)


def _report_keys() -> set[str]:
    return set(_base_report(build_plan(load_policy())))


def _verify_checksum_manifest(output_dir: Path, names: set[str]) -> None:
    checksum_path = output_dir / CHECKSUM_FILE
    _require_regular_file(checksum_path, "evidence checksum manifest", 16384)
    try:
        lines = checksum_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ResourceEnvelopeError(f"cannot read evidence checksums: {exc}") from exc
    expected_names = sorted(names - {CHECKSUM_FILE})
    if len(lines) != len(expected_names):
        raise ResourceEnvelopeError("evidence checksum row count differs")
    observed_names = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None:
            raise ResourceEnvelopeError("malformed evidence checksum row")
        digest, name = match.groups()
        observed_names.append(name)
        path = output_dir / name
        _require_regular_file(
            path,
            f"checksummed evidence {name}",
            MAX_EVIDENCE_BYTES,
            allow_empty=True,
        )
        if sha256_file(path) != digest:
            raise ResourceEnvelopeError(f"evidence checksum mismatch: {name}")
    if observed_names != expected_names:
        raise ResourceEnvelopeError("evidence checksum inventory is not exact and sorted")


def _verify_success_repository_and_trust(
    report: dict, output_dir: Path
) -> None:
    repository = _require_exact_keys(
        report["repository"],
        {
            "head",
            "clean",
            "full_history",
            "baseline_pointer",
            "baseline_guard_matches",
        },
        "resource report repository",
    )
    trust = _require_exact_keys(
        report["trust"],
        {
            "label",
            "trusted_observation",
            "promotion_eligible",
            "reason",
            "ci",
            "requires_external_workflow_provenance",
            "requires_companion_compilers",
            "requires_separate_numeric_policy_change",
        },
        "resource report trust",
    )
    current_head = _run_git("rev-parse", "HEAD").strip()
    current_status = _run_git(
        "status", "--porcelain=v1", "--untracked-files=all"
    )
    shallow = _run_git("rev-parse", "--is-shallow-repository").strip()
    if (
        repository["head"] != current_head
        or HEX_40.fullmatch(current_head) is None
        or repository["clean"] is not True
        or current_status
        or repository["full_history"] is not True
        or shallow != "false"
    ):
        raise ResourceEnvelopeError("resource report repository state differs")
    if _read_text_file(
        output_dir / GIT_HEAD_FILE, "resource evidence Git head", maximum=64
    ) != current_head + "\n":
        raise ResourceEnvelopeError("resource evidence Git head differs")
    if _read_text_file(
        output_dir / GIT_STATUS_FILE,
        "resource evidence Git status",
        maximum=MAX_LOG_BYTES,
        allow_empty=True,
    ) != current_status:
        raise ResourceEnvelopeError("resource evidence Git status differs")
    pointer_bytes = BASELINE_POINTER.read_bytes()
    if re.fullmatch(rb"[0-9a-f]{40}\n", pointer_bytes) is None:
        raise ResourceEnvelopeError("review baseline pointer is malformed")
    baseline = pointer_bytes[:-1].decode("ascii")
    if repository["baseline_pointer"] != baseline:
        raise ResourceEnvelopeError("resource report baseline pointer differs")
    _require_first_parent_baseline(current_head, baseline)
    current_diff = _run_git(
        "diff", "--name-only", baseline, current_head, "--", *GUARDED_PATHS
    )
    if _read_text_file(
        output_dir / BASELINE_DIFF_FILE,
        "resource evidence baseline diff",
        maximum=MAX_LOG_BYTES,
        allow_empty=True,
    ) != current_diff:
        raise ResourceEnvelopeError("resource evidence baseline diff differs")
    baseline_guard_matches = not bool(current_diff)
    if repository["baseline_guard_matches"] is not baseline_guard_matches:
        raise ResourceEnvelopeError("resource report baseline result differs")

    ci_context = trust["ci"]
    if type(ci_context) is not dict:
        raise ResourceEnvelopeError("resource report CI context must be an object")
    if ci_context.get("github_actions") is True:
        _validate_github_context(ci_context, current_head)
    elif ci_context != _local_ci_context():
        raise ResourceEnvelopeError("resource report local context differs")
    expected_trust = _build_trust(ci_context, baseline_guard_matches)
    if canonical_json(trust) != canonical_json(expected_trust):
        raise ResourceEnvelopeError("resource report trust classification differs")
    if os.environ.get("GITHUB_ACTIONS", "") == "true":
        if _ci_context_from_environment(current_head) != ci_context:
            raise ResourceEnvelopeError("ambient GitHub context differs from evidence")


def _validate_detector_controls(controls: dict) -> dict:
    _require_exact_keys(
        controls,
        {"schema_version", "status", "controls", "scope"},
        "detector controls",
    )
    _require_int(controls["schema_version"], "detector-control schema")
    if (
        controls["schema_version"] != 1
        or controls["status"] != "PASS"
        or controls["scope"]
        != (
            "calibrates allocator interposition, undersized-stack rejection, "
            "RLIMIT_CPU, and alarm-based wall containment"
        )
        or type(controls["controls"]) is not list
        or len(controls["controls"]) != 4
    ):
        raise ResourceEnvelopeError("detector-control header drifted")
    expected_modes = [
        "--heap-positive-control",
        "--stack-positive-control",
        "--cpu-positive-control",
        "--wall-positive-control",
    ]
    for index, (record, expected_mode) in enumerate(
        zip(controls["controls"], expected_modes)
    ):
        _require_exact_keys(
            record,
            {
                "mode",
                "status",
                "returncode",
                "signal",
                "elapsed_ns",
                "stdout",
                "stderr",
            },
            f"detector control {index}",
        )
        if (
            record["mode"] != expected_mode
            or record["status"] != "PASS"
            or type(record["returncode"]) is not int
            or type(record["stdout"]) is not str
            or type(record["stderr"]) is not str
            or (
                record["signal"] is not None
                and type(record["signal"]) is not str
            )
            or len(record["stdout"].encode()) > 4096
            or len(record["stderr"].encode()) > 4096
        ):
            raise ResourceEnvelopeError(f"detector control drifted: {expected_mode}")
        _require_int(record["elapsed_ns"], f"{expected_mode} elapsed time", 1)
        if expected_mode == "--heap-positive-control":
            expected_signal = None
            expected_returncodes = {0}
            marker = {
                "control": "heap_interposition",
                "status": "PASS",
                "calls": 1,
            }
        elif expected_mode == "--stack-positive-control":
            expected_signal = None
            expected_returncodes = {0}
            marker = {
                "control": "undersized_stack_rejection",
                "status": "PASS",
            }
        elif expected_mode == "--cpu-positive-control":
            expected_signal = {"SIGXCPU"}
            expected_returncodes = {-signal.SIGXCPU}
            marker = None
        else:
            expected_signal = {"SIGALRM"}
            expected_returncodes = {-signal.SIGALRM}
            marker = None
        if record["returncode"] not in expected_returncodes:
            raise ResourceEnvelopeError(
                f"detector control return code drifted: {expected_mode}"
            )
        if marker is not None:
            try:
                parsed = json.loads(
                    record["stdout"],
                    object_pairs_hook=_reject_duplicate_json_keys,
                    parse_constant=_reject_nonfinite_json,
                )
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ResourceEnvelopeError(
                    f"detector control marker is invalid: {expected_mode}"
                ) from exc
            if (
                parsed != marker
                or record["signal"] is not None
                or record["stderr"]
            ):
                raise ResourceEnvelopeError(
                    f"detector control marker drifted: {expected_mode}"
                )
        elif (
            record["signal"] not in expected_signal
            or record["stdout"]
            or record["stderr"]
        ):
            raise ResourceEnvelopeError(
                f"detector control signal drifted: {expected_mode}"
            )
    return controls


def _verify_success_report_bindings(
    report: dict, output_dir: Path, inventory: dict
) -> None:
    compiler = _require_exact_keys(
        report["compiler"], {"name", "path", "target"}, "resource compiler"
    )
    _require_string(compiler["name"], "resource compiler name")
    _require_string(compiler["path"], "resource compiler path")
    _require_string(compiler["target"], "resource compiler target")
    if (
        compiler["name"] not in {"gcc", "clang"}
        or not Path(compiler["path"]).is_absolute()
        or "x86_64" not in compiler["target"].lower()
    ):
        raise ResourceEnvelopeError("resource compiler name differs")
    if (
        compiler["target"]
        != _read_text_file(
            output_dir / COMPILER_TARGET_FILE,
            "compiler target evidence",
            maximum=4096,
        ).strip()
    ):
        raise ResourceEnvelopeError("resource compiler identity differs")
    build = _require_exact_keys(
        report["build"],
        {
            "compiler_name",
            "compiler_path",
            "compiler_version_sha256",
            "compiler_target",
            "production_library_sha256",
            "probe_sha256",
            "production_wrapper_undefined_heap_allocators",
            "production_exported_symbols",
            "optimization",
            "lto",
            "sanitizers",
            "testing_define_in_measured_objects",
            "assembly",
        },
        "resource build",
    )
    if (
        build["compiler_name"] != compiler["name"]
        or build["compiler_path"] != compiler["path"]
        or build["compiler_target"] != compiler["target"]
        or build["compiler_version_sha256"]
        != sha256_file(output_dir / COMPILER_VERSION_FILE)
        or build["production_library_sha256"]
        != sha256_file(output_dir / LIBRARY_FILE)
        or build["probe_sha256"] != sha256_file(output_dir / PROBE_FILE)
        or build["production_wrapper_undefined_heap_allocators"] != []
        or build["production_exported_symbols"]
        != ["pqbtc_mldsa44_sign_hedged", "pqbtc_mldsa44_verify_strict"]
        or build["optimization"] != "-O2"
        or build["lto"] is not False
        or build["sanitizers"] is not False
        or build["testing_define_in_measured_objects"] is not False
        or build["assembly"] is not False
    ):
        raise ResourceEnvelopeError("resource build binding differs")
    expected_symbols = (
        "pqbtc_mldsa44_sign_hedged\npqbtc_mldsa44_verify_strict\n"
    )
    if _read_text_file(
        output_dir / SYMBOLS_FILE, "production symbol evidence", maximum=4096
    ) != expected_symbols:
        raise ResourceEnvelopeError("production symbol evidence differs")
    commands = load_json_object(
        output_dir / BUILD_COMMANDS_FILE, "resource build commands"
    )
    _require_exact_keys(
        commands,
        {"schema_version", "shell_used", "commands", "forbidden_flags_absent"},
        "resource build commands",
    )
    _require_int(commands["schema_version"], "resource build-command schema")
    if (
        commands["schema_version"] != 1
        or commands["shell_used"] is not False
        or commands["forbidden_flags_absent"] != FORBIDDEN_FLAG_CLAIMS
        or commands["commands"]
        != _expected_normalized_commands(compiler["path"])
    ):
        raise ResourceEnvelopeError("resource build-command evidence differs")

    host = load_json_object(output_dir / HOST_FILE, "host observation")
    _require_exact_keys(
        host,
        {
            "system",
            "machine",
            "kernel_release",
            "cpu_model",
            "microcode",
            "logical_cpu_count",
            "affinity_cpu_count",
            "cgroup_cpu_max",
            "cgroup_memory_max",
            "hostname_recorded",
            "environment_recorded",
        },
        "host observation",
    )
    for field in (
        "kernel_release",
        "cpu_model",
        "microcode",
        "cgroup_cpu_max",
        "cgroup_memory_max",
    ):
        _require_string(host[field], f"host observation {field}")
    _require_int(host["logical_cpu_count"], "host logical CPU count", 1)
    _require_int(host["affinity_cpu_count"], "host affinity CPU count", 1)
    if (
        host["system"] != "Linux"
        or host["machine"] != "x86_64"
        or host["hostname_recorded"] is not False
        or host["environment_recorded"] is not False
    ):
        raise ResourceEnvelopeError("host observation scope differs")
    if canonical_json(report["host"]) != canonical_json(host):
        raise ResourceEnvelopeError("resource host observation differs")
    if _read_text_file(
        output_dir / PROBE_STDERR_FILE,
        "successful probe stderr",
        maximum=MAX_LOG_BYTES,
        allow_empty=True,
    ):
        raise ResourceEnvelopeError("successful probe stderr is not empty")
    linked = _read_text_file(
        output_dir / LINKED_FILE, "linked-library evidence", maximum=MAX_LOG_BYTES
    )
    if (
        "libc.so.6" not in linked
        or "ld-linux-x86-64.so.2" not in linked
        or "not found" in linked
        or "libpqbtc" in linked
        or "$BUILD_DIR" in linked
        or str(REPO_ROOT) in linked
    ):
        raise ResourceEnvelopeError("linked-library evidence differs")
    if canonical_json(report["source_contract"]) != canonical_json(
        _validate_source_contract()
    ):
        raise ResourceEnvelopeError("resource source-contract evidence differs")
    expected_corpus = {
        "record_count": inventory["record_count"],
        "total_frame_bytes": inventory["total_frame_bytes"],
        "bundle_sha256": inventory["bundle_sha256"],
        "selection_counts": inventory["selection_counts"],
        "expected_outcomes": inventory["expected_outcomes"],
        "first_call_record": inventory["first_call_record"],
    }
    if canonical_json(report["corpus"]) != canonical_json(expected_corpus):
        raise ResourceEnvelopeError("resource corpus report binding differs")


def verify_evidence(output_dir: Path) -> dict:
    output_dir = _resolve_evidence_directory(output_dir, must_exist=True)
    entries = sorted(output_dir.iterdir(), key=lambda value: value.name)
    if not entries or len(entries) > MAX_EVIDENCE_FILES:
        raise ResourceEnvelopeError("evidence file count is outside the frozen bound")
    total_size = 0
    names = set()
    for path in entries:
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode):
            raise ResourceEnvelopeError(f"evidence contains a non-regular entry: {path.name}")
        if "/" in path.name or path.name in names:
            raise ResourceEnvelopeError("evidence contains an unsafe/duplicate name")
        names.add(path.name)
        total_size += status.st_size
    if total_size > MAX_EVIDENCE_BYTES:
        raise ResourceEnvelopeError("evidence total size exceeds the frozen bound")
    if not names <= SUCCESS_FILES:
        raise ResourceEnvelopeError(
            f"evidence contains unexpected files: {sorted(names - SUCCESS_FILES)}"
        )
    _verify_checksum_manifest(output_dir, names)
    if _read_text_file(
        output_dir / OWNER_FILE,
        "evidence ownership marker",
        maximum=1024,
    ) != OWNER_CONTENT:
        raise ResourceEnvelopeError("evidence ownership marker differs")

    plan = load_json_object(output_dir / PLAN_FILE, "evidence resource plan")
    expected_plan = build_plan(load_policy())
    if _read_text_file(
        output_dir / PLAN_FILE, "evidence resource plan"
    ) != canonical_json(expected_plan):
        raise ResourceEnvelopeError("evidence resource plan differs from this source tree")
    policy_copy = load_json_object(output_dir / POLICY_FILE, "evidence policy")
    if (
        canonical_json(policy_copy) != canonical_json(plan["policy"])
        or (output_dir / POLICY_FILE).read_bytes() != POLICY_PATH.read_bytes()
        or sha256_file(output_dir / POLICY_FILE) != POLICY_SHA256
    ):
        raise ResourceEnvelopeError("evidence policy copy differs")
    report = load_json_object(output_dir / REPORT_FILE, "resource report")
    _require_exact_keys(report, _report_keys(), "resource report")
    _require_int(report["schema_version"], "resource report schema")
    if report["schema_version"] != 1 or report["policy_sha256"] != POLICY_SHA256:
        raise ResourceEnvelopeError("resource report identity drifted")
    if report["plan_sha256"] != sha256_file(output_dir / PLAN_FILE):
        raise ResourceEnvelopeError("resource report plan hash differs")
    if canonical_json(report["scope"]) != canonical_json(_base_report(plan)["scope"]):
        raise ResourceEnvelopeError("resource report scope drifted")
    if report["limitations"] != _base_report(plan)["limitations"]:
        raise ResourceEnvelopeError("resource report limitations drifted")
    status = report["status"]
    if status not in {"PASS", "FAIL", "INCOMPLETE"}:
        raise ResourceEnvelopeError("resource report status is unsupported")
    job_status = _read_text_file(
        output_dir / JOB_STATUS_FILE,
        "resource job status",
        encoding="ascii",
        maximum=64,
    )
    if status == "PASS":
        if names != SUCCESS_FILES or job_status != "success\n" or report["error"] is not None:
            raise ResourceEnvelopeError("successful evidence inventory/status differs")
        _verify_success_repository_and_trust(report, output_dir)
        inventory = load_json_object(
            output_dir / INVENTORY_FILE, "verifier corpus inventory"
        )
        _validate_inventory_bundle(
            inventory, output_dir / BUNDLE_FILE, plan["policy"]
        )
        _verify_success_report_bindings(report, output_dir, inventory)
        observation = load_json_object(
            output_dir / OBSERVATION_FILE, "probe observation", MAX_LOG_BYTES
        )
        validated = validate_probe_observation(
            observation,
            plan,
            expected_input_fnv1a64=fnv1a64_bytes(
                (output_dir / BUNDLE_FILE).read_bytes()
            ),
        )
        for batch in observation["batches"]:
            if canonical_json(batch["outcomes"]) != canonical_json(
                inventory["expected_outcomes"][batch["id"]]
            ):
                raise ResourceEnvelopeError(
                    f"probe outcomes differ from corpus: {batch['id']}"
                )
        if canonical_json(observation["selection_counts"]) != canonical_json(
            inventory["selection_counts"]
        ):
            raise ResourceEnvelopeError("probe selection counts differ from corpus")
        if observation["first_call"]["record"] != inventory["first_call_record"]:
            raise ResourceEnvelopeError("probe first-call record differs from corpus")
        if report["observation_sha256"] != sha256_file(output_dir / OBSERVATION_FILE):
            raise ResourceEnvelopeError("resource report observation hash differs")
        if canonical_json(report["timing_summaries"]) != canonical_json(
            validated["derived_summaries"]
        ):
            raise ResourceEnvelopeError("resource report timing summaries differ")
        stack_report = load_json_object(
            output_dir / STACK_REPORT_FILE, "stack-usage report"
        )
        _require_exact_keys(
            stack_report,
            {
                "schema_version",
                "records",
                "upstream_mld_total_alloc_44_verify_bytes",
                "claim",
            },
            "stack-usage report",
        )
        _require_int(stack_report["schema_version"], "stack-usage schema")
        _require_int(
            stack_report["upstream_mld_total_alloc_44_verify_bytes"],
            "upstream verifier scratch allocation",
            1,
        )
        parsed_stack = parse_stack_usage(
            [output_dir / WRAPPER_STACK_FILE, output_dir / PROBE_STACK_FILE]
        )
        if (
            stack_report["schema_version"] != 1
            or stack_report["upstream_mld_total_alloc_44_verify_bytes"] != 24448
            or stack_report["claim"]
            != (
                "compiler-specific per-function observations corroborated by guarded "
                "execution; values are not summed into a formal call-chain bound"
            )
            or canonical_json(stack_report["records"]) != canonical_json(parsed_stack)
            or canonical_json(report["stack_usage"]) != canonical_json(stack_report)
        ):
            raise ResourceEnvelopeError("stack-usage evidence differs")
        controls = load_json_object(
            output_dir / CONTROLS_FILE, "detector controls"
        )
        _validate_detector_controls(controls)
        if canonical_json(report["detector_controls"]) != canonical_json(controls):
            raise ResourceEnvelopeError("detector-control evidence differs")
        if report["trust"]["promotion_eligible"] is not False:
            raise ResourceEnvelopeError("single-compiler evidence became promotion eligible")
        if any(
            plan["policy"]["acceptance_limits"][field] is not None
            for field in ("cpu_seconds", "wall_seconds", "peak_rss_kib")
        ):
            raise ResourceEnvelopeError("numeric thresholds bootstrapped from evidence")
    else:
        if not FAILURE_REQUIRED_FILES <= names:
            raise ResourceEnvelopeError("failure evidence is incomplete")
        expected_job_status = {
            "FAIL": "failure\n",
            "INCOMPLETE": "incomplete\n",
        }[status]
        if job_status != expected_job_status:
            raise ResourceEnvelopeError("failure evidence job status differs")
        if type(report["error"]) is not str or not report["error"]:
            raise ResourceEnvelopeError("failure evidence lacks an exact error")
        if status == "FAIL" and OBSERVATION_FILE in names:
            raise ResourceEnvelopeError(
                "failure evidence retained a canonical observation file"
            )
        if status == "INCOMPLETE" and OBSERVATION_FILE in names:
            observation = load_json_object(
                output_dir / OBSERVATION_FILE, "incomplete fixture observation"
            )
            validate_probe_observation(observation, plan)
    return report


def write_test_evidence_fixture(
    output_dir: Path, observation: dict, replace: bool = False
) -> None:
    """Create a canonical incomplete fixture used only by unit tests."""
    if replace and output_dir.exists():
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise ResourceEnvelopeError("test fixture path must be a regular directory")
        for path in output_dir.iterdir():
            if path.is_dir() and not path.is_symlink():
                raise ResourceEnvelopeError(
                    "test fixture replacement refuses nested directories"
                )
            path.unlink()
    policy = load_policy()
    plan = build_plan(policy)
    validate_probe_observation(observation, plan)
    _claim_output_directory(output_dir)
    (output_dir / PLAN_FILE).write_text(canonical_json(plan), encoding="utf8")
    (output_dir / POLICY_FILE).write_bytes(POLICY_PATH.read_bytes())
    (output_dir / OBSERVATION_FILE).write_text(
        canonical_json(observation), encoding="utf8"
    )
    report = _base_report(plan)
    report["status"] = "INCOMPLETE"
    report["error"] = "unit-test fixture; execution intentionally omitted"
    report["plan_sha256"] = sha256_file(output_dir / PLAN_FILE)
    report["observation_sha256"] = sha256_file(output_dir / OBSERVATION_FILE)
    report["timing_summaries"] = validate_probe_observation(
        observation, plan
    )["derived_summaries"]
    (output_dir / REPORT_FILE).write_text(canonical_json(report), encoding="utf8")
    (output_dir / JOB_STATUS_FILE).write_text("incomplete\n", encoding="ascii")
    write_evidence_hashes(output_dir)
    verify_evidence(output_dir)


def execute(compiler_name: str, output_dir: Path) -> int:
    policy = load_policy()
    plan = build_plan(policy)
    output_dir = _resolve_evidence_directory(output_dir, must_exist=False)
    resolved_repo = REPO_ROOT.resolve()
    if resolved_repo == output_dir or resolved_repo in output_dir.parents:
        raise ResourceEnvelopeError("evidence output directory must be outside the repository")
    _claim_output_directory(output_dir)
    (output_dir / PLAN_FILE).write_text(canonical_json(plan), encoding="utf8")
    (output_dir / POLICY_FILE).write_bytes(POLICY_PATH.read_bytes())
    report = _base_report(plan)
    report["plan_sha256"] = sha256_file(output_dir / PLAN_FILE)
    try:
        repository, trust = _repository_and_trust(output_dir)
        report["repository"] = repository
        report["trust"] = trust
        source_contract = _validate_source_contract()
        report["source_contract"] = source_contract
        host = _read_host_observation()
        report["host"] = host
        (output_dir / HOST_FILE).write_text(canonical_json(host), encoding="utf8")
        compiler = _compiler_path(compiler_name)
        with tempfile.TemporaryDirectory(
            prefix="pqbtc-mldsa44-resource-"
        ) as temporary:
            build_dir = Path(temporary)
            build, production_library, test_library, probe = _compile(
                compiler_name, compiler, build_dir, output_dir
            )
            report["compiler"] = {
                "name": compiler_name,
                "path": str(compiler),
                "target": build["compiler_target"],
            }
            report["build"] = build
            inventory = _materialize_corpus(
                test_library, production_library, output_dir, policy
            )
            _validate_inventory_bundle(
                inventory, output_dir / BUNDLE_FILE, policy
            )
            report["corpus"] = {
                "record_count": inventory["record_count"],
                "total_frame_bytes": inventory["total_frame_bytes"],
                "bundle_sha256": inventory["bundle_sha256"],
                "selection_counts": inventory["selection_counts"],
                "expected_outcomes": inventory["expected_outcomes"],
                "first_call_record": inventory["first_call_record"],
            }
            controls = _run_positive_controls(probe, compiler)
            (output_dir / CONTROLS_FILE).write_text(
                canonical_json(controls), encoding="utf8"
            )
            report["detector_controls"] = controls
            observation = _run_probe(
                probe, output_dir / BUNDLE_FILE, output_dir, compiler, policy
            )
            validated = validate_probe_observation(
                observation,
                plan,
                expected_input_fnv1a64=fnv1a64_bytes(
                    (output_dir / BUNDLE_FILE).read_bytes()
                ),
            )
            if observation["selection_counts"] != inventory["selection_counts"]:
                raise ResourceEnvelopeError(
                    "probe selection counts differ from frozen corpus"
                )
            for batch in observation["batches"]:
                if (
                    batch["outcomes"]
                    != inventory["expected_outcomes"][batch["id"]]
                ):
                    raise ResourceEnvelopeError(
                        f"probe outcome accounting differs: {batch['id']}"
                    )
            if observation["first_call"]["record"] != inventory["first_call_record"]:
                raise ResourceEnvelopeError("probe first-call record differs")
            report["observation_sha256"] = sha256_file(
                output_dir / OBSERVATION_FILE
            )
            report["timing_summaries"] = validated["derived_summaries"]
            stack_report = load_json_object(
                output_dir / STACK_REPORT_FILE, "stack-usage report"
            )
            report["stack_usage"] = stack_report

        status_after = _run_git(
            "status", "--porcelain=v1", "--untracked-files=all"
        )
        head_after = _run_git("rev-parse", "HEAD").strip()
        if status_after or head_after != repository["head"]:
            raise ResourceEnvelopeError("repository changed during resource execution")
        report["status"] = "PASS"
        report["error"] = None
        (output_dir / REPORT_FILE).write_text(canonical_json(report), encoding="utf8")
        (output_dir / JOB_STATUS_FILE).write_text("success\n", encoding="ascii")
        write_evidence_hashes(output_dir)
        verify_evidence(output_dir)
        return 0
    except (
        ResourceEnvelopeError,
        verifier.FuzzHarnessError,
        wrapper.HarnessError,
        OSError,
        UnicodeError,
        ValueError,
        ctypes.ArgumentError,
    ) as exc:
        _finalize_failure(output_dir, report, exc)
        print(f"error: {exc}", file=sys.stderr)
        return 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Observe the isolated ML-DSA-44 verifier resource envelope"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--verify-evidence", type=Path)
    mode.add_argument("--output-dir", type=Path)
    parser.add_argument("--compiler", choices=("gcc", "clang"))
    args = parser.parse_args(argv)
    if args.output_dir is not None and args.compiler is None:
        parser.error("--compiler is required with --output-dir")
    if args.output_dir is None and args.compiler is not None:
        parser.error("--compiler requires --output-dir")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.plan_only:
            print(canonical_json(build_plan(load_policy())), end="")
            return 0
        if args.verify_evidence is not None:
            report = verify_evidence(args.verify_evidence)
            print(
                f"ML-DSA-44 resource evidence verified: {report['status']}"
            )
            return 0
        return execute(args.compiler, args.output_dir)
    except (
        ResourceEnvelopeError,
        verifier.FuzzHarnessError,
        wrapper.HarnessError,
        OSError,
        UnicodeError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
