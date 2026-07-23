#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Replay and fuzz the isolated ML-DSA-44 signer and seeded key generator."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

import run_verifier_fuzz as verifier_fuzz
import run_wrapper_tests as wrapper


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
FUZZ_SOURCE = HERE / "pqbtc_mldsa44_stateful_fuzz.c"
CORPUS_MANIFEST = HERE / "stateful_signer_fuzz_corpus.json"
DRIVER_SOURCE = Path(__file__).resolve()

FRAME_HEADER = struct.Struct("<BBBBHH")
FRAME_VERSION = 1
SEED_BYTES = 32
RANDOMIZER_BYTES = 32
MAX_MESSAGE_BYTES = 4096
MAX_CONTEXT_BYTES = 256
MAX_FRAME_BYTES = (
    FRAME_HEADER.size
    + SEED_BYTES
    + 2 * RANDOMIZER_BYTES
    + MAX_MESSAGE_BYTES
    + MAX_CONTEXT_BYTES
)
CAMPAIGN_SCHEMA_VERSION = 1
TARGET_NAME = "ml-dsa-44-stateful-signer-seeded-keygen"
RETAINED_SOURCE_ENV = {
    "run_id": "RETAINED_SOURCE_RUN",
    "run_attempt": "RETAINED_SOURCE_ATTEMPT",
    "head_sha": "RETAINED_SOURCE_HEAD",
    "artifact": "RETAINED_SOURCE_ARTIFACT",
    "evidence_sha256": "RETAINED_SOURCE_EVIDENCE_SHA256",
    "restored_seed_file_count": "RETAINED_SOURCE_SEED_COUNT",
    "restored_seed_total_bytes": "RETAINED_SOURCE_SEED_BYTES",
    "restored_seed_aggregate_sha256": "RETAINED_SOURCE_SEED_AGGREGATE_SHA256",
}

SCENARIOS = {
    0: "fresh_a_then_fresh_b",
    1: "fresh_a_then_repeat_a_then_fresh_b",
    2: "fresh_a_then_short_b_then_repeat_a_then_fresh_b",
    3: "fresh_a_then_source_failure_then_repeat_a_then_fresh_b",
    4: "fresh_a_then_zero_then_repeat_a_then_fresh_b",
    5: "fresh_a_then_invalid_then_repeat_a_then_fresh_b",
    6: "backend_failure_a_then_repeat_a_then_fresh_b",
    7: "attempts_exhausted_a_then_repeat_a_then_fresh_b",
    8: "signature_length_failure_a_then_repeat_a_then_fresh_b",
    9: "self_verify_failure_a_then_repeat_a_then_fresh_b",
    10: "fresh_a_then_reset_then_reuse_a",
}
INVALID_CONTEXT_SCENARIO = "invalid_context_preserves_repeat_state"
ARGUMENT_VARIANTS = {
    0: "null_output",
    1: "short_output",
    2: "long_output",
    3: "alias_secret_key",
    4: "alias_public_key",
    5: "alias_message",
    6: "alias_context",
    7: "null_secret_key",
    8: "short_secret_key",
    9: "null_public_key",
    10: "short_public_key",
    11: "null_message",
    12: "null_context",
}


class StatefulFuzzError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignerCase:
    name: str
    frame: bytes
    scenario: int
    argument_variant: int


@dataclass(frozen=True)
class DecodedFrame:
    scenario: int
    argument_variant: int
    short_length: int
    seed: bytes
    randomizer_a: bytes
    randomizer_b: bytes
    message: bytes
    context: bytes


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode_frame(
    *,
    scenario: int,
    argument_variant: int,
    short_length: int,
    seed: bytes,
    randomizer_a: bytes,
    randomizer_b: bytes,
    message: bytes,
    context: bytes,
) -> bytes:
    if scenario not in SCENARIOS:
        raise StatefulFuzzError("unsupported stateful signer scenario")
    if argument_variant not in ARGUMENT_VARIANTS:
        raise StatefulFuzzError("unsupported invalid-argument variant")
    if not 0 <= short_length < RANDOMIZER_BYTES:
        raise StatefulFuzzError("short entropy length is outside 0..31")
    if len(seed) != SEED_BYTES:
        raise StatefulFuzzError("seed must be exactly 32 bytes")
    if len(randomizer_a) != RANDOMIZER_BYTES or len(randomizer_b) != RANDOMIZER_BYTES:
        raise StatefulFuzzError("randomizers must be exactly 32 bytes")
    if len(message) > MAX_MESSAGE_BYTES or len(context) > MAX_CONTEXT_BYTES:
        raise StatefulFuzzError("stateful signer frame exceeds a field bound")
    return (
        FRAME_HEADER.pack(
            FRAME_VERSION,
            scenario,
            argument_variant,
            short_length,
            len(message),
            len(context),
        )
        + seed
        + randomizer_a
        + randomizer_b
        + message
        + context
    )


def decode_frame(frame: bytes) -> DecodedFrame:
    fixed_size = FRAME_HEADER.size + SEED_BYTES + 2 * RANDOMIZER_BYTES
    if len(frame) < fixed_size:
        raise StatefulFuzzError("truncated stateful signer frame")
    (
        version,
        scenario,
        argument_variant,
        short_length,
        message_size,
        context_size,
    ) = FRAME_HEADER.unpack_from(frame)
    if version != FRAME_VERSION:
        raise StatefulFuzzError("unsupported stateful signer frame version")
    if scenario not in SCENARIOS or argument_variant not in ARGUMENT_VARIANTS:
        raise StatefulFuzzError("non-canonical stateful signer selector")
    if short_length >= RANDOMIZER_BYTES:
        raise StatefulFuzzError("non-canonical short entropy length")
    if message_size > MAX_MESSAGE_BYTES or context_size > MAX_CONTEXT_BYTES:
        raise StatefulFuzzError("stateful signer frame field exceeds its bound")
    if fixed_size + message_size + context_size != len(frame):
        raise StatefulFuzzError("stateful signer frame length mismatch")
    cursor = FRAME_HEADER.size
    seed = frame[cursor : cursor + SEED_BYTES]
    cursor += SEED_BYTES
    randomizer_a = frame[cursor : cursor + RANDOMIZER_BYTES]
    cursor += RANDOMIZER_BYTES
    randomizer_b = frame[cursor : cursor + RANDOMIZER_BYTES]
    cursor += RANDOMIZER_BYTES
    message = frame[cursor : cursor + message_size]
    cursor += message_size
    context = frame[cursor : cursor + context_size]
    return DecodedFrame(
        scenario,
        argument_variant,
        short_length,
        seed,
        randomizer_a,
        randomizer_b,
        message,
        context,
    )


def generated_corpus() -> list[SignerCase]:
    vectors = json.loads(wrapper.VECTORS.read_text(encoding="utf8"))["vectors"]
    project = vectors["pqbtc_sighash_v1"]
    seed = bytes.fromhex(project["seed_hex"])
    message = bytes.fromhex(project["message_hex"])
    context = bytes.fromhex(project["context_hex"])
    randomizer_a = bytes(range(1, 33))
    randomizer_b = bytes(range(33, 65))
    cases: list[SignerCase] = []

    def add(
        name: str,
        scenario: int,
        *,
        argument_variant: int = 0,
        short_length: int = 31,
        candidate_message: bytes = message,
        candidate_context: bytes = context,
        candidate_randomizer_a: bytes = randomizer_a,
        candidate_randomizer_b: bytes = randomizer_b,
    ) -> None:
        cases.append(
            SignerCase(
                name=name,
                scenario=scenario,
                argument_variant=argument_variant,
                frame=encode_frame(
                    scenario=scenario,
                    argument_variant=argument_variant,
                    short_length=short_length,
                    seed=seed,
                    randomizer_a=candidate_randomizer_a,
                    randomizer_b=candidate_randomizer_b,
                    message=candidate_message,
                    context=candidate_context,
                ),
            )
        )

    for scenario, name in SCENARIOS.items():
        if scenario != 5:
            add(name, scenario)
    for variant, name in ARGUMENT_VARIANTS.items():
        add(
            f"fresh_a_then_invalid_{name}_then_repeat_a_then_fresh_b",
            5,
            argument_variant=variant,
        )
    add(
        "fresh_a_then_invalid_alias_message_maximum_message_then_repeat_a_then_fresh_b",
        5,
        argument_variant=5,
        candidate_message=bytes(MAX_MESSAGE_BYTES),
    )
    for short_length in (0, 1, 16):
        add(
            f"fresh_a_then_short_{short_length}_then_repeat_a_then_fresh_b",
            2,
            short_length=short_length,
        )
    add("fresh_empty_message_and_context", 0, candidate_message=b"", candidate_context=b"")
    add("fresh_maximum_context", 0, candidate_context=bytes(range(255)))
    add(
        "fresh_a_then_invalid_256_context_then_repeat_a_then_fresh_b",
        0,
        candidate_context=bytes(256),
    )
    add("fresh_maximum_message", 0, candidate_message=bytes(4096))
    return cases


def corpus_filename(case: SignerCase) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", case.name)
    return f"project_{safe_name}.bin"


def corpus_summary(cases: list[SignerCase]) -> dict:
    digest = hashlib.sha256()
    scenario_counts = {
        name: 0 for name in (*SCENARIOS.values(), INVALID_CONTEXT_SCENARIO)
    }
    argument_counts = {name: 0 for name in ARGUMENT_VARIANTS.values()}
    frame_hashes = set()
    for case in sorted(cases, key=lambda item: item.name):
        frame_sha256 = hashlib.sha256(case.frame).hexdigest()
        scenario_name = (
            INVALID_CONTEXT_SCENARIO
            if len(decode_frame(case.frame).context) == MAX_CONTEXT_BYTES
            else SCENARIOS[case.scenario]
        )
        digest.update(
            f"{case.name}\0{scenario_name}\0"
            f"{ARGUMENT_VARIANTS[case.argument_variant]}\0{frame_sha256}\n".encode()
        )
        scenario_counts[scenario_name] += 1
        if scenario_name == SCENARIOS[5]:
            argument_counts[ARGUMENT_VARIANTS[case.argument_variant]] += 1
        frame_hashes.add(frame_sha256)
    return {
        "total_cases": len(cases),
        "unique_frames": len(frame_hashes),
        "scenario_counts": scenario_counts,
        "invalid_argument_variant_counts": argument_counts,
        "aggregate_sha256": digest.hexdigest(),
    }


def validate_corpus_manifest(cases: list[SignerCase]) -> dict:
    manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf8"))
    expected_keys = {
        "schema_version",
        "target",
        "frame_version",
        "fuzz_limits",
        "sources",
        "required_scenarios",
        "required_invalid_argument_variants",
        "generated_corpus",
    }
    if set(manifest) != expected_keys:
        raise StatefulFuzzError("stateful signer corpus manifest fields differ")
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or type(manifest["frame_version"]) is not int
        or manifest["frame_version"] != FRAME_VERSION
        or manifest["target"] != TARGET_NAME
    ):
        raise StatefulFuzzError("unsupported stateful signer corpus manifest")
    expected_limits = {
        "seed_bytes": SEED_BYTES,
        "randomizer_bytes": RANDOMIZER_BYTES,
        "message_bytes": MAX_MESSAGE_BYTES,
        "context_bytes": MAX_CONTEXT_BYTES,
        "frame_bytes": MAX_FRAME_BYTES,
        "hedged_signing_calls_per_input_max": 4,
    }
    if manifest["fuzz_limits"] != expected_limits:
        raise StatefulFuzzError("stateful signer fuzz limits differ")
    if manifest["sources"] != {"repo_vectors_sha256": sha256_file(wrapper.VECTORS)}:
        raise StatefulFuzzError("stateful signer corpus source hash differs")
    if manifest["required_scenarios"] != [
        *SCENARIOS.values(),
        INVALID_CONTEXT_SCENARIO,
    ]:
        raise StatefulFuzzError("stateful signer scenario inventory differs")
    if manifest["required_invalid_argument_variants"] != list(
        ARGUMENT_VARIANTS.values()
    ):
        raise StatefulFuzzError("stateful signer argument inventory differs")
    identities = [case.name for case in cases]
    if len(set(identities)) != len(identities):
        raise StatefulFuzzError("stateful signer corpus identities are not unique")
    filenames = [corpus_filename(case) for case in cases]
    if len(set(filenames)) != len(filenames):
        raise StatefulFuzzError("stateful signer corpus filenames collide")
    for case in cases:
        if encode_frame(**decode_frame(case.frame).__dict__) != case.frame:
            raise StatefulFuzzError(f"non-canonical stateful signer frame: {case.name}")
    summary = corpus_summary(cases)
    if manifest["generated_corpus"] != summary:
        raise StatefulFuzzError(
            "generated stateful signer corpus differs from the manifest:\n"
            + json.dumps(summary, indent=2, sort_keys=True)
        )
    return summary


def materialize_corpus(directory: Path, cases: list[SignerCase]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for case in cases:
        (directory / corpus_filename(case)).write_bytes(case.frame)


def filesystem_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
    )


def read_stable_regular_file(path: Path, label: str, maximum_size: int) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise StatefulFuzzError(f"{label} does not exist: {path}") from error
    if stat.S_ISLNK(before.st_mode):
        raise StatefulFuzzError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise StatefulFuzzError(f"{label} is not a regular file: {path}")
    if before.st_size > maximum_size:
        raise StatefulFuzzError(f"{label} exceeds its size bound: {path}")
    data = path.read_bytes()
    after = path.lstat()
    if (
        filesystem_identity(after) != filesystem_identity(before)
        or len(data) != before.st_size
    ):
        raise StatefulFuzzError(f"{label} changed while it was read: {path}")
    return data


def named_file_summary(entries: list[tuple[str, bytes]]) -> dict:
    digest = hashlib.sha256()
    total_bytes = 0
    for name, data in sorted(entries):
        file_digest = hashlib.sha256(data).hexdigest()
        digest.update(f"{name}\0{len(data)}\0{file_digest}\n".encode())
        total_bytes += len(data)
    return {
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "aggregate_sha256": digest.hexdigest(),
    }


def content_inventory_summary(contents: dict[str, bytes]) -> dict:
    digest = hashlib.sha256()
    total_bytes = 0
    for file_digest, data in sorted(contents.items()):
        digest.update(f"{len(data)}\0{file_digest}\n".encode())
        total_bytes += len(data)
    return {
        "file_count": len(contents),
        "total_bytes": total_bytes,
        "aggregate_sha256": digest.hexdigest(),
    }


def read_flat_retained_corpus(
    source: Path,
    *,
    label: str,
    require_nonempty: bool,
) -> list[tuple[str, bytes]]:
    try:
        source_status = source.lstat()
    except FileNotFoundError as error:
        raise StatefulFuzzError(f"{label} does not exist: {source}") from error
    if stat.S_ISLNK(source_status.st_mode):
        raise StatefulFuzzError(f"{label} must not be a symlink: {source}")
    if not stat.S_ISDIR(source_status.st_mode):
        raise StatefulFuzzError(f"{label} is not a directory: {source}")

    candidates = sorted(source.iterdir(), key=lambda path: path.name)
    if require_nonempty and not candidates:
        raise StatefulFuzzError(f"{label} is empty")
    if len(candidates) > verifier_fuzz.MAX_RETAINED_CORPUS_FILES:
        raise StatefulFuzzError("retained corpus exceeds the file-count bound")
    entries = []
    total_bytes = 0
    for path in candidates:
        data = read_stable_regular_file(
            path,
            f"{label} input",
            MAX_FRAME_BYTES,
        )
        total_bytes += len(data)
        if total_bytes > verifier_fuzz.MAX_RETAINED_CORPUS_BYTES:
            raise StatefulFuzzError("retained corpus exceeds the aggregate byte bound")
        entries.append((path.name, data))
    source_after = source.lstat()
    if filesystem_identity(source_after) != filesystem_identity(source_status):
        raise StatefulFuzzError(f"{label} changed while it was read: {source}")
    return entries


def empty_retained_source() -> dict:
    return {field: None for field in RETAINED_SOURCE_ENV}


def retained_source_metadata() -> dict:
    raw = {
        field: os.environ.get(environment_name) or None
        for field, environment_name in RETAINED_SOURCE_ENV.items()
    }
    present = [value is not None for value in raw.values()]
    if not any(present):
        return empty_retained_source()
    if not all(present):
        raise StatefulFuzzError("retained source provenance is incomplete")
    if (
        re.fullmatch(r"[0-9]+", raw["run_id"]) is None
        or int(raw["run_id"]) < 1
        or re.fullmatch(r"[0-9]+", raw["run_attempt"]) is None
        or int(raw["run_attempt"]) < 1
        or re.fullmatch(r"[0-9a-f]{40}", raw["head_sha"]) is None
        or re.fullmatch(r"[A-Za-z0-9._-]+", raw["artifact"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", raw["evidence_sha256"]) is None
        or re.fullmatch(r"[0-9]+", raw["restored_seed_file_count"]) is None
        or re.fullmatch(r"[0-9]+", raw["restored_seed_total_bytes"]) is None
        or re.fullmatch(
            r"[0-9a-f]{64}", raw["restored_seed_aggregate_sha256"]
        )
        is None
    ):
        raise StatefulFuzzError("retained source provenance is malformed")
    file_count = int(raw["restored_seed_file_count"])
    total_bytes = int(raw["restored_seed_total_bytes"])
    if (
        not 1 <= file_count <= verifier_fuzz.MAX_RETAINED_CORPUS_FILES
        or total_bytes > verifier_fuzz.MAX_RETAINED_CORPUS_BYTES
    ):
        raise StatefulFuzzError("retained source provenance exceeds a resource bound")
    return {
        **raw,
        "restored_seed_file_count": file_count,
        "restored_seed_total_bytes": total_bytes,
    }


def restored_source_summary(metadata: dict) -> dict | None:
    if metadata["run_id"] is None:
        return None
    return {
        "file_count": metadata["restored_seed_file_count"],
        "total_bytes": metadata["restored_seed_total_bytes"],
        "aggregate_sha256": metadata["restored_seed_aggregate_sha256"],
    }


def import_seed_corpus(
    source: Path,
    destination: Path,
    *,
    expected_source_summary: dict | None = None,
) -> dict:
    entries = read_flat_retained_corpus(
        source,
        label="seed corpus",
        require_nonempty=False,
    )
    source_summary = named_file_summary(entries)
    if (
        expected_source_summary is not None
        and source_summary != expected_source_summary
    ):
        raise StatefulFuzzError(
            "retained corpus summary differs from validated evidence"
        )

    retained: dict[str, bytes] = {}
    for _, data in entries:
        digest = hashlib.sha256(data).hexdigest()
        previous = retained.setdefault(digest, data)
        if previous != data:
            raise StatefulFuzzError(
                f"retained corpus SHA256 collision detected: {digest}"
            )

    destination_status = destination.lstat()
    if stat.S_ISLNK(destination_status.st_mode) or not stat.S_ISDIR(
        destination_status.st_mode
    ):
        raise StatefulFuzzError(
            f"working corpus is not a regular directory: {destination}"
        )
    existing: dict[str, bytes] = {}
    for path in sorted(destination.iterdir(), key=lambda item: item.name):
        data = read_stable_regular_file(
            path,
            "working corpus input",
            MAX_FRAME_BYTES,
        )
        digest = hashlib.sha256(data).hexdigest()
        previous = existing.setdefault(digest, data)
        if previous != data:
            raise StatefulFuzzError(
                f"working corpus SHA256 collision detected: {path}"
            )

    imported: dict[str, bytes] = {}
    for digest, data in retained.items():
        if digest in existing:
            if existing[digest] != data:
                raise StatefulFuzzError(
                    f"working corpus SHA256 collision detected: {digest}"
                )
            continue
        target = destination / f"retained_{digest}.bin"
        if target.exists() or target.is_symlink():
            raise StatefulFuzzError(
                f"retained corpus destination already exists: {target}"
            )
        with target.open("xb") as stream:
            stream.write(data)
        copied = read_stable_regular_file(
            target,
            "imported retained corpus input",
            MAX_FRAME_BYTES,
        )
        if copied != data:
            raise StatefulFuzzError(
                f"imported retained corpus input differs: {target}"
            )
        existing[digest] = data
        imported[digest] = data
    return {
        "source_summary": source_summary,
        "unique_source_summary": content_inventory_summary(retained),
        "imported_summary": content_inventory_summary(imported),
    }


def validate_sha256_manifest(evidence_dir: Path) -> str:
    manifest_path = evidence_dir / "SHA256SUMS"
    manifest = read_stable_regular_file(
        manifest_path,
        "retained evidence checksum manifest",
        8 * 1024 * 1024,
    )
    try:
        lines = manifest.decode("utf8").splitlines()
    except UnicodeDecodeError as error:
        raise StatefulFuzzError(
            "retained evidence checksum manifest is not UTF-8"
        ) from error
    expected: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise StatefulFuzzError("retained evidence checksum line is malformed")
        digest, relative = match.groups()
        path = PurePosixPath(relative)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != relative
            or relative == "SHA256SUMS"
            or relative in expected
        ):
            raise StatefulFuzzError(
                f"retained evidence checksum path is unsafe: {relative}"
            )
        expected[relative] = digest

    actual = {
        path.relative_to(evidence_dir).as_posix(): sha256_file(path)
        for path in sorted(evidence_dir.rglob("*"))
        if path.is_file() and path != manifest_path
    }
    if set(actual) != set(expected):
        raise StatefulFuzzError("retained evidence checksum inventory differs")
    for relative, digest in actual.items():
        if digest != expected[relative]:
            raise StatefulFuzzError(
                f"retained evidence checksum differs: {relative}"
            )
    return hashlib.sha256(manifest).hexdigest()


def validate_retained_evidence(
    evidence_dir: Path,
    *,
    expected_head: str,
    expected_sanitizer: str,
) -> dict:
    try:
        evidence_status = evidence_dir.lstat()
    except FileNotFoundError as error:
        raise StatefulFuzzError(
            f"retained evidence does not exist: {evidence_dir}"
        ) from error
    if stat.S_ISLNK(evidence_status.st_mode) or not stat.S_ISDIR(
        evidence_status.st_mode
    ):
        raise StatefulFuzzError("retained evidence must be a regular directory")
    if re.fullmatch(r"[0-9a-f]{40}", expected_head) is None:
        raise StatefulFuzzError("retained evidence head is not a Git commit")
    if expected_sanitizer not in verifier_fuzz.SANITIZERS:
        raise StatefulFuzzError("retained evidence sanitizer is unsupported")

    for path in sorted(evidence_dir.rglob("*")):
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise StatefulFuzzError(
                f"retained evidence must not contain symlinks: {path}"
            )
        if not stat.S_ISDIR(status.st_mode) and not stat.S_ISREG(status.st_mode):
            raise StatefulFuzzError(
                f"retained evidence contains a special entry: {path}"
            )

    seed_dir = evidence_dir / "minimized-corpus"
    seed_entries = read_flat_retained_corpus(
        seed_dir,
        label="retained minimized corpus",
        require_nonempty=True,
    )

    evidence_sha256 = validate_sha256_manifest(evidence_dir)
    campaign_path = evidence_dir / "campaign.json"
    try:
        campaign = json.loads(
            read_stable_regular_file(
                campaign_path,
                "retained campaign report",
                8 * 1024 * 1024,
            ).decode("utf8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatefulFuzzError("retained campaign report is malformed") from error
    actual_summary = named_file_summary(seed_entries)
    if (
        campaign.get("target") != TARGET_NAME
        or campaign.get("status") != "pass"
        or campaign.get("return_code") != 0
        or campaign.get("processing_error") is not None
        or campaign.get("repository_commit") != expected_head
        or campaign.get("repository_head") != expected_head
        or campaign.get("repository_dirty") is not False
        or campaign.get("sanitizer") != expected_sanitizer
        or campaign.get("minimized_corpus") != actual_summary
    ):
        raise StatefulFuzzError("retained campaign provenance differs")
    return {
        "source_head_sha": expected_head,
        "source_sanitizer": expected_sanitizer,
        "source_evidence_sha256": evidence_sha256,
        "restored_seed_file_count": actual_summary["file_count"],
        "restored_seed_total_bytes": actual_summary["total_bytes"],
        "restored_seed_aggregate_sha256": actual_summary["aggregate_sha256"],
    }


def repository_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def compile_fuzzer(
    compiler: str,
    build_dir: Path,
    *,
    sanitizer: str,
    coverage: bool,
) -> Path:
    output = build_dir / "pqbtc_mldsa44_stateful_fuzz"
    command = wrapper.common_flags(compiler)
    command.extend(
        [
            "-DPQBTC_MLDSA44_TESTING=1",
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            f"-fsanitize={verifier_fuzz.SANITIZERS[sanitizer]}",
        ]
    )
    if sanitizer == "memory":
        command.extend(["-fsanitize-memory-track-origins=2", "-fPIE", "-pie"])
    if coverage:
        command.extend(["-fprofile-instr-generate", "-fcoverage-mapping"])
    command.extend(
        [
            str(wrapper.WRAPPER_SOURCE),
            str(FUZZ_SOURCE),
            "-o",
            str(output),
        ]
    )
    wrapper.run(command)
    return output


def sanitizer_environment(
    sanitizer: str, profile_pattern: Path | None = None
) -> dict[str, str]:
    env = os.environ.copy()
    if sanitizer == "address-undefined":
        env["ASAN_OPTIONS"] = (
            "detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1"
        )
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    if sanitizer == "memory":
        env["MSAN_OPTIONS"] = "halt_on_error=1:print_stats=1"
    if profile_pattern is not None:
        env["LLVM_PROFILE_FILE"] = str(profile_pattern)
    return env


def replay_corpus(
    executable: Path,
    corpus_dir: Path,
    cases: list[SignerCase],
    log_path: Path,
    *,
    sanitizer: str,
    profile_pattern: Path | None,
) -> dict:
    log_parts = []
    records = []
    env = sanitizer_environment(sanitizer, profile_pattern)
    for case in cases:
        path = corpus_dir / corpus_filename(case)
        command = [
            str(executable),
            str(path),
            "-runs=1",
            "-seed=188",
            "-timeout=5",
            "-rss_limit_mb=1024",
            "-malloc_limit_mb=256",
        ]
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=30,
        )
        log_parts.append(
            f"case: {case.name}\ncommand: {' '.join(command)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\n"
        )
        records.append(
            {
                "name": case.name,
                "frame_sha256": hashlib.sha256(case.frame).hexdigest(),
                "return_code": completed.returncode,
                "status": "pass" if completed.returncode == 0 else "fail",
            }
        )
        if completed.returncode != 0:
            log_path.write_text("\n".join(log_parts), encoding="utf8")
            raise StatefulFuzzError(
                f"deterministic stateful replay failed: {case.name}"
            )
    log_path.write_text("\n".join(log_parts), encoding="utf8")
    return {
        "status": "pass",
        "case_count": len(records),
        "cases": records,
    }


def executed_units(stderr: str) -> int | None:
    matches = re.findall(r"stat::number_of_executed_units:\s+(\d+)", stderr)
    return int(matches[-1]) if matches else None


def write_campaign_report(
    output_dir: Path,
    *,
    compiler: str,
    sanitizer: str,
    coverage: bool,
    runs: int | None,
    seconds: int | None,
    seed: int,
    retained_source: dict,
    retained_import: dict | None,
    source_summary: dict,
    replay: dict | None,
    fuzzer: Path | None,
    started_at: str,
    duration_seconds: float,
    fuzzer_duration_seconds: float | None,
    completed: subprocess.CompletedProcess[str],
    processing_error: str | None,
    crash_minimization: list[dict],
) -> None:
    progress_lines = [
        line.strip()
        for line in completed.stderr.splitlines()
        if re.match(r"^#\d+", line.strip())
    ]
    final_stats = [
        line.strip()
        for line in completed.stderr.splitlines()
        if line.strip().startswith("stat::")
    ]
    report = {
        "schema_version": CAMPAIGN_SCHEMA_VERSION,
        "target": TARGET_NAME,
        "status": (
            "pass" if completed.returncode == 0 and processing_error is None else "fail"
        ),
        "return_code": completed.returncode,
        "processing_error": processing_error,
        "repository_commit": verifier_fuzz.repository_commit(),
        "repository_head": repository_head(),
        "repository_dirty": verifier_fuzz.repository_dirty(),
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(duration_seconds, 3),
        "fuzzer_duration_seconds": (
            round(fuzzer_duration_seconds, 3)
            if fuzzer_duration_seconds is not None
            else None
        ),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "compiler": verifier_fuzz.compiler_identity(compiler),
        "coverage_tools": (
            verifier_fuzz.coverage_tool_identities(compiler) if coverage else None
        ),
        "sanitizer": sanitizer,
        "coverage_enabled": coverage,
        "campaign_limit": {"runs": runs, "seconds": seconds},
        "resource_limits": {
            "harness_frame_bytes": MAX_FRAME_BYTES,
            "fuzzer_max_len_bytes": MAX_FRAME_BYTES,
            "input_timeout_seconds": 5,
            "rss_limit_mb": 1024,
            "malloc_limit_mb": 256,
            "seed": seed,
        },
        "stateful_contract": {
            "reset_before_and_after_every_input": True,
            "seeded_keygen_determinism": True,
            "entropy_request_accounting": True,
            "post_entropy_failures_consume_repeat_state": True,
            "pre_entropy_failures_preserve_repeat_state": True,
            "failure_output_contract": True,
            "strict_self_verification": True,
            "external_oracles_in_process": False,
        },
        "deterministic_replay": replay,
        "executed_units": executed_units(completed.stderr),
        "imported_retained_seeds": (
            retained_import["imported_summary"]["file_count"]
            if retained_import is not None
            else 0
        ),
        "retained_corpus_source": retained_source,
        "retained_corpus_import": retained_import,
        "source_corpus": source_summary,
        "source_files": {
            "wrapper_sha256": sha256_file(wrapper.WRAPPER_SOURCE),
            "public_header_sha256": sha256_file(HERE / "pqbtc_mldsa44.h"),
            "test_header_sha256": sha256_file(HERE / "pqbtc_mldsa44_test.h"),
            "fuzz_target_sha256": sha256_file(FUZZ_SOURCE),
            "driver_sha256": sha256_file(DRIVER_SOURCE),
            "verifier_fuzz_driver_sha256": sha256_file(
                Path(verifier_fuzz.__file__).resolve()
            ),
            "wrapper_test_driver_sha256": sha256_file(
                Path(wrapper.__file__).resolve()
            ),
            "corpus_manifest_sha256": sha256_file(CORPUS_MANIFEST),
            "repo_vectors_sha256": sha256_file(wrapper.VECTORS),
            "source_manifest_sha256": sha256_file(wrapper.SOURCE_MANIFEST),
            "source_capsule_sha256": json.loads(
                wrapper.SOURCE_MANIFEST.read_text(encoding="utf8")
            )["capsule_hash"]["value"],
            "fuzzer_binary_sha256": (
                sha256_file(fuzzer) if fuzzer is not None and fuzzer.is_file() else None
            ),
        },
        "working_corpus": verifier_fuzz.directory_summary(output_dir / "corpus"),
        "minimized_corpus": verifier_fuzz.directory_summary(
            output_dir / "minimized-corpus"
        ),
        "crash_artifacts": verifier_fuzz.directory_summary(output_dir / "crashes"),
        "minimized_crash_artifacts": verifier_fuzz.directory_summary(
            output_dir / "minimized-crashes"
        ),
        "crash_minimization": crash_minimization,
        "last_progress_line": progress_lines[-1] if progress_lines else None,
        "final_stats": final_stats,
    }
    (output_dir / "campaign.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf8",
    )


def run_campaign(args: argparse.Namespace, cases: list[SignerCase], summary: dict) -> int:
    compiler = os.environ.get("CC", "clang")
    if shutil.which(compiler) is None:
        raise StatefulFuzzError(f"stateful fuzz compiler not found: {compiler}")
    output_dir = args.output_dir
    if output_dir is None:
        raise StatefulFuzzError("--output-dir is required for sanitizer campaigns")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise StatefulFuzzError("stateful fuzz output directory is not empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir = output_dir / "corpus"
    crashes_dir = output_dir / "crashes"
    corpus_dir.mkdir()
    crashes_dir.mkdir()
    materialize_corpus(corpus_dir, cases)
    retained_source = empty_retained_source()
    retained_import: dict | None = None

    started_at = datetime.now(timezone.utc).isoformat()
    overall_started = time.monotonic()
    fuzzer: Path | None = None
    replay: dict | None = None
    crash_minimization: list[dict] = []
    processing_error: str | None = None
    completed = subprocess.CompletedProcess(
        args=["stateful-fuzzer-not-run"],
        returncode=1,
        stdout="",
        stderr="",
    )
    fuzzer_duration: float | None = None

    with tempfile.TemporaryDirectory(prefix="pqbtc-mldsa44-stateful-fuzz-") as temporary:
        build_dir = Path(temporary)
        try:
            retained_source = retained_source_metadata()
            source_expectation = restored_source_summary(retained_source)
            if args.seed_corpus is None and source_expectation is not None:
                raise StatefulFuzzError(
                    "retained source provenance requires a seed corpus"
                )
            if args.seed_corpus is not None:
                retained_import = import_seed_corpus(
                    args.seed_corpus,
                    corpus_dir,
                    expected_source_summary=source_expectation,
                )
            fuzzer = compile_fuzzer(
                compiler,
                build_dir,
                sanitizer=args.sanitizer,
                coverage=args.coverage,
            )
            replay = replay_corpus(
                fuzzer,
                corpus_dir,
                cases,
                output_dir / "deterministic-replay.log",
                sanitizer=args.sanitizer,
                profile_pattern=(
                    output_dir / "coverage-replay-%p.profraw"
                    if args.coverage
                    else None
                ),
            )
            fuzzer_started = time.monotonic()
            completed = verifier_fuzz.run_fuzzer(
                fuzzer,
                corpus_dir,
                crashes_dir,
                output_dir / "fuzzer.log",
                runs=args.runs,
                seconds=args.seconds,
                sanitizer=args.sanitizer,
                profile_pattern=(
                    output_dir / "coverage-campaign-%p.profraw"
                    if args.coverage
                    else None
                ),
                seed=args.seed,
                max_frame_bytes=MAX_FRAME_BYTES,
            )
            fuzzer_duration = time.monotonic() - fuzzer_started
            if completed.returncode != 0:
                processing_error = f"stateful fuzz campaign failed ({completed.returncode})"
            else:
                verifier_fuzz.minimize_corpus(
                    fuzzer,
                    corpus_dir,
                    output_dir / "minimized-corpus",
                    output_dir / "corpus-minimization.log",
                    sanitizer=args.sanitizer,
                    profile_pattern=(
                        output_dir / "coverage-merge-%p.profraw"
                        if args.coverage
                        else None
                    ),
                    max_frame_bytes=MAX_FRAME_BYTES,
                )
                if args.coverage:
                    verifier_fuzz.write_coverage_report(
                        compiler, fuzzer, output_dir
                    )
            crash_minimization = verifier_fuzz.minimize_crash_artifacts(
                fuzzer,
                crashes_dir,
                output_dir,
                sanitizer=args.sanitizer,
                seed=args.seed,
                max_frame_bytes=MAX_FRAME_BYTES,
            )
        except (
            OSError,
            subprocess.SubprocessError,
            StatefulFuzzError,
            verifier_fuzz.FuzzHarnessError,
            wrapper.HarnessError,
        ) as error:
            processing_error = str(error)

        write_campaign_report(
            output_dir,
            compiler=compiler,
            sanitizer=args.sanitizer,
            coverage=args.coverage,
            runs=args.runs,
            seconds=args.seconds,
            seed=args.seed,
            retained_source=retained_source,
            retained_import=retained_import,
            source_summary=summary,
            replay=replay,
            fuzzer=fuzzer,
            started_at=started_at,
            duration_seconds=time.monotonic() - overall_started,
            fuzzer_duration_seconds=fuzzer_duration,
            completed=completed,
            processing_error=processing_error,
            crash_minimization=crash_minimization,
        )
        verifier_fuzz.write_evidence_hashes(output_dir)

    return 0 if completed.returncode == 0 and processing_error is None else 1


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fuzz the isolated ML-DSA-44 stateful signer and seeded keygen"
    )
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--sanitizers", action="store_true")
    parser.add_argument(
        "--sanitizer",
        choices=sorted(verifier_fuzz.SANITIZERS),
        default="address-undefined",
    )
    parser.add_argument("--runs", type=int)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--seed", type=int, default=188)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seed-corpus", type=Path)
    parser.add_argument("--coverage", action="store_true")
    parser.add_argument("--validate-retained-evidence", type=Path)
    parser.add_argument("--expected-retained-head")
    parser.add_argument(
        "--expected-retained-sanitizer",
        choices=sorted(verifier_fuzz.SANITIZERS),
    )
    args = parser.parse_args()
    validation_mode = args.validate_retained_evidence is not None
    if validation_mode:
        if (
            args.expected_retained_head is None
            or args.expected_retained_sanitizer is None
        ):
            raise StatefulFuzzError(
                "retained evidence validation requires its head and sanitizer"
            )
        if (
            args.manifest_only
            or args.sanitizers
            or args.runs is not None
            or args.seconds is not None
            or args.output_dir is not None
            or args.seed_corpus is not None
            or args.coverage
        ):
            raise StatefulFuzzError(
                "retained evidence validation cannot run a fuzz campaign"
            )
        return args
    if (
        args.expected_retained_head is not None
        or args.expected_retained_sanitizer is not None
    ):
        raise StatefulFuzzError(
            "retained evidence expectations require validation mode"
        )
    if args.runs is not None and args.seconds is not None:
        raise StatefulFuzzError("--runs and --seconds are mutually exclusive")
    if args.runs is not None and args.runs < 1:
        raise StatefulFuzzError("--runs must be positive")
    if args.seconds is not None and args.seconds < 1:
        raise StatefulFuzzError("--seconds must be positive")
    if not 1 <= args.seed <= 0xFFFFFFFF:
        raise StatefulFuzzError("--seed must be a nonzero unsigned 32-bit integer")
    if args.coverage and not args.sanitizers:
        raise StatefulFuzzError("--coverage requires --sanitizers")
    if args.coverage and args.sanitizer == "memory":
        raise StatefulFuzzError("coverage is not combined with the MSan campaign")
    if not args.manifest_only and not args.sanitizers:
        raise StatefulFuzzError("campaign execution requires --sanitizers")
    if args.sanitizers and args.runs is None and args.seconds is None:
        args.runs = 1000
    return args


def main() -> int:
    args = parse_arguments()
    wrapper.validate_source_capsule()
    cases = generated_corpus()
    summary = validate_corpus_manifest(cases)
    if args.validate_retained_evidence is not None:
        print(
            json.dumps(
                validate_retained_evidence(
                    args.validate_retained_evidence,
                    expected_head=args.expected_retained_head,
                    expected_sanitizer=args.expected_retained_sanitizer,
                ),
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.manifest_only:
        print(
            "ML-DSA-44 stateful signer corpus OK: "
            f"{summary['total_cases']} cases, {summary['unique_frames']} unique frames"
        )
        return 0
    return run_campaign(args, cases, summary)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        StatefulFuzzError,
        verifier_fuzz.FuzzHarnessError,
        wrapper.HarnessError,
    ) as error:
        print(f"stateful signer fuzz: {error}", file=sys.stderr)
        raise SystemExit(1)
