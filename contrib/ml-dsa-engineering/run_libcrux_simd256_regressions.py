#!/usr/bin/env python3
"""Run exact, test-only libcrux ML-DSA-44 AVX2 advisory regressions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
SOURCE_MANIFEST = HERE / "fuzz_sources" / "wycheproof" / "SOURCE.json"
VECTOR_FILE = (
    HERE / "fuzz_sources" / "wycheproof" / "mldsa_44_verify_test.json"
)
HARNESS_SOURCE = HERE / "libcrux_simd256_regression.rs"

SOURCE_MANIFEST_SHA256 = (
    "3522cf3ae87aaa929f8d6b0e3be809665d809ce97b71cc01aa3256d7f2b0f1f2"
)
VECTOR_FILE_SHA256 = (
    "5ec04790c240c443ca8b662b8fc871834602c7cce87fcd36a193110745b2b9ea"
)
HARNESS_SOURCE_SHA256 = (
    "babe124c26ce5ea6d0056c6314bd0475e6f98004fa099fc679429db3fca53008"
)
CRATE_ARCHIVE_SHA256 = (
    "783ebed7cb27de6d44ef2aa662648d1a0869694f2f754f2f1ed45e959ef3b48e"
)
CRATE_NAME = "libcrux-ml-dsa"
CRATE_VERSION = "0.0.10"
CRATE_ROOT = f"{CRATE_NAME}-{CRATE_VERSION}"
CRATE_COMMIT = "c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd"
CRATE_CARGO_TOML_SHA256 = (
    "5796c72c70ced10baba72fdb0fa2345163a2ab628b2c04d89ef883ede90f44c1"
)
CRATE_CARGO_LOCK_SHA256 = (
    "10e6505cebc85f9cbf7836002fe5b3b1d9c6c7d84cfc6dd5b6e1f38ebbb6648d"
)
CRATE_VCS_INFO_SHA256 = (
    "52ea479dc21f621e72e8d0abd130f5e202eb6aa0797bc6e7504c7e771b8227c3"
)
CRATE_TREE_SHA256 = (
    "26b2206e58eb6cf4de2a49c3185a85c3961bf9b5b43cc020f63a1d1b92b75faa"
)
SOURCE_COMMIT = "fc24cd5b787d8e496bff31b0468af693a652b0f2"
TARGET_TRIPLE = "x86_64-unknown-linux-gnu"
RUST_TOOLCHAIN_VERSION = "1.89.0"
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_BYTES = re.compile(r"^(?:[0-9a-f]{2})*$")
LIBTEST_SUMMARY = re.compile(
    r"^test result: ok\. 1 passed; 0 failed; 0 ignored; "
    r"0 measured; \d+ filtered out; finished in .+$"
)
EVIDENCE_MARKER = ".pqbtc-simd256-evidence"
EVIDENCE_MARKER_CONTENT = "pqbtc-libcrux-simd256-regression-v1\n"

INVNTT_TESTS = (
    "simd::avx2::invntt::tests::inv_ntt_unreduced_max",
    "simd::avx2::invntt::tests::inv_ntt_reduced",
    "simd::avx2::invntt::tests::inv_ntt_reduced_large",
)
CASE_CONTRACTS = {
    147: {
        "comment": "signature that calls use_hint(1, 0)",
        "result": "valid",
        "flags": {
            "ValidSignature",
            "BoundaryCondition",
            "ZeroPublicKey",
        },
        "public_key_sha256": (
            "b07bcb1a9e37ac843cb678d6c3c57b960c2b0d2d5d02bc91f3b642258d75b50f"
        ),
        "message_sha256": (
            "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"
        ),
        "context_sha256": (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        "signature_sha256": (
            "5306515480c0f680da054413c248876024870eaccf8032703aaf06105c1a2191"
        ),
    },
    148: {
        "comment": "invalid signature that calls use_hint(1, 0)",
        "result": "invalid",
        "flags": {
            "InvalidSignature",
            "BoundaryCondition",
            "ZeroPublicKey",
        },
        "public_key_sha256": (
            "b07bcb1a9e37ac843cb678d6c3c57b960c2b0d2d5d02bc91f3b642258d75b50f"
        ),
        "message_sha256": (
            "64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"
        ),
        "context_sha256": (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        "signature_sha256": (
            "0642b1cb6f51243aa6292fc11caa41e6f21ac7072988b0fa939c5d73cfcc6629"
        ),
    },
}


class RegressionError(RuntimeError):
    """The exact SIMD256 regression contract was not satisfied."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise RegressionError(f"cannot read {path}: {exc}") from exc


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RegressionError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise RegressionError(f"non-finite JSON value: {value}")


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf8"),
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RegressionError) as exc:
        raise RegressionError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise RegressionError(f"{label} must be a JSON object")
    return value


def require_file_hash(path: Path, expected: str, label: str) -> None:
    actual = sha256_file(path)
    if actual != expected:
        raise RegressionError(
            f"{label} SHA256 mismatch: expected {expected}, got {actual}"
        )


def require_hex(
    value: object,
    *,
    exact_bytes: int | None,
    maximum_bytes: int | None,
    label: str,
) -> str:
    if not isinstance(value, str) or HEX_BYTES.fullmatch(value) is None:
        raise RegressionError(f"{label} must be lowercase even-length hex")
    byte_length = len(value) // 2
    if exact_bytes is not None and byte_length != exact_bytes:
        raise RegressionError(f"{label} must be exactly {exact_bytes} bytes")
    if maximum_bytes is not None and byte_length > maximum_bytes:
        raise RegressionError(f"{label} exceeds {maximum_bytes} bytes")
    return value


def load_wycheproof_cases(
    source_manifest_path: Path = SOURCE_MANIFEST,
    vector_file_path: Path = VECTOR_FILE,
) -> list[dict[str, Any]]:
    require_file_hash(
        source_manifest_path,
        SOURCE_MANIFEST_SHA256,
        "Wycheproof source manifest",
    )
    require_file_hash(vector_file_path, VECTOR_FILE_SHA256, "Wycheproof vector file")

    manifest = load_json_object(source_manifest_path, "Wycheproof source manifest")
    source = manifest.get("source")
    vector_record = manifest.get("vector_file")
    if not isinstance(source, dict) or not isinstance(vector_record, dict):
        raise RegressionError("Wycheproof source manifest records are missing")
    if source != {
        "commit": SOURCE_COMMIT,
        "imported": "2026-07-20",
        "license": "Apache-2.0",
        "repository": "https://github.com/C2SP/wycheproof",
    }:
        raise RegressionError("Wycheproof source identity drifted")
    expected_vector_record = {
        "algorithm": "ML-DSA-44",
        "generator_version": "1",
        "git_blob_sha1": "44f1c08df53338b7a9ffd9c2e123e82e1cfbfaea",
        "number_of_tests": 180,
        "sha256": VECTOR_FILE_SHA256,
        "size": 1081169,
        "upstream_path": "testvectors_v1/mldsa_44_verify_test.json",
    }
    if vector_record != expected_vector_record:
        raise RegressionError("Wycheproof vector manifest record drifted")

    document = load_json_object(vector_file_path, "Wycheproof vector file")
    if (
        document.get("algorithm") != "ML-DSA-44"
        or str(document.get("generatorVersion")) != "1"
        or document.get("numberOfTests") != 180
    ):
        raise RegressionError("Wycheproof vector metadata drifted")
    groups = document.get("testGroups")
    if not isinstance(groups, list):
        raise RegressionError("Wycheproof testGroups must be a list")

    indexed: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("tests"), list):
            raise RegressionError("Wycheproof test group is malformed")
        for case in group["tests"]:
            if not isinstance(case, dict):
                raise RegressionError("Wycheproof test case is malformed")
            test_case_id = case.get("tcId")
            if not isinstance(test_case_id, int) or test_case_id in indexed:
                raise RegressionError("Wycheproof test IDs are invalid or duplicated")
            indexed[test_case_id] = (group, case)
    if len(indexed) != 180:
        raise RegressionError("Wycheproof test inventory is not exactly 180 cases")

    selected: list[dict[str, Any]] = []
    for test_case_id, contract in CASE_CONTRACTS.items():
        if test_case_id not in indexed:
            raise RegressionError(f"Wycheproof tcId {test_case_id} is missing")
        group, case = indexed[test_case_id]
        if group.get("type") != "MlDsaVerify" or group.get("source") != {
            "name": "github/gendx",
            "version": "0.1",
        }:
            raise RegressionError(f"Wycheproof tcId {test_case_id} group drifted")
        flags = case.get("flags")
        if (
            case.get("comment") != contract["comment"]
            or case.get("result") != contract["result"]
            or not isinstance(flags, list)
            or len(flags) != len(set(flags))
            or set(flags) != contract["flags"]
        ):
            raise RegressionError(f"Wycheproof tcId {test_case_id} semantics drifted")

        public_key_hex = require_hex(
            group.get("publicKey"),
            exact_bytes=1312,
            maximum_bytes=None,
            label=f"tcId {test_case_id} public key",
        )
        message_hex = require_hex(
            case.get("msg"),
            exact_bytes=None,
            maximum_bytes=8192,
            label=f"tcId {test_case_id} message",
        )
        context_hex = require_hex(
            case.get("ctx") or "",
            exact_bytes=None,
            maximum_bytes=255,
            label=f"tcId {test_case_id} context",
        )
        signature_hex = require_hex(
            case.get("sig"),
            exact_bytes=2420,
            maximum_bytes=None,
            label=f"tcId {test_case_id} signature",
        )
        for field, value in (
            ("public_key_sha256", public_key_hex),
            ("message_sha256", message_hex),
            ("context_sha256", context_hex),
            ("signature_sha256", signature_hex),
        ):
            actual = sha256_bytes(bytes.fromhex(value))
            if actual != contract[field]:
                raise RegressionError(
                    f"Wycheproof tcId {test_case_id} {field} mismatch"
                )
        selected.append(
            {
                "test_case_id": test_case_id,
                "expected_valid": contract["result"] == "valid",
                "public_key_hex": public_key_hex,
                "message_hex": message_hex,
                "context_hex": context_hex,
                "signature_hex": signature_hex,
                "signature_sha256": contract["signature_sha256"],
            }
        )

    common_fields = ("public_key_hex", "message_hex", "context_hex")
    for field in common_fields:
        if len({str(case[field]) for case in selected}) != 1:
            raise RegressionError(f"Wycheproof tcIds 147/148 {field} mismatch")
    return selected


def classify_trust(event_name: str, ref: str) -> dict[str, Any]:
    if event_name == "pull_request":
        return {
            "label": "UNTRUSTED_PR_EVIDENCE",
            "scope": "pull_request_head_candidate",
            "may_report_pass": False,
            "eligible_for_ledger_promotion": False,
        }
    if event_name in {"push", "schedule", "workflow_dispatch"} and ref == (
        "refs/heads/main"
    ):
        return {
            "label": "TRUSTED_MAIN_EVIDENCE",
            "scope": "trusted_main",
            "may_report_pass": True,
            "eligible_for_ledger_promotion": True,
        }
    return {
        "label": "UNTRUSTED_NON_MAIN_EVIDENCE",
        "scope": "non_main_candidate",
        "may_report_pass": False,
        "eligible_for_ledger_promotion": False,
    }


def plan_document(cases: list[dict[str, Any]]) -> dict[str, Any]:
    require_file_hash(HARNESS_SOURCE, HARNESS_SOURCE_SHA256, "Rust regression harness")
    return {
        "schema_version": 1,
        "advisories": {
            "RUSTSEC-2026-0125": {
                "parameter_set": "ML-DSA-44",
                "test_case_ids": [case["test_case_id"] for case in cases],
                "expected_validity": {
                    str(case["test_case_id"]): case["expected_valid"] for case in cases
                },
                "called_backends": ["portable", "avx2"],
            },
            "RUSTSEC-2026-0126": {
                "upstream_libtest_paths": list(INVNTT_TESTS),
                "called_backends": ["portable", "avx2"],
            },
        },
        "source_contract": {
            "wycheproof_commit": SOURCE_COMMIT,
            "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
            "vector_file_sha256": VECTOR_FILE_SHA256,
            "crate": f"{CRATE_NAME} {CRATE_VERSION}",
            "crate_commit": CRATE_COMMIT,
            "crate_archive_sha256": CRATE_ARCHIVE_SHA256,
            "crate_cargo_toml_sha256": CRATE_CARGO_TOML_SHA256,
            "crate_cargo_lock_sha256": CRATE_CARGO_LOCK_SHA256,
            "crate_vcs_info_sha256": CRATE_VCS_INFO_SHA256,
            "crate_tree_sha256": CRATE_TREE_SHA256,
            "harness_sha256": HARNESS_SOURCE_SHA256,
        },
        "execution_contract": {
            "architecture": "x86_64",
            "required_cpu_feature": "avx2",
            "target_triple": TARGET_TRIPLE,
            "default_features": False,
            "features": ["mldsa44", "simd256", "std"],
            "compiled_backends": ["portable", "simd256"],
            "called_backends": ["portable", "avx2"],
            "required_environment": {
                "LIBCRUX_DISABLE_SIMD128": "1",
                "LIBCRUX_ENABLE_SIMD256": "1",
                "LIBCRUX_DISABLE_SIMD256": "UNSET",
            },
            "production_backend": "NONE",
            "simd256_admitted": False,
            "release_hold": True,
            "release_hold_changed": False,
            "rustsec_2026_0125_profile": "debug",
            "rustsec_2026_0126_profiles": ["debug", "release"],
        },
    }


def require_x86_64_avx2() -> dict[str, Any]:
    machine = os.uname().machine
    if machine != "x86_64":
        raise RegressionError(
            f"SIMD256 regression requires uname -m x86_64, got {machine}"
        )
    if not sys.platform.startswith("linux"):
        raise RegressionError(
            f"SIMD256 regression requires Linux /proc/cpuinfo, got {sys.platform}"
        )
    cpuinfo = Path("/proc/cpuinfo")
    try:
        cpuinfo_text = cpuinfo.read_text(encoding="utf8").lower()
    except OSError as exc:
        raise RegressionError(f"cannot read /proc/cpuinfo: {exc}") from exc
    flags = set()
    for line in cpuinfo_text.splitlines():
        if line.startswith(("flags", "features")) and ":" in line:
            flags.update(line.split(":", 1)[1].split())
    if "avx2" not in flags:
        raise RegressionError("SIMD256 regression requires the AVX2 CPU flag")
    return {
        "uname_machine": machine,
        "platform_machine": platform.machine().lower(),
        "avx2": "present",
        "cpu_flags": sorted(flags),
        "cpuinfo_sha256": sha256_bytes(cpuinfo_text.encode("utf8")),
    }


def _safe_member_path(member_name: str) -> PurePosixPath:
    path = PurePosixPath(member_name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise RegressionError(f"unsafe crate archive member path: {member_name}")
    if path.parts[0] != CRATE_ROOT:
        raise RegressionError(f"unexpected crate archive root: {member_name}")
    return path


def make_tree_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_symlink():
            raise RegressionError(f"crate source contains a symlink: {path}")
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    root.chmod(root.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))


def require_tree_read_only(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        if path.is_symlink():
            raise RegressionError(f"crate source contains a symlink: {path}")
        if path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise RegressionError(f"crate source is writable: {path}")


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RegressionError(f"crate source contains a symlink: {path}")
        relative = path.relative_to(root).as_posix().encode("utf8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        kind = b"d" if path.is_dir() else b"f"
        digest.update(kind)
        if path.is_file():
            content = path.read_bytes()
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
    return digest.hexdigest()


def extract_verified_crate(archive: Path, destination: Path) -> Path:
    if archive.is_symlink() or not archive.is_file():
        raise RegressionError("libcrux crate archive must be a regular file")
    require_file_hash(archive, CRATE_ARCHIVE_SHA256, "libcrux crate archive")
    archive.chmod(archive.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            members = bundle.getmembers()
            if not members:
                raise RegressionError("libcrux crate archive is empty")
            for member in members:
                _safe_member_path(member.name)
                if not (member.isfile() or member.isdir()):
                    raise RegressionError(
                        f"unsupported crate archive member type: {member.name}"
                    )
            bundle.extractall(destination, members=members, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise RegressionError(f"cannot extract libcrux crate archive: {exc}") from exc
    crate_dir = destination / CRATE_ROOT
    if not (crate_dir / "Cargo.toml").is_file() or not (
        crate_dir / "Cargo.lock"
    ).is_file():
        raise RegressionError("libcrux crate is missing Cargo.toml or Cargo.lock")
    require_file_hash(
        crate_dir / "Cargo.toml",
        CRATE_CARGO_TOML_SHA256,
        "libcrux Cargo.toml",
    )
    require_file_hash(
        crate_dir / "Cargo.lock",
        CRATE_CARGO_LOCK_SHA256,
        "libcrux Cargo.lock",
    )
    vcs_info_path = crate_dir / ".cargo_vcs_info.json"
    require_file_hash(vcs_info_path, CRATE_VCS_INFO_SHA256, "libcrux VCS metadata")
    vcs_info = load_json_object(vcs_info_path, "libcrux VCS metadata")
    if vcs_info != {
        "git": {"sha1": CRATE_COMMIT},
        "path_in_vcs": "libcrux-ml-dsa",
    }:
        raise RegressionError("libcrux VCS identity drifted")
    make_tree_read_only(crate_dir)
    require_tree_read_only(crate_dir)
    return crate_dir


def regression_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["LIBCRUX_DISABLE_SIMD128"] = "1"
    environment["LIBCRUX_ENABLE_SIMD256"] = "1"
    environment.pop("LIBCRUX_DISABLE_SIMD256", None)
    environment["CARGO_TERM_COLOR"] = "never"
    return environment


def run_command(
    arguments: list[str],
    *,
    environment: dict[str, str],
    log_path: Path,
    timeout_seconds: int,
) -> str:
    if not arguments or any(not isinstance(argument, str) for argument in arguments):
        raise RegressionError("subprocess arguments must be a fixed string list")
    try:
        completed = subprocess.run(
            arguments,
            cwd=REPO_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        captured = exc.stdout or b""
        if isinstance(captured, str):
            captured = captured.encode("utf8", errors="replace")
        log_path.write_bytes(captured)
        raise RegressionError(
            f"{arguments[0]} exceeded {timeout_seconds} seconds; "
            f"see {log_path.name}"
        ) from exc
    except OSError as exc:
        raise RegressionError(f"cannot execute {arguments[0]}: {exc}") from exc
    log_path.write_bytes(completed.stdout)
    if completed.returncode != 0:
        raise RegressionError(
            f"{arguments[0]} exited {completed.returncode}; see {log_path.name}"
        )
    return completed.stdout.decode("utf8", errors="replace")


def require_tool_version(output: str, tool: str) -> str:
    lines = output.splitlines()
    if not lines:
        raise RegressionError(f"{tool} version output is empty")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != tool or fields[1] != RUST_TOOLCHAIN_VERSION:
        raise RegressionError(
            f"{tool} version drifted; expected {RUST_TOOLCHAIN_VERSION}"
        )
    return output.strip()


def require_exact_libtest_success(output: str, test_name: str) -> None:
    lines = [line.strip() for line in output.splitlines()]
    if lines.count("running 1 test") != 1:
        raise RegressionError(
            f"{test_name} did not select exactly one libtest"
        )
    if lines.count(f"test {test_name} ... ok") != 1:
        raise RegressionError(f"{test_name} did not run and pass exactly once")
    summaries = [line for line in lines if line.startswith("test result:")]
    if len(summaries) != 1 or LIBTEST_SUMMARY.fullmatch(summaries[0]) is None:
        raise RegressionError(f"{test_name} libtest summary drifted")


def require_repository_state(
    git: str,
    repository_commit: str,
    *,
    environment: dict[str, str],
    output_dir: Path,
    phase: str,
) -> dict[str, Any]:
    head = run_command(
        [git, "rev-parse", "HEAD"],
        environment=environment,
        log_path=output_dir / f"git-head-{phase}.log",
        timeout_seconds=30,
    ).strip()
    if head != repository_commit:
        raise RegressionError(
            f"repository HEAD drifted during {phase}: expected "
            f"{repository_commit}, got {head}"
        )
    status = run_command(
        [git, "status", "--porcelain=v1", "--untracked-files=all"],
        environment=environment,
        log_path=output_dir / f"git-status-{phase}.log",
        timeout_seconds=30,
    )
    if status:
        raise RegressionError(f"repository is dirty during {phase}")
    return {
        "head": head,
        "clean": True,
    }


def find_built_library(target_dir: Path) -> Path:
    dependencies = target_dir / TARGET_TRIPLE / "debug" / "deps"
    candidates = sorted(dependencies.glob("liblibcrux_ml_dsa-*.rlib"))
    if len(candidates) != 1:
        raise RegressionError(
            f"expected exactly one libcrux ML-DSA rlib, found {len(candidates)}"
        )
    return candidates[0]


def rustc_dependency_arguments(target_dir: Path) -> list[str]:
    target_dependencies = target_dir / TARGET_TRIPLE / "debug" / "deps"
    host_dependencies = target_dir / "debug" / "deps"
    for label, path in (
        ("target", target_dependencies),
        ("host", host_dependencies),
    ):
        if path.is_symlink() or not path.is_dir():
            raise RegressionError(
                f"{label} dependency directory is missing or unsafe"
            )
    return [
        "-L",
        f"dependency={target_dependencies}",
        "-L",
        f"dependency={host_dependencies}",
    ]


def write_checksums(output_dir: Path) -> None:
    rows = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_symlink():
            raise RegressionError(f"evidence contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RegressionError(f"evidence contains a special file: {path}")
        if path.name != "SHA256SUMS":
            rows.append(
                f"{sha256_file(path)}  {path.relative_to(output_dir).as_posix()}"
            )
    (output_dir / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf8")


def require_owned_output_directory(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise RegressionError("evidence output directory must not be a symlink")
    if not output_dir.is_dir():
        raise RegressionError("evidence output path must be a directory")
    marker = output_dir / EVIDENCE_MARKER
    if (
        not marker.is_file()
        or marker.is_symlink()
        or marker.read_text(encoding="utf8") != EVIDENCE_MARKER_CONTENT
    ):
        raise RegressionError("evidence output directory is not owned by this run")
    for path in output_dir.rglob("*"):
        if path.is_symlink():
            raise RegressionError(f"evidence contains a symlink: {path}")
        if not (path.is_file() or path.is_dir()):
            raise RegressionError(f"evidence contains a special file: {path}")


def claim_output_directory(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise RegressionError("evidence output directory must not be a symlink")
    if output_dir.exists() and not output_dir.is_dir():
        raise RegressionError("evidence output path must be a directory")
    output_dir.mkdir(parents=True, exist_ok=True)
    entries = list(output_dir.iterdir())
    marker = output_dir / EVIDENCE_MARKER
    if not entries:
        marker.write_text(EVIDENCE_MARKER_CONTENT, encoding="utf8")
        return
    require_owned_output_directory(output_dir)
    if entries != [marker]:
        raise RegressionError("evidence output directory contains stale files")


def execute(
    *,
    archive: Path,
    output_dir: Path,
    event_name: str,
    ref: str,
    repository_commit: str,
    run_id: str,
    run_attempt: str,
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    if HEX_40.fullmatch(repository_commit) is None:
        raise RegressionError("repository commit must be lowercase 40-byte hex")
    if not run_id.isdigit() or int(run_id) < 1:
        raise RegressionError("workflow run ID must be a positive integer")
    if not run_attempt.isdigit() or int(run_attempt) < 1:
        raise RegressionError("workflow run attempt must be a positive integer")
    claim_output_directory(output_dir)

    plan = plan_document(cases)
    trust = classify_trust(event_name, ref)
    preflight = require_x86_64_avx2()
    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    git = shutil.which("git")
    if cargo is None or rustc is None or git is None:
        raise RegressionError("cargo, rustc, and git are required")
    environment = regression_environment()
    cargo_version = require_tool_version(
        run_command(
            [cargo, "--version", "--verbose"],
            environment=environment,
            log_path=output_dir / "cargo-version.log",
            timeout_seconds=30,
        ),
        "cargo",
    )
    rustc_version = require_tool_version(
        run_command(
            [rustc, "--version", "--verbose"],
            environment=environment,
            log_path=output_dir / "rustc-version.log",
            timeout_seconds=30,
        ),
        "rustc",
    )
    repository_before = require_repository_state(
        git,
        repository_commit,
        environment=environment,
        output_dir=output_dir,
        phase="before",
    )
    (output_dir / "toolchain.txt").write_text(
        f"cargo={cargo_version}\n"
        f"rustc={rustc_version}\n"
        f"uname_machine={preflight['uname_machine']}\n"
        f"target={TARGET_TRIPLE}\n",
        encoding="utf8",
    )

    with tempfile.TemporaryDirectory(prefix="pqbtc-libcrux-simd256-") as temporary:
        work_root = Path(temporary)
        crate_dir = extract_verified_crate(archive, work_root / "source")
        source_digest_before = tree_digest(crate_dir)
        if source_digest_before != CRATE_TREE_SHA256:
            raise RegressionError("verified libcrux crate tree digest drifted")
        cargo_toml_sha256 = sha256_file(crate_dir / "Cargo.toml")
        cargo_lock_sha256 = sha256_file(crate_dir / "Cargo.lock")
        target_dir = work_root / "target"

        cargo_build = [
            cargo,
            "build",
            "--manifest-path",
            str(crate_dir / "Cargo.toml"),
            "--target",
            TARGET_TRIPLE,
            "--target-dir",
            str(target_dir),
            "--locked",
            "--no-default-features",
            "--features",
            "std,mldsa44,simd256",
            "--lib",
        ]
        run_command(
            cargo_build,
            environment=environment,
            log_path=output_dir / "cargo-build.log",
            timeout_seconds=900,
        )

        library = find_built_library(target_dir)
        harness_binary = work_root / "pqbtc-libcrux-simd256-regression"
        rustc_build = [
            rustc,
            str(HARNESS_SOURCE),
            "--edition=2021",
            "--target",
            TARGET_TRIPLE,
            "--crate-name",
            "pqbtc_libcrux_simd256_regression",
            *rustc_dependency_arguments(target_dir),
            "--extern",
            f"libcrux_ml_dsa={library}",
            "-o",
            str(harness_binary),
        ]
        run_command(
            rustc_build,
            environment=environment,
            log_path=output_dir / "rustc-harness.log",
            timeout_seconds=120,
        )
        if not harness_binary.is_file():
            raise RegressionError("rustc did not produce the SIMD256 harness")

        valid_case, invalid_case = cases
        harness_arguments = [
            str(harness_binary),
            str(valid_case["public_key_hex"]),
            str(valid_case["message_hex"]),
            str(valid_case["context_hex"]),
            str(valid_case["signature_hex"]),
            str(invalid_case["signature_hex"]),
        ]
        harness_output = run_command(
            harness_arguments,
            environment=environment,
            log_path=output_dir / "rustsec-2026-0125.log",
            timeout_seconds=120,
        )
        observations = [
            line.strip()
            for line in harness_output.splitlines()
            if line.startswith("tcId=")
        ]
        expected_observations = [
            "tcId=147 portable=1 avx2=1 expected=1",
            "tcId=148 portable=0 avx2=0 expected=0",
        ]
        if observations != expected_observations:
            raise RegressionError(
                "RUSTSEC-2026-0125 harness observations were incomplete or drifted"
            )

        for profile_name, profile_arguments in (
            ("debug", []),
            ("release", ["--release"]),
        ):
            for index, test_name in enumerate(INVNTT_TESTS, start=1):
                cargo_test = [
                    cargo,
                    "test",
                    "--manifest-path",
                    str(crate_dir / "Cargo.toml"),
                    "--target",
                    TARGET_TRIPLE,
                    "--target-dir",
                    str(target_dir),
                    "--locked",
                    "--no-default-features",
                    "--features",
                    "std,mldsa44,simd256",
                    *profile_arguments,
                    "--lib",
                    test_name,
                    "--",
                    "--exact",
                ]
                libtest_output = run_command(
                    cargo_test,
                    environment=environment,
                    log_path=(
                        output_dir
                        / f"rustsec-2026-0126-{profile_name}-{index}.log"
                    ),
                    timeout_seconds=300,
                )
                require_exact_libtest_success(libtest_output, test_name)

        require_tree_read_only(crate_dir)
        source_digest_after = tree_digest(crate_dir)
        if source_digest_after != source_digest_before:
            raise RegressionError("verified libcrux crate source changed during tests")

    repository_after = require_repository_state(
        git,
        repository_commit,
        environment=environment,
        output_dir=output_dir,
        phase="after",
    )
    report = {
        **plan,
        "status": "PASS" if trust["may_report_pass"] else "UNTESTED",
        "trust": {
            "event_name": event_name,
            "ref": ref,
            **trust,
        },
        "repository_commit": repository_commit,
        "workflow_run": {
            "id": run_id,
            "attempt": run_attempt,
        },
        "preflight": preflight,
        "toolchain": {
            "cargo": cargo_version,
            "rustc": rustc_version,
            "pinned_version": RUST_TOOLCHAIN_VERSION,
        },
        "repository_state": {
            "before": repository_before,
            "after": repository_after,
        },
        "crate_source": {
            "archive_sha256": CRATE_ARCHIVE_SHA256,
            "commit": CRATE_COMMIT,
            "cargo_toml_original_sha256": cargo_toml_sha256,
            "cargo_toml_prepared_sha256": cargo_toml_sha256,
            "cargo_lock_sha256": cargo_lock_sha256,
            "manifest_preparation": "NONE",
            "read_only": True,
            "unchanged": True,
            "tree_sha256": source_digest_after,
        },
        "results": {
            "RUSTSEC-2026-0125": {
                "status": (
                    "PASS"
                    if trust["may_report_pass"]
                    else "UNTRUSTED_OBSERVATION"
                ),
                "test_case_ids": [147, 148],
                "portable_results": {"147": "valid", "148": "invalid"},
                "avx2_results": {"147": "valid", "148": "invalid"},
                "observations": observations,
                "profile": "debug",
                "cases": [
                    {
                        "test_case_id": case["test_case_id"],
                        "expected_valid": case["expected_valid"],
                        "flags": sorted(CASE_CONTRACTS[case["test_case_id"]]["flags"]),
                        "public_key_sha256": CASE_CONTRACTS[case["test_case_id"]][
                            "public_key_sha256"
                        ],
                        "message_sha256": CASE_CONTRACTS[case["test_case_id"]][
                            "message_sha256"
                        ],
                        "context_sha256": CASE_CONTRACTS[case["test_case_id"]][
                            "context_sha256"
                        ],
                        "signature_sha256": case["signature_sha256"],
                    }
                    for case in cases
                ],
            },
            "RUSTSEC-2026-0126": {
                "status": (
                    "PASS"
                    if trust["may_report_pass"]
                    else "UNTRUSTED_OBSERVATION"
                ),
                "upstream_libtest_paths": list(INVNTT_TESTS),
                "profiles": ["debug", "release"],
            },
        },
        "checked_in_ledger_updated": False,
    }
    (output_dir / "simd256-regression-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf8",
    )
    write_checksums(output_dir)
    return report


def failure_report(
    *,
    output_dir: Path,
    event_name: str,
    ref: str,
    repository_commit: str,
    run_id: str,
    run_attempt: str,
    error: Exception,
) -> None:
    try:
        require_owned_output_directory(output_dir)
    except (OSError, UnicodeError, RegressionError):
        return
    trust = classify_trust(event_name, ref)
    failure_trust = {
        **trust,
        "may_report_pass": False,
        "eligible_for_ledger_promotion": False,
        "actual_pass_capable": False,
    }
    report = {
        "schema_version": 1,
        "status": "FAIL",
        "trust": {
            "event_name": event_name,
            "ref": ref,
            **failure_trust,
        },
        "repository_commit": repository_commit,
        "workflow_run": {
            "id": run_id,
            "attempt": run_attempt,
        },
        "error": str(error),
        "execution_contract": {
            "production_backend": "NONE",
            "simd256_admitted": False,
            "release_hold": True,
            "release_hold_changed": False,
        },
        "checked_in_ledger_updated": False,
    }
    (output_dir / "simd256-regression-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf8",
    )
    write_checksums(output_dir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--crate-archive", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--event-name",
        choices=("pull_request", "push", "schedule", "workflow_dispatch"),
    )
    parser.add_argument("--ref")
    parser.add_argument("--repository-commit")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    output_path = (
        Path(os.path.abspath(arguments.output_dir))
        if arguments.output_dir is not None
        else None
    )
    output_claimed = False
    try:
        if not arguments.plan_only and output_path is not None:
            claim_output_directory(output_path)
            output_claimed = True
        cases = load_wycheproof_cases()
        if arguments.plan_only:
            if any(
                value is not None
                for value in (
                    arguments.crate_archive,
                    arguments.output_dir,
                    arguments.event_name,
                    arguments.ref,
                    arguments.repository_commit,
                    arguments.run_id,
                    arguments.run_attempt,
                )
            ):
                raise RegressionError("--plan-only does not accept execution inputs")
            print(json.dumps(plan_document(cases), indent=2, sort_keys=True))
            return 0
        if any(
            value is None
            for value in (
                arguments.crate_archive,
                arguments.output_dir,
                arguments.event_name,
                arguments.ref,
                arguments.repository_commit,
                arguments.run_id,
                arguments.run_attempt,
            )
        ):
            raise RegressionError(
                "execution requires --crate-archive, --output-dir, "
                "--event-name, --ref, --repository-commit, --run-id, "
                "and --run-attempt"
            )
        execute(
            archive=Path(os.path.abspath(arguments.crate_archive)),
            output_dir=output_path,
            event_name=arguments.event_name,
            ref=arguments.ref,
            repository_commit=arguments.repository_commit,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            cases=cases,
        )
        return 0
    except RegressionError as exc:
        if (
            not arguments.plan_only
            and output_path is not None
            and output_claimed
            and arguments.event_name is not None
            and arguments.ref is not None
        ):
            failure_report(
                output_dir=output_path,
                event_name=arguments.event_name,
                ref=arguments.ref,
                repository_commit=arguments.repository_commit or "UNKNOWN",
                run_id=arguments.run_id or "UNKNOWN",
                run_attempt=arguments.run_attempt or "UNKNOWN",
                error=exc,
            )
        print(f"run_libcrux_simd256_regressions.py: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
