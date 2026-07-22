#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Fuzz the isolated verifier against pinned OpenSSL and libcrux oracles."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import run_verifier_fuzz as verifier_fuzz


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
REFERENCE_DIR = REPO_ROOT / "contrib" / "ml-dsa-ref"


def load_reference_module():
    spec = importlib.util.spec_from_file_location(
        "compare_ml_dsa_oracles", REFERENCE_DIR / "compare_oracles.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the frozen ML-DSA comparator module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reference = load_reference_module()


OPENSSL_BRIDGE = HERE / "pqbtc_mldsa44_openssl_verify.c"
LIBCRUX_BRIDGE = HERE / "pqbtc_mldsa44_libcrux_verify.rs"
DIFFERENTIAL_HEADER = HERE / "pqbtc_mldsa44_differential.h"
DIFFERENTIAL_REPLAY = HERE / "pqbtc_mldsa44_differential_replay.c"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-review-reproduction.yml"
SANITIZER = "address-undefined"
MAX_CAMPAIGN_SECONDS = 1800
SMOKE_CASE_NAMES = (
    "valid_frozen_vector",
    "valid_empty_message_context",
    "reject_ctilde_bit_flip",
    "reject_hint_counter_overflow",
    "reject_null_signature",
)


class DifferentialFuzzError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command_identity(command: str) -> str:
    try:
        completed = subprocess.run(
            [command, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as error:
        return f"unavailable: {error}"
    return completed.stdout.splitlines()[0] if completed.stdout else command


def validate_local_inputs(manifest: dict) -> dict:
    expected_files = (
        Path(__file__).resolve(),
        REFERENCE_DIR / "compare_oracles.py",
        REFERENCE_DIR / "libcrux_oracle.rs",
        reference.MANIFEST_PATH,
        DIFFERENTIAL_HEADER,
        DIFFERENTIAL_REPLAY,
        OPENSSL_BRIDGE,
        LIBCRUX_BRIDGE,
        HERE / "pqbtc_mldsa44.h",
        HERE / "pqbtc_mldsa44_config.h",
        verifier_fuzz.FUZZ_SOURCE,
        verifier_fuzz.CORPUS_MANIFEST,
        verifier_fuzz.WYCHEPROOF_SOURCE,
        verifier_fuzz.WYCHEPROOF_LICENSE,
        verifier_fuzz.WYCHEPROOF_VECTORS,
        verifier_fuzz.wrapper.VECTORS,
        verifier_fuzz.wrapper.SOURCE_MANIFEST,
        verifier_fuzz.wrapper.WRAPPER_SOURCE,
        HERE / "run_verifier_fuzz.py",
        HERE / "run_wrapper_tests.py",
        WORKFLOW,
    )
    missing = [str(path.relative_to(REPO_ROOT)) for path in expected_files if not path.is_file()]
    if missing:
        raise DifferentialFuzzError(f"missing differential fuzz inputs: {missing}")
    if manifest["sources"]["openssl"]["version"] != "3.6.3":
        raise DifferentialFuzzError("differential fuzzing requires OpenSSL 3.6.3")
    if manifest["sources"]["libcrux"]["version"] != "0.0.10":
        raise DifferentialFuzzError("differential fuzzing requires libcrux 0.0.10")
    return {
        str(path.relative_to(REPO_ROOT)): sha256_file(path) for path in expected_files
    }


def git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def git_input_status(source_hashes: dict) -> list[str] | None:
    completed = subprocess.run(
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            *source_hashes,
        ],
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.splitlines()


def openssl_runtime_provenance(executable: Path) -> dict:
    if sys.platform.startswith("linux"):
        dependency_command = ["ldd", str(executable)]
        dependency_pattern = re.compile(r"\blibcrypto\.so(?:\.\d+)*\s+=>\s+(\S+)")
    elif sys.platform == "darwin":
        dependency_command = ["otool", "-L", str(executable)]
        dependency_pattern = re.compile(r"^\s*(\S*libcrypto[^\s]*\.dylib)", re.MULTILINE)
    else:
        raise DifferentialFuzzError(
            "OpenSSL runtime provenance supports Linux and macOS only"
        )

    dependencies = reference.run(dependency_command).strip()
    match = dependency_pattern.search(dependencies)
    linked_path = Path(match.group(1)).resolve() if match is not None else None
    libdir = Path(
        reference.run(["pkg-config", "--variable=libdir", "openssl"]).strip()
    ).resolve()
    if linked_path is None or not linked_path.is_file():
        raise DifferentialFuzzError(
            "cannot resolve the linked OpenSSL libcrypto binary"
        )
    resolution = "linked-dependency"
    try:
        linked_path.relative_to(libdir)
    except ValueError as error:
        raise DifferentialFuzzError(
            f"linked libcrypto is outside the pkg-config libdir: {linked_path}"
        ) from error

    return {
        "cli_version_a": reference.run(["openssl", "version", "-a"]).strip(),
        "provider_inventory": reference.run(
            ["openssl", "list", "-providers", "-verbose"]
        ).strip(),
        "pkg_config_version": reference.run(
            ["pkg-config", "--modversion", "openssl"]
        ).strip(),
        "pkg_config_prefix": reference.run(
            ["pkg-config", "--variable=prefix", "openssl"]
        ).strip(),
        "pkg_config_libdir": str(libdir),
        "dependency_command": dependency_command,
        "dependency_report": dependencies,
        "libcrypto_path": str(linked_path),
        "libcrypto_resolution": resolution,
        "libcrypto_sha256": sha256_file(linked_path),
        "openssl_modules": os.environ.get("OPENSSL_MODULES"),
        "openssl_conf": os.environ.get("OPENSSL_CONF"),
    }


def compile_libcrux_bridge(build_dir: Path, crate_dir: Path) -> tuple[Path, Path]:
    reference.compile_libcrux_oracle(build_dir, crate_dir)
    dependency_dir = build_dir / "libcrux-target" / "release" / "deps"
    candidates = sorted(dependency_dir.glob("liblibcrux_ml_dsa-*.rlib"))
    if len(candidates) != 1:
        raise DifferentialFuzzError(
            "expected exactly one release libcrux ML-DSA rlib, got "
            f"{len(candidates)}"
        )
    rlib = candidates[0]
    if sys.platform.startswith("linux"):
        extension = ".so"
    elif sys.platform == "darwin":
        extension = ".dylib"
    else:
        raise DifferentialFuzzError(
            "differential verifier fuzzing supports Linux and macOS only"
        )
    output = build_dir / f"libpqbtc_mldsa44_libcrux_verify{extension}"
    reference.run(
        [
            "rustc",
            "--edition=2021",
            "--crate-type=cdylib",
            "-C",
            "opt-level=3",
            "-C",
            "panic=abort",
            "-L",
            f"dependency={dependency_dir}",
            "--extern",
            f"libcrux_ml_dsa={rlib}",
            str(LIBCRUX_BRIDGE),
            "-o",
            str(output),
        ]
    )
    if not output.is_file():
        raise DifferentialFuzzError(
            "rustc did not produce the libcrux differential bridge"
        )
    return output, rlib


def differential_link_args(
    libcrux_bridge: Path, expected_openssl_version: str
) -> tuple[str, ...]:
    reference.openssl_version(expected_openssl_version)
    openssl_flags = shlex.split(
        reference.run(["pkg-config", "--cflags", "--libs", "openssl"])
    )
    return (
        str(libcrux_bridge),
        f"-Wl,-rpath,{libcrux_bridge.parent}",
        *openssl_flags,
    )


def compile_differential_targets(
    build_dir: Path,
    libcrux_bridge: Path,
    expected_openssl_version: str,
) -> tuple[Path, Path, str]:
    compiler = os.environ.get("FUZZ_CC", "clang")
    if shutil.which(compiler) is None:
        raise DifferentialFuzzError(f"differential fuzz compiler not found: {compiler}")
    link_args = differential_link_args(libcrux_bridge, expected_openssl_version)
    try:
        fuzzer = verifier_fuzz.compile_fuzzer(
            compiler,
            build_dir,
            sanitizer=SANITIZER,
            coverage=True,
            differential_sources=(OPENSSL_BRIDGE,),
            differential_link_args=link_args,
        )
        replay = build_dir / "pqbtc_mldsa44_differential_replay"
        replay_command = verifier_fuzz.wrapper.common_flags(compiler)
        replay_command.extend(
            [
                "-O1",
                "-g",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                "-fsanitize=address,undefined",
                "-fprofile-instr-generate",
                "-fcoverage-mapping",
                "-DPQBTC_MLDSA44_DIFFERENTIAL=1",
                str(verifier_fuzz.wrapper.WRAPPER_SOURCE),
                str(verifier_fuzz.FUZZ_SOURCE),
                str(OPENSSL_BRIDGE),
                str(DIFFERENTIAL_REPLAY),
                "-o",
                str(replay),
                *link_args,
            ]
        )
        verifier_fuzz.wrapper.run(replay_command)
    except (
        OSError,
        verifier_fuzz.FuzzHarnessError,
        verifier_fuzz.wrapper.HarnessError,
    ) as error:
        raise DifferentialFuzzError(
            f"differential target compilation failed: {error}"
        ) from error
    return fuzzer, replay, compiler


def replay_differential_smoke(
    executable: Path,
    cases: list[verifier_fuzz.CorpusCase],
    output_dir: Path,
) -> list[dict]:
    selected_by_name = {case.name: case for case in cases if case.source == "project"}
    if set(SMOKE_CASE_NAMES) - selected_by_name.keys():
        raise DifferentialFuzzError("differential smoke corpus is incomplete")
    smoke_dir = output_dir / "differential-smoke-inputs"
    smoke_dir.mkdir()
    records = []
    log_parts = []
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = (
        "detect_leaks=0" if sys.platform == "darwin" else "detect_leaks=1"
    )
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    env["LLVM_PROFILE_FILE"] = str(output_dir / "coverage-replay-%p.profraw")
    for index, name in enumerate(SMOKE_CASE_NAMES):
        case = selected_by_name[name]
        path = smoke_dir / f"{index:02d}-{name}"
        path.write_bytes(case.frame)
        record = {
            "name": name,
            "source": case.source,
            "frame_sha256": hashlib.sha256(case.frame).hexdigest(),
            "expected": "accept" if case.expected == verifier_fuzz.OK else "reject",
        }
        command = [str(executable), str(path)]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                timeout=30,
            )
            record["return_code"] = completed.returncode
            record["status"] = "pass" if completed.returncode == 0 else "fail"
            record["error"] = None
            stdout = completed.stdout
            stderr = completed.stderr
        except subprocess.TimeoutExpired as error:
            record["return_code"] = 124
            record["status"] = "fail"
            record["error"] = "exact replay exceeded 30 seconds"
            stdout = verifier_fuzz.captured_output(error.stdout)
            stderr = verifier_fuzz.captured_output(error.stderr)
        records.append(record)
        log_parts.append(
            f"case: {name}\ncommand: {shlex.join(command)}\n"
            f"status: {record['status']}\nreturn_code: {record['return_code']}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}\n"
        )
    (output_dir / "differential-smoke.log").write_text(
        "\n".join(log_parts),
        encoding="utf8",
    )
    return records


def filesystem_identity(status: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
    )


def open_corpus_directory(path: Path, label: str) -> int:
    try:
        expected = path.lstat()
    except FileNotFoundError as error:
        raise DifferentialFuzzError(f"{label} does not exist: {path}") from error
    if stat.S_ISLNK(expected.st_mode):
        raise DifferentialFuzzError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISDIR(expected.st_mode):
        raise DifferentialFuzzError(f"{label} is not a directory: {path}")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DifferentialFuzzError(f"cannot open {label}: {path}: {error}") from error
    actual = os.fstat(descriptor)
    if filesystem_identity(actual) != filesystem_identity(expected):
        os.close(descriptor)
        raise DifferentialFuzzError(f"{label} changed during import: {path}")
    return descriptor


def read_corpus_file(
    directory_descriptor: int,
    name: str,
    display_path: Path,
    label: str,
) -> bytes:
    try:
        expected = os.stat(
            name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise DifferentialFuzzError(
            f"cannot inspect {label}: {display_path}: {error}"
        ) from error
    if stat.S_ISLNK(expected.st_mode):
        raise DifferentialFuzzError(f"{label} must not be a symlink: {display_path}")
    if not stat.S_ISREG(expected.st_mode):
        raise DifferentialFuzzError(f"{label} is not a regular file: {display_path}")
    if expected.st_size > verifier_fuzz.MAX_FRAME_BYTES:
        raise DifferentialFuzzError(f"{label} exceeds fuzz bound: {display_path}")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise DifferentialFuzzError(
            f"cannot open {label}: {display_path}: {error}"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if filesystem_identity(opened) != filesystem_identity(expected):
            raise DifferentialFuzzError(
                f"{label} changed during import: {display_path}"
            )
        remaining = verifier_fuzz.MAX_FRAME_BYTES + 1
        chunks = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > verifier_fuzz.MAX_FRAME_BYTES:
        raise DifferentialFuzzError(f"{label} exceeds fuzz bound: {display_path}")
    if (
        filesystem_identity(after) != filesystem_identity(opened)
        or len(data) != opened.st_size
    ):
        raise DifferentialFuzzError(f"{label} changed during import: {display_path}")
    return data


def import_seed_corpus(source: Path, destination: Path) -> int:
    """Import a flat retained corpus without trusting its filesystem layout."""
    source_descriptor = open_corpus_directory(source, "seed corpus")
    try:
        candidates = []
        with os.scandir(source_descriptor) as entries:
            for entry in entries:
                candidates.append(entry.name)
                if len(candidates) > verifier_fuzz.MAX_RETAINED_CORPUS_FILES:
                    raise DifferentialFuzzError(
                        "retained corpus exceeds the file-count bound"
                    )
        candidates.sort()

        retained: dict[str, bytes] = {}
        total_bytes = 0
        for name in candidates:
            path = source / name
            data = read_corpus_file(
                source_descriptor,
                name,
                path,
                "retained corpus input",
            )
            total_bytes += len(data)
            if total_bytes > verifier_fuzz.MAX_RETAINED_CORPUS_BYTES:
                raise DifferentialFuzzError(
                    "retained corpus exceeds the aggregate byte bound"
                )
            digest = hashlib.sha256(data).hexdigest()
            previous = retained.setdefault(digest, data)
            if previous != data:
                raise DifferentialFuzzError(
                    f"retained corpus SHA256 collision detected: {path}"
                )
    finally:
        os.close(source_descriptor)

    destination_status = destination.lstat()
    if stat.S_ISLNK(destination_status.st_mode) or not stat.S_ISDIR(
        destination_status.st_mode
    ):
        raise DifferentialFuzzError(
            f"working corpus is not a regular directory: {destination}"
        )

    destination_contents: dict[str, bytes] = {}
    for path in sorted(destination.iterdir(), key=lambda item: item.name):
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise DifferentialFuzzError(
                f"working corpus input is not a regular file: {path}"
            )
        if before.st_size > verifier_fuzz.MAX_FRAME_BYTES:
            raise DifferentialFuzzError(
                f"working corpus input exceeds fuzz bound: {path}"
            )
        data = path.read_bytes()
        after = path.lstat()
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_after != identity_before or len(data) != before.st_size:
            raise DifferentialFuzzError(
                f"working corpus input changed during import: {path}"
            )
        digest = hashlib.sha256(data).hexdigest()
        previous = destination_contents.setdefault(digest, data)
        if previous != data:
            raise DifferentialFuzzError(
                f"working corpus SHA256 collision detected: {path}"
            )

    imported = 0
    for digest, data in retained.items():
        target = destination / f"retained_{digest}.bin"
        if target.exists() or target.is_symlink():
            target_status = target.lstat()
            if stat.S_ISLNK(target_status.st_mode) or not stat.S_ISREG(
                target_status.st_mode
            ):
                raise DifferentialFuzzError(
                    f"retained corpus destination is not a regular file: {target}"
                )
            if target.read_bytes() != data:
                raise DifferentialFuzzError(
                    f"retained corpus destination hash collision: {target}"
                )
            continue
        if digest in destination_contents:
            if destination_contents[digest] != data:
                raise DifferentialFuzzError(
                    f"working corpus SHA256 collision detected: {target}"
                )
            continue
        with target.open("xb") as output:
            output.write(data)
        if target.read_bytes() != data:
            raise DifferentialFuzzError(
                f"retained corpus destination changed during import: {target}"
            )
        destination_contents[digest] = data
        imported += 1
    return imported


def add_differential_metadata(
    output_dir: Path,
    manifest: dict,
    source_hashes: dict,
    source_manifest: dict,
    fuzzer: Path | None,
    replay: Path | None,
    libcrux_bridge: Path | None,
    libcrux_rlib: Path | None,
    crate_dir: Path | None,
    openssl_runtime: dict | None,
    smoke_records: list[dict],
    input_status: list[str] | None,
    fuzzer_duration_seconds: float | None,
) -> dict:
    campaign_path = output_dir / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf8"))
    executed_units = None
    for line in campaign["final_stats"]:
        match = re.fullmatch(r"stat::number_of_executed_units:\s*(\d+)", line)
        if match is not None:
            executed_units = int(match.group(1))
            break
    campaign["repository_commit"] = git_head()
    campaign["github_sha"] = os.environ.get("GITHUB_SHA")
    campaign["repository_dirty"] = (
        None if input_status is None else bool(input_status)
    )
    campaign["repository_input_status_porcelain"] = input_status
    campaign["executed_units"] = executed_units
    campaign["fuzzer_duration_seconds"] = (
        round(fuzzer_duration_seconds, 3)
        if fuzzer_duration_seconds is not None
        else None
    )
    campaign["differential_oracles"] = {
        "comparison": "accept/reject equality for every parsed fuzz frame",
        "wrapper": {
            "implementation": "vendored mldsa-native through pqbtc_mldsa44_verify_strict",
            "commit": source_manifest.get("commit"),
            "source_capsule_sha256": source_manifest.get("capsule_hash", {}).get(
                "value"
            ),
        },
        "openssl": {
            "version": manifest["sources"]["openssl"]["version"],
            "commit": manifest["sources"]["openssl"]["commit"],
            "bridge_source_sha256": sha256_file(OPENSSL_BRIDGE),
            "runtime": openssl_runtime,
        },
        "libcrux": {
            "version": manifest["sources"]["libcrux"]["version"],
            "commit": manifest["sources"]["libcrux"]["commit"],
            "crate_sha256": manifest["sources"]["libcrux"]["crate_sha256"],
            "bridge_source_sha256": sha256_file(LIBCRUX_BRIDGE),
            "cargo_lock_sha256": (
                sha256_file(crate_dir / "Cargo.lock")
                if crate_dir is not None and (crate_dir / "Cargo.lock").is_file()
                else None
            ),
            "rlib_sha256": (
                sha256_file(libcrux_rlib)
                if libcrux_rlib is not None and libcrux_rlib.is_file()
                else None
            ),
            "bridge_binary_sha256": (
                sha256_file(libcrux_bridge)
                if libcrux_bridge is not None and libcrux_bridge.is_file()
                else None
            ),
        },
        "source_files": source_hashes,
        "fuzzer_binary_sha256": (
            sha256_file(fuzzer) if fuzzer is not None and fuzzer.is_file() else None
        ),
        "exact_replay": {
            "status": (
                "pass"
                if len(smoke_records) == len(SMOKE_CASE_NAMES)
                and all(record["status"] == "pass" for record in smoke_records)
                else ("fail" if smoke_records else "not_run")
            ),
            "case_count": len(smoke_records),
            "expected_accept_count": sum(
                record["expected"] == "accept" for record in smoke_records
            ),
            "expected_reject_count": sum(
                record["expected"] == "reject" for record in smoke_records
            ),
            "cases": smoke_records,
            "binary_sha256": (
                sha256_file(replay)
                if replay is not None and replay.is_file()
                else None
            ),
        },
        "coverage_scope": {
            "instrumented": [
                "pqbtc_mldsa44 wrapper and vendored portable C backend",
                "differential fuzz target and exact replay driver",
                "OpenSSL C adapter",
            ],
            "not_instrumented": [
                "prebuilt OpenSSL provider implementation body",
                "prebuilt libcrux Rust implementation body",
            ],
        },
        "toolchain": {
            "rustc": command_identity("rustc"),
            "cargo": command_identity("cargo"),
        },
    }
    campaign_path.write_text(
        json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf8"
    )
    verifier_fuzz.write_evidence_hashes(output_dir)
    return campaign


def run_campaign(
    manifest: dict,
    source_hashes: dict,
    openssl_source: Path,
    libcrux_source: Path,
    libcrux_crate: Path,
    output_dir: Path,
    *,
    seconds: int,
    seed: int,
    seed_corpus: Path | None = None,
) -> dict:
    input_status = git_input_status(source_hashes)
    output_dir = output_dir.resolve()
    if output_dir.exists():
        if not output_dir.is_dir():
            raise DifferentialFuzzError(f"output path is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise DifferentialFuzzError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir = output_dir / "corpus"
    artifact_dir = output_dir / "crashes"
    artifact_dir.mkdir()

    started_at = datetime.now(timezone.utc).isoformat()
    monotonic_start = time.monotonic()
    completed = subprocess.CompletedProcess([], 1, "", "campaign did not start")
    processing_error = None
    crash_minimization: list[dict] = []
    source_summary: dict = {}
    compiler = os.environ.get("FUZZ_CC", "clang")
    fuzzer: Path | None = None
    libcrux_bridge: Path | None = None
    libcrux_rlib: Path | None = None
    crate_dir: Path | None = None
    replay: Path | None = None
    openssl_runtime: dict | None = None
    smoke_records: list[dict] = []
    source_manifest: dict = {}
    fuzzer_duration_seconds: float | None = None
    imported_seeds = 0

    with tempfile.TemporaryDirectory(prefix="pqbtc-mldsa44-differential-") as temporary:
        build_dir = Path(temporary)
        try:
            source_manifest = verifier_fuzz.wrapper.validate_source_capsule()
            wycheproof = verifier_fuzz.validate_wycheproof_source()
            sources = manifest["sources"]
            reference.require_openssl_source(
                openssl_source, sources["openssl"]["commit"]
            )
            reference.require_libcrux_source(libcrux_source, sources["libcrux"])
            reference.require_artifact(
                libcrux_crate,
                sources["libcrux"]["crate_sha256"],
                "libcrux ML-DSA crate",
            )
            production_library = verifier_fuzz.wrapper.compile_shared(
                compiler, build_dir, testing=False
            )
            test_library = verifier_fuzz.wrapper.compile_shared(
                compiler, build_dir, testing=True
            )
            cases = verifier_fuzz.project_corpus(
                test_library
            ) + verifier_fuzz.wycheproof_corpus(wycheproof)
            source_summary = verifier_fuzz.validate_corpus_manifest(cases)
            verifier_fuzz.replay_corpus(production_library, cases)
            verifier_fuzz.materialize_corpus(corpus_dir, cases)
            if seed_corpus is not None:
                imported_seeds = import_seed_corpus(seed_corpus, corpus_dir)
                if imported_seeds == 0:
                    raise DifferentialFuzzError(
                        "retained seed corpus contributed no novel inputs"
                    )

            crate_dir = reference.prepare_libcrux_crate(
                build_dir, libcrux_crate, sources["libcrux"]
            )
            libcrux_bridge, libcrux_rlib = compile_libcrux_bridge(
                build_dir, crate_dir
            )
            fuzzer, replay, compiler = compile_differential_targets(
                build_dir, libcrux_bridge, sources["openssl"]["version"]
            )
            openssl_runtime = openssl_runtime_provenance(fuzzer)
            smoke_records = replay_differential_smoke(
                replay, cases, output_dir
            )
            failed_smoke_cases = [
                record["name"]
                for record in smoke_records
                if record["status"] != "pass"
            ]
            if failed_smoke_cases:
                raise DifferentialFuzzError(
                    "exact differential smoke replay failed for: "
                    + ", ".join(failed_smoke_cases)
                )
            fuzzer_started = time.monotonic()
            completed = verifier_fuzz.run_fuzzer(
                fuzzer,
                corpus_dir,
                artifact_dir,
                output_dir / "fuzzer.log",
                runs=None,
                seconds=seconds,
                sanitizer=SANITIZER,
                profile_pattern=output_dir / "coverage-%p.profraw",
                seed=seed,
            )
            fuzzer_duration_seconds = time.monotonic() - fuzzer_started
            if completed.returncode == 0:
                verifier_fuzz.minimize_corpus(
                    fuzzer,
                    corpus_dir,
                    output_dir / "minimized-corpus",
                    output_dir / "corpus-minimization.log",
                    sanitizer=SANITIZER,
                    profile_pattern=output_dir / "coverage-merge-%p.profraw",
                )
                verifier_fuzz.write_coverage_report(compiler, fuzzer, output_dir)
            else:
                crash_minimization = verifier_fuzz.minimize_crash_artifacts(
                    fuzzer,
                    artifact_dir,
                    output_dir,
                    sanitizer=SANITIZER,
                    seed=seed,
                )
        except (
            DifferentialFuzzError,
            KeyError,
            OSError,
            ValueError,
            reference.ReferenceError,
            verifier_fuzz.FuzzHarnessError,
            verifier_fuzz.wrapper.HarnessError,
        ) as error:
            processing_error = str(error)
        finally:
            verifier_fuzz.write_campaign_report(
                output_dir,
                compiler=compiler,
                sanitizer=SANITIZER,
                coverage=True,
                runs=None,
                seconds=seconds,
                imported_seeds=imported_seeds,
                source_summary=source_summary,
                started_at=started_at,
                duration_seconds=time.monotonic() - monotonic_start,
                seed=seed,
                completed=completed,
                processing_error=processing_error,
                crash_minimization=crash_minimization,
            )
            campaign = add_differential_metadata(
                output_dir,
                manifest,
                source_hashes,
                source_manifest,
                fuzzer,
                replay,
                libcrux_bridge,
                libcrux_rlib,
                crate_dir,
                openssl_runtime,
                smoke_records,
                input_status,
                fuzzer_duration_seconds,
            )

    if processing_error is not None:
        raise DifferentialFuzzError(
            f"campaign processing failed; evidence retained in {output_dir}: "
            f"{processing_error}"
        )
    if completed.returncode != 0:
        raise DifferentialFuzzError(
            f"fuzzer failed ({completed.returncode}); evidence retained in {output_dir}"
        )
    return {
        "status": campaign["status"],
        "return_code": campaign["return_code"],
        "sanitizer": campaign["sanitizer"],
        "coverage_enabled": campaign["coverage_enabled"],
        "campaign_limit": campaign["campaign_limit"],
        "repository_commit": campaign["repository_commit"],
        "repository_dirty": campaign["repository_dirty"],
        "seed": seed,
        "seconds": seconds,
        "imported_retained_seeds": campaign["imported_retained_seeds"],
        "source_corpus": campaign["source_corpus"],
        "working_corpus": campaign["working_corpus"],
        "minimized_corpus": campaign["minimized_corpus"],
        "crash_artifacts": campaign["crash_artifacts"],
        "last_progress_line": campaign["last_progress_line"],
        "final_stats": campaign["final_stats"],
        "executed_units": campaign["executed_units"],
        "fuzzer_duration_seconds": campaign["fuzzer_duration_seconds"],
        "differential_oracles": campaign["differential_oracles"],
        "evidence_sha256": sha256_file(output_dir / "SHA256SUMS"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-only", action="store_true")
    parser.add_argument("--openssl-source", type=Path)
    parser.add_argument("--libcrux-source", type=Path)
    parser.add_argument("--libcrux-crate", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--seed", type=int, default=188)
    parser.add_argument("--seed-corpus", type=Path)
    return parser.parse_args()


def require_path(value: Path | None, option: str) -> Path:
    if value is None:
        raise DifferentialFuzzError(f"{option} is required")
    return value.resolve()


def main() -> int:
    args = parse_args()
    try:
        manifest = reference.load_manifest()
        source_hashes = validate_local_inputs(manifest)
        verifier_fuzz.wrapper.validate_source_capsule()
        verifier_fuzz.validate_wycheproof_source()
        if args.manifest_only:
            print(
                "ML-DSA-44 differential verifier fuzz inputs OK: "
                "wrapper + OpenSSL 3.6.3 + libcrux 0.0.10"
            )
            return 0
        if not 1 <= args.seconds <= MAX_CAMPAIGN_SECONDS:
            raise DifferentialFuzzError(
                f"--seconds must be between 1 and {MAX_CAMPAIGN_SECONDS}"
            )
        if not 1 <= args.seed <= 0xFFFFFFFF:
            raise DifferentialFuzzError(
                "--seed must be a nonzero unsigned 32-bit integer"
            )
        report = run_campaign(
            manifest,
            source_hashes,
            require_path(args.openssl_source, "--openssl-source"),
            require_path(args.libcrux_source, "--libcrux-source"),
            require_path(args.libcrux_crate, "--libcrux-crate"),
            require_path(args.output_dir, "--output-dir"),
            seconds=args.seconds,
            seed=args.seed,
            seed_corpus=args.seed_corpus,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (
        DifferentialFuzzError,
        OSError,
        KeyError,
        ValueError,
        reference.ReferenceError,
        verifier_fuzz.FuzzHarnessError,
        verifier_fuzz.wrapper.HarnessError,
    ) as error:
        if args.output_dir is not None:
            campaign_path = args.output_dir.resolve() / "campaign.json"
            if campaign_path.is_file():
                campaign = json.loads(campaign_path.read_text(encoding="utf8"))
                print(
                    json.dumps(
                        {
                            "status": campaign.get("status", "fail"),
                            "return_code": campaign.get("return_code"),
                            "processing_error": campaign.get("processing_error"),
                            "repository_commit": campaign.get("repository_commit"),
                            "evidence_directory": str(args.output_dir.resolve()),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
        print(f"differential verifier fuzz: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
