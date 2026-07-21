#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Reproduce the pinned upstream ML-DSA-44 CBMC proof suite."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
ENGINEERING_ROOT = "contrib/ml-dsa-engineering"
VENDOR_ROOT = f"{ENGINEERING_ROOT}/vendor/mldsa-native"
PROOF_MANIFEST = f"{ENGINEERING_ROOT}/cbmc_proof_manifest.json"
SOURCE_MANIFEST = f"{VENDOR_ROOT}/SOURCE.json"

EVIDENCE_FILES = [
    ".github/workflows/ml-dsa-44-cbmc-reproduction.yml",
    "ci/test/test_ml_dsa_cbmc_reproduction.py",
    f"{ENGINEERING_ROOT}/README.md",
    f"{ENGINEERING_ROOT}/run_cbmc_reproduction.py",
    "docs/ML_DSA_44_WRAPPER_PROTOTYPE.md",
    PROOF_MANIFEST,
    SOURCE_MANIFEST,
]
EVIDENCE_PATHS = [*EVIDENCE_FILES, VENDOR_ROOT]

TOOL_COMMANDS = {
    "bitwuzla": ["bitwuzla", "--version"],
    "cbmc": ["cbmc", "--version"],
    "cbmc-viewer": ["cbmc-viewer", "--version"],
    "goto-cc": ["goto-cc", "--version"],
    "goto-instrument": ["goto-instrument", "--version"],
    "litani": ["litani", "--version"],
    "make": ["make", "--version"],
    "ninja": ["ninja", "--version"],
    "nix": ["nix", "--version"],
    "python3": ["python3", "--version"],
    "z3": ["z3", "--version"],
}


class AuditError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_lines(values: list[str]) -> str:
    payload = "".join(f"{value}\n" for value in sorted(values)).encode("utf8")
    return hashlib.sha256(payload).hexdigest()


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def run_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def run_binary_command(
    command: list[str], *, cwd: Path = REPO_ROOT
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def run_streamed_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf8") as log:
        log.write(f"command: {shlex.join(command)}\n\n[combined output]\n")
        log.flush()
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf8",
            errors="replace",
            bufsize=1,
        )
        if process.stdout is None:
            process.kill()
            raise AuditError("cannot capture the upstream CBMC runner output")
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log.write(line)
            log.flush()
        returncode = process.wait()
        log.write(f"\nreturncode: {returncode}\n")
    return returncode


def write_log(
    path: Path,
    command: list[str],
    returncode: int,
    stdout: str,
    stderr: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "command: "
        + shlex.join(command)
        + f"\nreturncode: {returncode}\n\n[stdout]\n{stdout}\n[stderr]\n{stderr}",
        encoding="utf8",
    )


def load_json_object(path: Path, label: str) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, OSError, ValueError) as error:
        raise AuditError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise AuditError(f"{label} is not a JSON object")
    return value


def load_manifest() -> dict[str, object]:
    manifest = load_json_object(REPO_ROOT / PROOF_MANIFEST, "CBMC proof manifest")
    if manifest.get("schema_version") != 1:
        raise AuditError("unsupported CBMC proof manifest schema")
    if manifest.get("audit") != "mldsa-native-upstream-cbmc-reproduction":
        raise AuditError("unexpected CBMC audit identifier")
    return manifest


def build_plan(
    manifest: dict[str, object], parallel_jobs: int, per_proof_timeout: int
) -> dict[str, object]:
    profile = manifest.get("profile")
    inventory = manifest.get("proof_inventory")
    scope = manifest.get("scope")
    if not isinstance(profile, dict) or not isinstance(inventory, dict):
        raise AuditError("CBMC manifest profile or inventory is missing")
    if not isinstance(scope, dict):
        raise AuditError("CBMC manifest scope is missing")
    if profile.get("parameter_set") != 44 or profile.get("reduce_ram") is not False:
        raise AuditError("CBMC manifest must select normal ML-DSA-44")
    if profile.get("coverage") is not False:
        raise AuditError(
            "CBMC reproduction must use property checking without coverage"
        )
    return {
        "schema_version": 1,
        "audit": manifest["audit"],
        "profile": {
            "parameter_set": 44,
            "reduce_ram": False,
            "coverage": False,
            "parallel_jobs": parallel_jobs,
            "per_proof_timeout_seconds": per_proof_timeout,
        },
        "upstream": manifest["upstream"],
        "proof_inventory": inventory,
        "tools": manifest["tools"],
        "source_capsule": manifest["source_capsule"],
        "scope": scope,
        "command": [
            "<upstream>/scripts/tests",
            "cbmc",
            "-j",
            str(parallel_jobs),
            "--mldsa-parameter-set",
            "44",
            "--per-proof-timeout",
            str(per_proof_timeout),
            "--output-result-json",
            "<output>/cbmc-result.json",
        ],
        "result_contract": {
            "mldsa_parameter_set": "44",
            "total": inventory["proof_uid_count"],
            "success": inventory["proof_uid_count"],
            "failed": 0,
            "timeout": 0,
            "failures": [],
            "exact_proof_uid_set": True,
        },
    }


def source_hashes() -> dict[str, str]:
    hashes = {}
    for relative in EVIDENCE_FILES:
        path = REPO_ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise AuditError(
                f"required audit input is missing or not a file: {relative}"
            )
        hashes[relative] = sha256_file(path)
    return hashes


def repository_state() -> dict[str, object]:
    commit = run_command(["git", "rev-parse", "HEAD"])
    unstaged = run_binary_command(
        ["git", "diff", "--name-only", "-z", "--", *EVIDENCE_PATHS]
    )
    staged = run_binary_command(
        ["git", "diff", "--cached", "--name-only", "-z", "--", *EVIDENCE_PATHS]
    )
    untracked = run_binary_command(
        [
            "git",
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *EVIDENCE_PATHS,
        ]
    )
    tracked = run_binary_command(
        ["git", "ls-files", "-z", "--", *EVIDENCE_FILES]
    )

    def paths(completed: subprocess.CompletedProcess[bytes]) -> list[str]:
        if completed.returncode != 0:
            return []
        return sorted(
            item.decode("utf8", errors="surrogateescape")
            for item in completed.stdout.split(b"\0")
            if item
        )

    changed = sorted(
        set(paths(unstaged)) | set(paths(staged)) | set(paths(untracked))
    )
    tracked_files = set(paths(tracked))
    commands_valid = all(
        completed.returncode == 0
        for completed in (unstaged, staged, untracked, tracked)
    )
    missing_tracked = sorted(set(EVIDENCE_FILES) - tracked_files)
    return {
        "commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "audit_input_dirty": bool(changed) if commands_valid else None,
        "dirty_audit_inputs": changed,
        "all_audit_inputs_tracked": not missing_tracked if commands_valid else None,
        "untracked_evidence_sources": missing_tracked,
    }


def upstream_identity(
    source_dir: Path, manifest: dict[str, object]
) -> dict[str, object]:
    upstream = manifest.get("upstream")
    if not isinstance(upstream, dict):
        raise AuditError("CBMC manifest upstream object is missing")
    resolved = source_dir.resolve()
    commit = run_command(["git", "rev-parse", "HEAD"], cwd=resolved)
    tree = run_command(["git", "rev-parse", "HEAD^{tree}"], cwd=resolved)
    status = run_command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=resolved
    )
    ignored = run_binary_command(
        [
            "git",
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        ],
        cwd=resolved,
    )
    tracked_flags = run_command(["git", "ls-files", "-v"], cwd=resolved)
    archive = run_binary_command(
        ["git", "archive", "--format=tar", "HEAD"], cwd=resolved
    )
    flake_lock = resolved / "flake.lock"
    lock_nodes: dict[str, object] = {}
    if flake_lock.is_file():
        lock = load_json_object(flake_lock, "upstream flake.lock")
        nodes = lock.get("nodes")
        if isinstance(nodes, dict):
            lock_nodes = nodes

    def locked_node(name: str) -> dict[str, object]:
        node = lock_nodes.get(name)
        if not isinstance(node, dict):
            return {}
        locked = node.get("locked")
        return locked if isinstance(locked, dict) else {}

    critical = upstream.get("critical_files")
    if not isinstance(critical, dict):
        raise AuditError("CBMC manifest critical-file inventory is missing")
    critical_actual = {}
    critical_errors = []
    for relative, expected in sorted(critical.items()):
        if not isinstance(relative, str) or not isinstance(expected, str):
            critical_errors.append("upstream critical-file entry is not textual")
            continue
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != relative:
            critical_errors.append(f"unsafe upstream critical-file path: {relative}")
            continue
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            critical_errors.append(f"invalid upstream critical-file hash: {relative}")
            continue
        path = resolved.joinpath(*pure.parts)
        try:
            path.resolve().relative_to(resolved)
        except ValueError:
            critical_errors.append(f"escaping upstream critical-file path: {relative}")
            continue
        actual = (
            sha256_file(path) if path.is_file() and not path.is_symlink() else None
        )
        critical_actual[str(relative)] = actual
        if actual != expected:
            critical_errors.append(f"upstream critical-file mismatch: {relative}")

    archive_sha256 = (
        hashlib.sha256(archive.stdout).hexdigest()
        if archive.returncode == 0
        else None
    )
    ignored_files = sorted(
        item.decode("utf8", errors="surrogateescape")
        for item in ignored.stdout.split(b"\0")
        if item
    )
    special_index_entries = sorted(
        line
        for line in tracked_flags.stdout.splitlines()
        if not line.startswith("H ")
    )
    nixpkgs = locked_node("nixpkgs")
    nixpkgs_unstable = locked_node("nixpkgs-unstable")
    expected_nixpkgs = upstream.get("nixpkgs")
    expected_unstable = upstream.get("nixpkgs_unstable")
    errors = [
        message
        for valid, message in (
            (
                commit.returncode == 0
                and commit.stdout.strip() == upstream.get("commit"),
                "upstream commit mismatch",
            ),
            (
                tree.returncode == 0
                and tree.stdout.strip() == upstream.get("git_tree"),
                "upstream git tree mismatch",
            ),
            (
                archive_sha256 == upstream.get("git_archive_tar_sha256"),
                "upstream git archive mismatch",
            ),
            (
                status.returncode == 0 and not status.stdout.strip(),
                "upstream worktree is dirty",
            ),
            (
                ignored.returncode == 0 and not ignored_files,
                "upstream worktree contains ignored files",
            ),
            (
                tracked_flags.returncode == 0 and not special_index_entries,
                "upstream index contains special tracked-file flags",
            ),
            (
                flake_lock.is_file()
                and not flake_lock.is_symlink()
                and sha256_file(flake_lock) == upstream.get("flake_lock_sha256"),
                "upstream flake.lock mismatch",
            ),
            (
                isinstance(expected_nixpkgs, dict)
                and nixpkgs.get("rev") == expected_nixpkgs.get("rev")
                and nixpkgs.get("narHash") == expected_nixpkgs.get("nar_hash"),
                "upstream nixpkgs lock mismatch",
            ),
            (
                isinstance(expected_unstable, dict)
                and nixpkgs_unstable.get("rev") == expected_unstable.get("rev")
                and nixpkgs_unstable.get("narHash")
                == expected_unstable.get("nar_hash"),
                "upstream nixpkgs-unstable lock mismatch",
            ),
        )
        if not valid
    ]
    errors.extend(critical_errors)
    return {
        "path": str(resolved),
        "commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "git_tree": tree.stdout.strip() if tree.returncode == 0 else None,
        "git_archive_tar_sha256": archive_sha256,
        "worktree_clean": (
            status.returncode == 0
            and not status.stdout.strip()
            and ignored.returncode == 0
            and not ignored_files
            and tracked_flags.returncode == 0
            and not special_index_entries
        ),
        "worktree_status": (
            status.stdout.splitlines() if status.returncode == 0 else None
        ),
        "ignored_worktree_files": ignored_files,
        "special_index_entries": special_index_entries,
        "flake_lock_sha256": sha256_file(flake_lock) if flake_lock.is_file() else None,
        "nixpkgs": {"rev": nixpkgs.get("rev"), "nar_hash": nixpkgs.get("narHash")},
        "nixpkgs_unstable": {
            "rev": nixpkgs_unstable.get("rev"),
            "nar_hash": nixpkgs_unstable.get("narHash"),
        },
        "critical_files": critical_actual,
        "validation_errors": errors,
    }


def capsule_equivalence(
    upstream_dir: Path, manifest: dict[str, object]
) -> dict[str, object]:
    source = load_json_object(REPO_ROOT / SOURCE_MANIFEST, "source capsule manifest")
    expected = manifest.get("source_capsule")
    if not isinstance(expected, dict):
        raise AuditError("CBMC source-capsule contract is missing")
    files = source.get("files")
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise AuditError("source capsule file inventory is invalid")
    if len(files) != len(set(files)):
        raise AuditError("source capsule file inventory contains duplicates")

    records = []
    errors = []
    aggregate_lines: list[tuple[str, str]] = []
    capsule_root = REPO_ROOT / VENDOR_ROOT
    actual_local_files = []
    for path in sorted(capsule_root.rglob("*")):
        relative = path.relative_to(capsule_root).as_posix()
        if path.is_symlink():
            errors.append(f"source capsule contains a symlink: {relative}")
        elif path.is_file() and relative != "SOURCE.json":
            actual_local_files.append(relative)
    missing_local = sorted(set(files) - set(actual_local_files))
    extra_local = sorted(set(actual_local_files) - set(files))
    if missing_local:
        errors.append("source capsule files are missing: " + ", ".join(missing_local))
    if extra_local:
        errors.append("source capsule has extra files: " + ", ".join(extra_local))

    for relative in files:
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != relative:
            errors.append(f"unsafe source capsule path: {relative}")
            continue
        local = REPO_ROOT / VENDOR_ROOT / relative
        upstream = upstream_dir.resolve() / relative
        local_hash = (
            sha256_file(local)
            if local.is_file() and not local.is_symlink()
            else None
        )
        upstream_hash = (
            sha256_file(upstream)
            if upstream.is_file() and not upstream.is_symlink()
            else None
        )
        matches = local_hash is not None and local_hash == upstream_hash
        records.append(
            {
                "path": relative,
                "checked_in_sha256": local_hash,
                "upstream_sha256": upstream_hash,
                "matches": matches,
            }
        )
        if local_hash is not None:
            aggregate_lines.append((relative, f"{local_hash}  ./{relative}\n"))
        if not matches:
            errors.append(f"source capsule differs from pinned upstream: {relative}")

    aggregate_payload = "".join(
        line for _, line in sorted(aggregate_lines)
    ).encode("utf8")
    aggregate = hashlib.sha256(aggregate_payload).hexdigest()
    expected_count = expected.get("file_count")
    expected_aggregate = expected.get("aggregate_sha256")
    for valid, message in (
        (len(files) == expected_count, "source capsule file count mismatch"),
        (aggregate == expected_aggregate, "source capsule aggregate mismatch"),
        (
            source.get("commit") == manifest["upstream"]["commit"],
            "source capsule commit mismatch",
        ),
        (
            source.get("git_tree") == manifest["upstream"]["git_tree"],
            "source capsule tree mismatch",
        ),
        (
            source.get("upstream_git_archive_tar_sha256")
            == manifest["upstream"]["git_archive_tar_sha256"],
            "source capsule archive mismatch",
        ),
    ):
        if not valid:
            errors.append(message)
    return {
        "status": "passed" if not errors else "failed",
        "file_count": len(files),
        "checked_in_file_count": len(actual_local_files),
        "aggregate_sha256": aggregate,
        "files": records,
        "validation_errors": errors,
    }


def proof_inventory(
    upstream_dir: Path, manifest: dict[str, object]
) -> dict[str, object]:
    expected = manifest.get("proof_inventory")
    if not isinstance(expected, dict):
        raise AuditError("CBMC proof inventory contract is missing")
    lister = upstream_dir.resolve() / "proofs/cbmc/list_proofs.sh"
    completed = run_command([str(lister)], cwd=upstream_dir.resolve())
    directories = [
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    ]
    errors = []
    if completed.returncode != 0:
        errors.append("upstream proof lister failed")
    if len(directories) != len(set(directories)):
        errors.append("upstream proof directory inventory has duplicates")

    proof_uids = []
    records = []
    for directory in directories:
        pure = PurePosixPath(directory)
        proof_dir = upstream_dir.resolve() / "proofs/cbmc" / directory
        makefile = proof_dir / "Makefile"
        if pure.is_absolute() or len(pure.parts) != 1 or not makefile.is_file():
            errors.append(f"invalid proof directory: {directory}")
            continue
        uid_matches = []
        for line in makefile.read_text(encoding="utf8").splitlines():
            match = re.fullmatch(r"PROOF_UID\s*=\s*(.+?)\s*", line)
            if match is not None:
                uid_matches.append(match.group(1))
        harnesses = sorted(
            path.name
            for path in proof_dir.glob("*_harness.c")
            if path.is_file()
        )
        if len(uid_matches) != 1:
            errors.append(f"proof has no unique PROOF_UID: {directory}")
            continue
        if not harnesses:
            errors.append(f"proof has no harness source: {directory}")
        proof_uids.append(uid_matches[0])
        records.append(
            {
                "directory": directory,
                "proof_uid": uid_matches[0],
                "makefile_sha256": sha256_file(makefile),
                "harnesses": harnesses,
            }
        )

    if len(proof_uids) != len(set(proof_uids)):
        errors.append("upstream PROOF_UID inventory has duplicates")
    directory_hash = sha256_lines(directories)
    uid_hash = sha256_lines(proof_uids)
    for valid, message in (
        (
            len(directories) == expected.get("directory_count"),
            "proof directory count mismatch",
        ),
        (
            directory_hash == expected.get("sorted_directory_names_sha256"),
            "proof directory inventory hash mismatch",
        ),
        (
            len(proof_uids) == expected.get("proof_uid_count"),
            "proof UID count mismatch",
        ),
        (
            uid_hash == expected.get("sorted_proof_uids_sha256"),
            "proof UID inventory hash mismatch",
        ),
    ):
        if not valid:
            errors.append(message)
    return {
        "status": "passed" if not errors else "failed",
        "directories": directories,
        "proof_uids": proof_uids,
        "directory_count": len(directories),
        "proof_uid_count": len(proof_uids),
        "sorted_directory_names_sha256": directory_hash,
        "sorted_proof_uids_sha256": uid_hash,
        "records": records,
        "validation_errors": errors,
    }


def expected_tool_versions(manifest: dict[str, object]) -> dict[str, str | None]:
    tools = manifest.get("tools")
    if not isinstance(tools, dict):
        raise AuditError("CBMC tool contract is missing")
    return {
        "bitwuzla": str(tools["bitwuzla"]),
        "cbmc": str(tools["cbmc"]),
        "cbmc-viewer": str(tools["cbmc_viewer"]),
        "goto-cc": str(tools["cbmc"]),
        "goto-instrument": str(tools["cbmc"]),
        "litani": None,
        "make": None,
        "ninja": str(tools["ninja"]),
        "nix": str(tools["nix"]),
        "python3": None,
        "z3": str(tools["z3"]),
    }


def tool_identities(
    manifest: dict[str, object], output_dir: Path
) -> tuple[dict[str, object], list[str]]:
    expected = expected_tool_versions(manifest)
    identities = {}
    errors = []
    for name, command in TOOL_COMMANDS.items():
        resolved = shutil.which(command[0])
        log_relative = f"logs/tool-{name}.log"
        if resolved is None:
            message = f"required CBMC tool is unavailable: {command[0]}"
            write_log(output_dir / log_relative, command, 127, "", message)
            identities[name] = {
                "status": "failed",
                "command": command,
                "error": message,
                "log": log_relative,
            }
            errors.append(message)
            continue
        actual_command = [resolved, *command[1:]]
        completed = run_command(actual_command)
        version = "\n".join(
            part
            for part in (completed.stdout.strip(), completed.stderr.strip())
            if part
        )
        required_version = expected[name]
        version_ok = required_version is None or re.search(
            rf"(?<![0-9]){re.escape(required_version)}(?![0-9])", version
        ) is not None
        passed = completed.returncode == 0 and bool(version) and version_ok
        write_log(
            output_dir / log_relative,
            actual_command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
        resolved_path = Path(resolved).resolve()
        identities[name] = {
            "status": "passed" if passed else "failed",
            "command": command,
            "resolved_path": str(resolved_path),
            "binary_sha256": (
                sha256_file(resolved_path) if resolved_path.is_file() else None
            ),
            "version": version,
            "required_version": required_version,
            "log": log_relative,
        }
        if not passed:
            errors.append(
                f"{name} failed its version contract: {version or 'no output'}"
            )
    return identities, errors


def validate_result(
    result: dict[str, object], expected_uids: list[str], parameter_set: int
) -> list[str]:
    errors = []
    summary = result.get("summary")
    failures = result.get("failures")
    runtimes = result.get("runtimes")
    if result.get("mldsa_parameter_set") != str(parameter_set):
        errors.append("CBMC result parameter set mismatch")
    if not isinstance(summary, dict):
        return [*errors, "CBMC result summary is missing"]
    expected_count = len(expected_uids)
    for key, expected in (
        ("total", expected_count),
        ("success", expected_count),
        ("failed", 0),
        ("timeout", 0),
    ):
        actual = summary.get(key)
        if (
            not isinstance(actual, int)
            or isinstance(actual, bool)
            or actual != expected
        ):
            errors.append(f"CBMC result summary {key} mismatch")
    if failures != []:
        errors.append("CBMC result contains failures")
    if not isinstance(runtimes, list):
        return [*errors, "CBMC result runtimes are missing"]
    names = []
    for runtime in runtimes:
        if not isinstance(runtime, dict):
            errors.append("CBMC result contains a non-object runtime")
            continue
        name = runtime.get("name")
        if not isinstance(name, str):
            errors.append("CBMC result runtime has no name")
            continue
        names.append(name)
        value = runtime.get("value")
        if (
            runtime.get("unit") != "seconds"
            or not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            errors.append(f"CBMC result runtime is invalid: {name}")
        if "status" in runtime:
            errors.append(f"CBMC result runtime has failed status: {name}")
    if len(names) != len(set(names)):
        errors.append("CBMC result contains duplicate proof names")
    if sorted(names) != sorted(expected_uids):
        errors.append("CBMC result proof UID set mismatch")
    return errors


def system_identity() -> dict[str, object]:
    total_memory = None
    try:
        total_memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (KeyError, OSError, ValueError):
        pass
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "total_memory_bytes": total_memory,
        "python": sys.version,
    }


def write_evidence_hashes(output_dir: Path) -> None:
    entries = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.name == "SHA256SUMS":
            continue
        entries.append(
            f"{sha256_file(path)}  {path.relative_to(output_dir).as_posix()}\n"
        )
    (output_dir / "SHA256SUMS").write_text("".join(entries), encoding="utf8")


def prepare_output_dir(output_dir: Path) -> Path:
    resolved = output_dir.resolve()
    if resolved.exists():
        if not resolved.is_dir():
            raise AuditError(f"output path is not a directory: {resolved}")
        if any(resolved.iterdir()):
            raise AuditError(f"output directory is not empty: {resolved}")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def execute_audit(
    plan: dict[str, object],
    manifest: dict[str, object],
    output_dir: Path,
    upstream_source_dir: Path,
) -> int:
    output = prepare_output_dir(output_dir)
    plan_path = output / "cbmc-plan.json"
    plan_path.write_text(json_text(plan), encoding="utf8")
    report: dict[str, object] = {
        "schema_version": 1,
        "audit": plan["audit"],
        "status": "failed",
        "plan_sha256": sha256_file(plan_path),
        "repository": {},
        "system": system_identity(),
        "upstream": {},
        "source_capsule": {},
        "proof_inventory": {},
        "tools": {},
        "execution": {},
        "result": None,
        "errors": [],
    }
    errors = report["errors"]
    assert isinstance(errors, list)

    try:
        report["audit_input_sha256"] = source_hashes()
        repository = repository_state()
        report["repository"] = repository
        if repository["audit_input_dirty"] is not False:
            errors.append(
                "tracked audit inputs must be clean: "
                + ", ".join(repository["dirty_audit_inputs"])
            )
        if repository["all_audit_inputs_tracked"] is not True:
            errors.append(
                "all audit inputs must be tracked: "
                + ", ".join(repository["untracked_evidence_sources"])
            )

        upstream = upstream_identity(upstream_source_dir, manifest)
        report["upstream"] = upstream
        errors.extend(upstream["validation_errors"])

        capsule = capsule_equivalence(upstream_source_dir, manifest)
        report["source_capsule"] = capsule
        (output / "capsule-equivalence.json").write_text(
            json_text(capsule), encoding="utf8"
        )
        errors.extend(capsule["validation_errors"])

        if upstream["validation_errors"]:
            inventory = {
                "status": "skipped",
                "reason": "upstream identity validation failed",
                "directories": [],
                "proof_uids": [],
                "validation_errors": [],
            }
        else:
            inventory = proof_inventory(upstream_source_dir, manifest)
            errors.extend(inventory["validation_errors"])
        report["proof_inventory"] = {
            key: value for key, value in inventory.items() if key != "records"
        }
        (output / "proof-inventory.json").write_text(
            json_text(inventory), encoding="utf8"
        )
        (output / "proof-directories.txt").write_text(
            "".join(f"{name}\n" for name in sorted(inventory["directories"])),
            encoding="utf8",
        )
        (output / "proof-uids.txt").write_text(
            "".join(f"{name}\n" for name in sorted(inventory["proof_uids"])),
            encoding="utf8",
        )

        tools, tool_errors = tool_identities(manifest, output)
        report["tools"] = tools
        (output / "tool-identities.json").write_text(
            json_text(tools), encoding="utf8"
        )
        errors.extend(tool_errors)

        if not errors:
            profile = plan["profile"]
            assert isinstance(profile, dict)
            result_path = output / "cbmc-result.json"
            command = [
                str(upstream_source_dir.resolve() / "scripts/tests"),
                "cbmc",
                "-j",
                str(profile["parallel_jobs"]),
                "--mldsa-parameter-set",
                str(profile["parameter_set"]),
                "--per-proof-timeout",
                str(profile["per_proof_timeout_seconds"]),
                "--output-result-json",
                str(result_path),
            ]
            environment = os.environ.copy()
            environment.update({"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"})
            log_relative = "logs/cbmc-full-ml-dsa-44.log"
            started = time.monotonic()
            returncode = run_streamed_command(
                command,
                cwd=upstream_source_dir.resolve(),
                env=environment,
                log_path=output / log_relative,
            )
            duration = time.monotonic() - started
            execution = {
                "command": command,
                "return_code": returncode,
                "duration_seconds": duration,
                "log": log_relative,
            }
            report["execution"] = execution
            if returncode != 0:
                errors.append(
                    f"upstream CBMC runner failed with return code {returncode}"
                )
            if not result_path.is_file():
                errors.append("upstream CBMC runner produced no result JSON")
            else:
                result = load_json_object(result_path, "CBMC result")
                report["result"] = result
                errors.extend(
                    validate_result(
                        result,
                        list(inventory["proof_uids"]),
                        int(profile["parameter_set"]),
                    )
                )
    except (AuditError, KeyError, OSError, TypeError, ValueError) as error:
        errors.append(str(error))

    report["status"] = "passed" if not errors else "failed"
    report_path = output / "cbmc-reproduction-report.json"
    report_path.write_text(json_text(report), encoding="utf8")
    write_evidence_hashes(output)
    if report["status"] == "passed":
        print(f"ML-DSA-44 upstream CBMC reproduction passed; evidence: {output}")
        return 0
    print(
        f"ML-DSA-44 upstream CBMC reproduction failed; evidence: {output}",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reproduce the pinned upstream ML-DSA-44 CBMC proof suite"
    )
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--upstream-source-dir", type=Path)
    parser.add_argument("--parallel-jobs", type=int)
    parser.add_argument("--per-proof-timeout", type=int)
    args = parser.parse_args()

    manifest = load_manifest()
    profile = manifest.get("profile")
    if not isinstance(profile, dict):
        raise AuditError("CBMC manifest profile is missing")
    parallel_jobs = (
        args.parallel_jobs
        if args.parallel_jobs is not None
        else int(profile["parallel_jobs"])
    )
    per_proof_timeout = (
        args.per_proof_timeout
        if args.per_proof_timeout is not None
        else int(profile["per_proof_timeout_seconds"])
    )
    if not 1 <= parallel_jobs <= 32:
        parser.error("--parallel-jobs must be between 1 and 32")
    if not 60 <= per_proof_timeout <= 3600:
        parser.error("--per-proof-timeout must be between 60 and 3600")
    if per_proof_timeout != int(profile["per_proof_timeout_seconds"]):
        parser.error(
            "--per-proof-timeout must match the pinned manifest contract "
            f"({profile['per_proof_timeout_seconds']})"
        )
    plan = build_plan(manifest, parallel_jobs, per_proof_timeout)
    if args.plan_only:
        print(json_text(plan), end="")
        return 0
    if args.output_dir is None:
        parser.error("--output-dir is required unless --plan-only is used")
    if args.upstream_source_dir is None:
        parser.error("--upstream-source-dir is required unless --plan-only is used")
    return execute_audit(plan, manifest, args.output_dir, args.upstream_source_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, ValueError) as error:
        print(f"CBMC reproduction: {error}", file=sys.stderr)
        raise SystemExit(1)
