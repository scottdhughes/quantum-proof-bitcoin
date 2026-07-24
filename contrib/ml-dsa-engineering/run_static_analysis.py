#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Run versioned static analysis over the isolated ML-DSA-44 wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import run_wrapper_tests as wrapper_contract


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
ENGINEERING_ROOT = "contrib/ml-dsa-engineering"
VENDOR_ROOT = f"{ENGINEERING_ROOT}/vendor"
WRAPPER_SOURCE = f"{ENGINEERING_ROOT}/pqbtc_mldsa44.c"
SMOKE_SOURCE = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_smoke.c"
FUZZ_SOURCE = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_verify_fuzz.c"
STATEFUL_FUZZ_SOURCE = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_stateful_fuzz.c"
PUBLIC_HEADER = f"{ENGINEERING_ROOT}/pqbtc_mldsa44.h"
TEST_HEADER = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_test.h"
CONFIG_HEADER = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_config.h"
SOURCE_MANIFEST = f"{VENDOR_ROOT}/mldsa-native/SOURCE.json"
TIDY_CONFIG = "src/.clang-tidy"
IWYU_MAPPING = "contrib/devtools/iwyu/bitcoin.core.imp"
EXPECTED_LLVM_MAJOR = 20
EXPECTED_IWYU_COMMIT = "6e08906c66b3009f2d590e4bd40d60fa303bf803"
ANNEX_K_TIDY_CHECK = (
    "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
)
CLANG_TIDY_CHECKS = "clang-analyzer-*"
EXPECTED_ANNEX_K_SUPPRESSIONS = 13

FIRST_PARTY_HEADER_FILTER = (
    r"(^|.*/)contrib/ml-dsa-engineering/pqbtc_mldsa44[^/]*\.h$"
)
VENDOR_HEADER_EXCLUDE = r"(^|.*/)contrib/ml-dsa-engineering/vendor/"

COMMON_C_FLAGS = [
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wno-unused-function",
    "-Wno-unknown-pragmas",
    "-fvisibility=hidden",
    f"-I{ENGINEERING_ROOT}",
]

EVIDENCE_SOURCES = [
    ".github/workflows/ml-dsa-44-wrapper-prototype.yml",
    ".github/workflows/promotion-matrix.yml",
    "ci/test/00_setup_env_native_tidy.sh",
    "ci/test/01_base_install.sh",
    "ci/test/03_test_script.sh",
    "ci/test/test_ml_dsa_wrapper_prototype.py",
    "contrib/ml-dsa-engineering/README.md",
    "contrib/ml-dsa-engineering/run_static_analysis.py",
    "contrib/ml-dsa-engineering/run_wrapper_tests.py",
    WRAPPER_SOURCE,
    SMOKE_SOURCE,
    FUZZ_SOURCE,
    STATEFUL_FUZZ_SOURCE,
    PUBLIC_HEADER,
    TEST_HEADER,
    CONFIG_HEADER,
    SOURCE_MANIFEST,
    TIDY_CONFIG,
    IWYU_MAPPING,
]


class AuditError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def source_hashes() -> dict[str, str]:
    hashes = {}
    for relative in EVIDENCE_SOURCES:
        path = REPO_ROOT / relative
        if not path.is_file():
            raise AuditError(f"required audit input is missing: {relative}")
        hashes[relative] = sha256_file(path)
    return hashes


def annex_k_suppression_count() -> int:
    marker = f"NOLINTNEXTLINE({ANNEX_K_TIDY_CHECK})"
    return sum(
        (REPO_ROOT / relative).read_text(encoding="utf8").count(marker)
        for relative in (
            WRAPPER_SOURCE,
            SMOKE_SOURCE,
            FUZZ_SOURCE,
            STATEFUL_FUZZ_SOURCE,
        )
    )


def tidy_command(
    clang_tidy: str,
    plugin: str,
    source: str,
    extra_flags: list[str] | None = None,
) -> list[str]:
    return [
        clang_tidy,
        "--quiet",
        f"--load={plugin}",
        f"--config-file={TIDY_CONFIG}",
        f"--checks={CLANG_TIDY_CHECKS}",
        "--warnings-as-errors=*",
        f"--header-filter={FIRST_PARTY_HEADER_FILTER}",
        f"--exclude-header-filter={VENDOR_HEADER_EXCLUDE}",
        source,
        "--",
        *COMMON_C_FLAGS,
        *(extra_flags or []),
    ]


def iwyu_command(
    iwyu: str,
    source: str,
    check_also: list[str],
    extra_flags: list[str] | None = None,
) -> list[str]:
    command = [
        iwyu,
        "-Xiwyu",
        "--error=1",
        "-Xiwyu",
        f"--mapping_file={IWYU_MAPPING}",
        "-Xiwyu",
        "--max_line_length=160",
    ]
    for header in check_also:
        command.extend(["-Xiwyu", f"--check_also={header}"])
    command.extend([*COMMON_C_FLAGS, *(extra_flags or []), source])
    return command


def header_command(clang: str, header: str) -> list[str]:
    return [
        clang,
        *COMMON_C_FLAGS,
        "-x",
        "c-header",
        "-fsyntax-only",
        header,
    ]


def build_plan(
    clang: str,
    clang_tidy: str,
    iwyu: str,
    iwyu_source_dir: str,
    plugin: str,
) -> dict[str, object]:
    checks = [
        {
            "id": "clang-tidy-wrapper-production",
            "kind": "clang-tidy",
            "input": WRAPPER_SOURCE,
            "variant": "production",
            "command": tidy_command(clang_tidy, plugin, WRAPPER_SOURCE),
        },
        {
            "id": "clang-tidy-wrapper-testing",
            "kind": "clang-tidy",
            "input": WRAPPER_SOURCE,
            "variant": "testing",
            "command": tidy_command(
                clang_tidy,
                plugin,
                WRAPPER_SOURCE,
                ["-DPQBTC_MLDSA44_TESTING=1"],
            ),
        },
        {
            "id": "clang-tidy-smoke-testing",
            "kind": "clang-tidy",
            "input": SMOKE_SOURCE,
            "variant": "testing",
            "command": tidy_command(
                clang_tidy,
                plugin,
                SMOKE_SOURCE,
                ["-DPQBTC_MLDSA44_TESTING=1", "-pthread"],
            ),
        },
        {
            "id": "clang-tidy-verifier-fuzz",
            "kind": "clang-tidy",
            "input": FUZZ_SOURCE,
            "variant": "production-api",
            "command": tidy_command(clang_tidy, plugin, FUZZ_SOURCE),
        },
        {
            "id": "clang-tidy-stateful-signer-fuzz",
            "kind": "clang-tidy",
            "input": STATEFUL_FUZZ_SOURCE,
            "variant": "testing",
            "command": tidy_command(
                clang_tidy,
                plugin,
                STATEFUL_FUZZ_SOURCE,
                ["-DPQBTC_MLDSA44_TESTING=1"],
            ),
        },
        {
            "id": "iwyu-smoke-testing",
            "kind": "iwyu",
            "input": SMOKE_SOURCE,
            "variant": "testing",
            "check_also": [PUBLIC_HEADER, TEST_HEADER],
            "command": iwyu_command(
                iwyu,
                SMOKE_SOURCE,
                [PUBLIC_HEADER, TEST_HEADER],
                ["-DPQBTC_MLDSA44_TESTING=1", "-pthread"],
            ),
        },
        {
            "id": "iwyu-verifier-fuzz",
            "kind": "iwyu",
            "input": FUZZ_SOURCE,
            "variant": "production-api",
            "check_also": [PUBLIC_HEADER],
            "command": iwyu_command(iwyu, FUZZ_SOURCE, [PUBLIC_HEADER]),
        },
        {
            "id": "iwyu-stateful-signer-fuzz",
            "kind": "iwyu",
            "input": STATEFUL_FUZZ_SOURCE,
            "variant": "testing",
            "check_also": [PUBLIC_HEADER, TEST_HEADER],
            "command": iwyu_command(
                iwyu,
                STATEFUL_FUZZ_SOURCE,
                [PUBLIC_HEADER, TEST_HEADER],
                ["-DPQBTC_MLDSA44_TESTING=1"],
            ),
        },
        {
            "id": "header-self-contained-production",
            "kind": "header-self-containment",
            "input": PUBLIC_HEADER,
            "variant": "production",
            "command": header_command(clang, PUBLIC_HEADER),
        },
        {
            "id": "header-self-contained-testing",
            "kind": "header-self-containment",
            "input": TEST_HEADER,
            "variant": "testing",
            "command": header_command(clang, TEST_HEADER),
        },
    ]
    manifest = wrapper_contract.validate_source_capsule()
    plan: dict[str, object] = {
        "schema_version": 1,
        "audit": "ml-dsa-44-isolated-wrapper-static-analysis",
        "expected_llvm_major": EXPECTED_LLVM_MAJOR,
        "scope": {
            "isolated_wrapper_only": True,
            "clang_tidy_wrapper_implementation": True,
            "iwyu_wrapper_implementation": False,
            "iwyu_first_party_leaf_units_and_headers": True,
            "production_integration": False,
            "release_hold_unchanged": True,
        },
        "tools": {
            "clang": {"command": clang, "required_llvm_major": EXPECTED_LLVM_MAJOR},
            "clang-tidy": {
                "command": clang_tidy,
                "plugin": plugin,
                "required_llvm_major": EXPECTED_LLVM_MAJOR,
            },
            "iwyu": {
                "command": iwyu,
                "required_llvm_major": EXPECTED_LLVM_MAJOR,
                "source_dir": iwyu_source_dir,
                "source_commit": EXPECTED_IWYU_COMMIT,
            },
        },
        "reporting_boundary": {
            "first_party_root": ENGINEERING_ROOT,
            "first_party_header_filter": FIRST_PARTY_HEADER_FILTER,
            "vendor_root": VENDOR_ROOT,
            "vendor_header_exclude": VENDOR_HEADER_EXCLUDE,
            "clang_tidy_check_expression": CLANG_TIDY_CHECKS,
            "clang_tidy_local_suppression": {
                "check": ANNEX_K_TIDY_CHECK,
                "annotation": "NOLINTNEXTLINE",
                "occurrences": annex_k_suppression_count(),
                "expected_occurrences": EXPECTED_ANNEX_K_SUPPRESSIONS,
                "reason": (
                    "C11 Annex K _s functions are optional and unavailable on "
                    "the supported Linux toolchain"
                ),
            },
            "vendor_may_be_parsed_for_translation_unit_semantics": True,
            "vendor_files_are_never_main_inputs": True,
            "iwyu_excludes_single_compilation_unit_aggregator": WRAPPER_SOURCE,
        },
        "source_capsule": {
            "commit": manifest["commit"],
            "capsule_sha256": manifest["capsule_hash"]["value"],
            "manifest_sha256": sha256_file(REPO_ROOT / SOURCE_MANIFEST),
            "verified_against_checked_in_files": True,
        },
        "source_files": source_hashes(),
        "checks": checks,
    }
    validate_plan(plan)
    return plan


def validate_plan(plan: dict[str, object]) -> None:
    checks = plan.get("checks")
    if not isinstance(checks, list):
        raise AuditError("static-analysis plan has no check list")

    expected_counts = {
        "clang-tidy": 5,
        "iwyu": 3,
        "header-self-containment": 2,
    }
    counts = {kind: 0 for kind in expected_counts}
    seen_ids = set()
    for raw_check in checks:
        if not isinstance(raw_check, dict):
            raise AuditError("static-analysis check is not an object")
        check_id = raw_check.get("id")
        kind = raw_check.get("kind")
        source = raw_check.get("input")
        command = raw_check.get("command")
        if not isinstance(check_id, str) or not check_id:
            raise AuditError("static-analysis check has no id")
        if check_id in seen_ids:
            raise AuditError(f"duplicate static-analysis check id: {check_id}")
        seen_ids.add(check_id)
        if kind not in counts:
            raise AuditError(f"unknown static-analysis check kind: {kind}")
        counts[kind] += 1
        if not isinstance(source, str) or source.startswith(f"{VENDOR_ROOT}/"):
            raise AuditError(f"vendored file selected as main input: {source}")
        if not isinstance(command, list) or not all(
            isinstance(argument, str) for argument in command
        ):
            raise AuditError(f"invalid command for {check_id}")
        if "-std=c11" not in command:
            raise AuditError(f"{check_id} does not use the C11 wrapper contract")

        if kind == "clang-tidy":
            required = {
                f"--checks={CLANG_TIDY_CHECKS}",
                f"--header-filter={FIRST_PARTY_HEADER_FILTER}",
                f"--exclude-header-filter={VENDOR_HEADER_EXCLUDE}",
                "--warnings-as-errors=*",
            }
            if not required.issubset(command):
                raise AuditError(f"{check_id} lacks the reporting boundary")
        if kind == "iwyu":
            if source == WRAPPER_SOURCE:
                raise AuditError("IWYU must not analyze the vendored SCU aggregator")
            if "--error=1" not in command:
                raise AuditError(f"{check_id} is not enforcing IWYU findings")
            check_also = raw_check.get("check_also")
            if not isinstance(check_also, list) or not check_also:
                raise AuditError(f"{check_id} has no first-party header coverage")
            for path in check_also:
                if not isinstance(path, str) or not path.startswith(
                    f"{ENGINEERING_ROOT}/pqbtc_mldsa44"
                ):
                    raise AuditError(f"{check_id} has an invalid check_also path: {path}")
                if path.startswith(f"{VENDOR_ROOT}/"):
                    raise AuditError(f"{check_id} selects a vendored check_also path")

    if counts != expected_counts:
        raise AuditError(
            f"unexpected static-analysis check counts: {counts}, expected {expected_counts}"
        )

    tools = plan.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get("iwyu"), dict):
        raise AuditError("static-analysis plan has no IWYU tool contract")
    if tools["iwyu"].get("source_commit") != EXPECTED_IWYU_COMMIT:
        raise AuditError("static-analysis plan does not pin the expected IWYU commit")
    suppression = plan["reporting_boundary"].get("clang_tidy_local_suppression")
    if (
        not isinstance(suppression, dict)
        or suppression.get("occurrences") != EXPECTED_ANNEX_K_SUPPRESSIONS
        or suppression.get("expected_occurrences")
        != EXPECTED_ANNEX_K_SUPPRESSIONS
    ):
        raise AuditError("unexpected Annex-K clang-tidy suppression inventory")


def resolve_tool(command: str) -> str | None:
    resolved = shutil.which(command)
    if resolved is not None:
        return str(Path(resolved).resolve())
    candidate = Path(command)
    if candidate.is_file():
        return str(candidate.resolve())
    return None


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf8",
        errors="replace",
    )


def write_log(
    path: Path,
    command: list[str],
    return_code: int,
    stdout: str,
    stderr: str,
) -> None:
    path.write_text(
        "\n".join(
            [
                f"command: {shlex.join(command)}",
                f"cwd: {REPO_ROOT}",
                f"return_code: {return_code}",
                "stdout:",
                stdout.rstrip(),
                "stderr:",
                stderr.rstrip(),
                "",
            ]
        ),
        encoding="utf8",
    )


def prepare_output_dir(output_dir: Path) -> Path:
    resolved = output_dir.resolve()
    if resolved.exists():
        if not resolved.is_dir():
            raise AuditError(f"output path is not a directory: {resolved}")
        if any(resolved.iterdir()):
            raise AuditError(f"output directory is not empty: {resolved}")
    else:
        resolved.mkdir(parents=True)
    (resolved / "logs").mkdir()
    return resolved


def version_matches_llvm_20(output: str) -> bool:
    return re.search(
        rf"\b(?:clang|LLVM)(?:\s+version)?\s+{EXPECTED_LLVM_MAJOR}(?:\.|\b)",
        output,
        flags=re.IGNORECASE,
    ) is not None


def repository_state() -> dict[str, object]:
    commit = run_command(["git", "rev-parse", "HEAD"])
    status = run_command(["git", "status", "--porcelain", "--untracked-files=no"])
    tracked_changes = []
    if status.returncode == 0:
        for line in status.stdout.splitlines():
            path = line[3:]
            if " -> " in path:
                path = path.rsplit(" -> ", maxsplit=1)[1]
            tracked_changes.append(path)
    audit_inputs = set(EVIDENCE_SOURCES)
    dirty_audit_inputs = sorted(
        path
        for path in tracked_changes
        if path in audit_inputs or path.startswith(f"{ENGINEERING_ROOT}/")
    )
    return {
        "commit": commit.stdout.strip() if commit.returncode == 0 else "unknown",
        "tracked_worktree_dirty": bool(tracked_changes)
        if status.returncode == 0
        else None,
        "tracked_changes": sorted(tracked_changes),
        "audit_input_dirty": bool(dirty_audit_inputs)
        if status.returncode == 0
        else None,
        "dirty_audit_inputs": dirty_audit_inputs,
    }


def write_evidence_hashes(output_dir: Path) -> None:
    lines = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            relative = path.relative_to(output_dir).as_posix()
            lines.append(f"{sha256_file(path)}  {relative}\n")
    (output_dir / "SHA256SUMS").write_text("".join(lines), encoding="utf8")


def execute_audit(plan: dict[str, object], requested_output_dir: Path) -> int:
    output_dir = prepare_output_dir(requested_output_dir)
    plan_path = output_dir / "static-analysis-plan.json"
    plan_path.write_text(json_text(plan), encoding="utf8")

    repository = repository_state()
    report: dict[str, object] = {
        "schema_version": 1,
        "audit": plan["audit"],
        "status": "failed",
        "repository": repository,
        "plan_sha256": sha256_file(plan_path),
        "tools": {},
        "checks": [],
        "errors": [],
    }
    errors = report["errors"]
    tool_results = report["tools"]
    assert isinstance(errors, list)
    assert isinstance(tool_results, dict)
    if repository["audit_input_dirty"] is not False:
        errors.append(
            "tracked audit inputs must be clean: "
            + ", ".join(repository["dirty_audit_inputs"])
        )

    plan_tools = plan["tools"]
    assert isinstance(plan_tools, dict)
    resolved_tools: dict[str, str] = {}
    for tool_name in ("clang", "clang-tidy", "iwyu"):
        tool = plan_tools[tool_name]
        assert isinstance(tool, dict)
        configured = tool["command"]
        assert isinstance(configured, str)
        resolved = resolve_tool(configured)
        log_relative = f"logs/tool-{tool_name}-version.log"
        log_path = output_dir / log_relative
        if resolved is None:
            message = f"required tool is unavailable: {configured}"
            write_log(log_path, [configured, "--version"], 127, "", message)
            tool_results[tool_name] = {
                "configured_command": configured,
                "status": "failed",
                "error": message,
                "log": log_relative,
            }
            errors.append(message)
            continue

        completed = run_command([resolved, "--version"])
        version_output = "\n".join(
            part for part in (completed.stdout.strip(), completed.stderr.strip()) if part
        )
        write_log(
            log_path,
            [resolved, "--version"],
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
        valid_version = completed.returncode == 0 and version_matches_llvm_20(
            version_output
        )
        status = "passed" if valid_version else "failed"
        tool_results[tool_name] = {
            "configured_command": configured,
            "resolved_command": resolved,
            "status": status,
            "version": version_output,
            "sha256": sha256_file(Path(resolved)),
            "log": log_relative,
        }
        if valid_version:
            resolved_tools[tool_name] = resolved
        else:
            message = (
                f"{tool_name} is not a successful LLVM {EXPECTED_LLVM_MAJOR} tool: "
                f"{version_output or 'no version output'}"
            )
            errors.append(message)

    iwyu_tool = plan_tools["iwyu"]
    assert isinstance(iwyu_tool, dict)
    iwyu_source_dir = Path(str(iwyu_tool["source_dir"]))
    if not iwyu_source_dir.is_absolute():
        iwyu_source_dir = REPO_ROOT / iwyu_source_dir
    iwyu_source_dir = iwyu_source_dir.resolve()
    source_command = [
        "git",
        "-C",
        str(iwyu_source_dir),
        "rev-parse",
        "HEAD",
    ]
    source_completed = run_command(source_command)
    source_commit = source_completed.stdout.strip()
    source_log_relative = "logs/tool-iwyu-source.log"
    write_log(
        output_dir / source_log_relative,
        source_command,
        source_completed.returncode,
        source_completed.stdout,
        source_completed.stderr,
    )
    source_valid = (
        source_completed.returncode == 0 and source_commit == EXPECTED_IWYU_COMMIT
    )
    iwyu_result = tool_results.get("iwyu")
    assert isinstance(iwyu_result, dict)
    iwyu_result.update(
        {
            "source_dir": str(iwyu_source_dir),
            "source_commit": source_commit or None,
            "expected_source_commit": EXPECTED_IWYU_COMMIT,
            "source_status": "passed" if source_valid else "failed",
            "source_log": source_log_relative,
        }
    )
    if not source_valid:
        resolved_tools.pop("iwyu", None)
        message = (
            f"IWYU source checkout mismatch: expected {EXPECTED_IWYU_COMMIT}, "
            f"got {source_commit or 'unavailable'} from {iwyu_source_dir}"
        )
        errors.append(message)

    tidy_tool = plan_tools["clang-tidy"]
    assert isinstance(tidy_tool, dict)
    plugin = Path(str(tidy_tool["plugin"]))
    if not plugin.is_absolute():
        plugin = REPO_ROOT / plugin
    plugin = plugin.resolve()
    plugin_available = plugin.is_file()
    tool_results["bitcoin-tidy-plugin"] = {
        "path": str(plugin),
        "status": "passed" if plugin_available else "failed",
        "sha256": sha256_file(plugin) if plugin_available else None,
    }
    if not plugin_available:
        errors.append(f"bitcoin-tidy plugin is unavailable: {plugin}")

    check_results = report["checks"]
    assert isinstance(check_results, list)
    plan_checks = plan["checks"]
    assert isinstance(plan_checks, list)
    tool_for_kind = {
        "clang-tidy": "clang-tidy",
        "iwyu": "iwyu",
        "header-self-containment": "clang",
    }
    for raw_check in plan_checks:
        assert isinstance(raw_check, dict)
        check_id = str(raw_check["id"])
        kind = str(raw_check["kind"])
        command = list(raw_check["command"])
        tool_name = tool_for_kind[kind]
        log_relative = f"logs/{check_id}.log"
        log_path = output_dir / log_relative
        skip_reason = None
        if tool_name not in resolved_tools:
            skip_reason = f"{tool_name} did not pass version validation"
        elif kind == "clang-tidy" and not plugin_available:
            skip_reason = "bitcoin-tidy plugin is unavailable"

        if skip_reason is not None:
            write_log(log_path, command, 125, "", f"skipped: {skip_reason}")
            check_results.append(
                {
                    "id": check_id,
                    "kind": kind,
                    "input": raw_check["input"],
                    "status": "skipped",
                    "reason": skip_reason,
                    "log": log_relative,
                }
            )
            continue

        command[0] = resolved_tools[tool_name]
        if kind == "clang-tidy":
            command = [
                f"--load={plugin}" if argument.startswith("--load=") else argument
                for argument in command
            ]
        completed = run_command(command)
        write_log(
            log_path,
            command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
        status = "passed" if completed.returncode == 0 else "failed"
        check_results.append(
            {
                "id": check_id,
                "kind": kind,
                "input": raw_check["input"],
                "status": status,
                "return_code": completed.returncode,
                "log": log_relative,
            }
        )
        if completed.returncode != 0:
            errors.append(f"{check_id} failed with return code {completed.returncode}")

    report["status"] = "passed" if not errors else "failed"
    report_path = output_dir / "static-analysis-report.json"
    report_path.write_text(json_text(report), encoding="utf8")
    write_evidence_hashes(output_dir)

    if report["status"] == "passed":
        print(f"ML-DSA-44 static analysis passed; evidence: {output_dir}")
        return 0
    print(f"ML-DSA-44 static analysis failed; evidence: {output_dir}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit the isolated ML-DSA-44 wrapper with LLVM 20 tools"
    )
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--clang", default="clang-20")
    parser.add_argument("--clang-tidy", default="clang-tidy-20")
    parser.add_argument("--iwyu", default="include-what-you-use")
    parser.add_argument(
        "--iwyu-source-dir",
        default="/include-what-you-use",
    )
    parser.add_argument(
        "--bitcoin-tidy-plugin",
        default="/tidy-build/libbitcoin-tidy.so",
    )
    args = parser.parse_args()

    plan = build_plan(
        clang=args.clang,
        clang_tidy=args.clang_tidy,
        iwyu=args.iwyu,
        iwyu_source_dir=args.iwyu_source_dir,
        plugin=args.bitcoin_tidy_plugin,
    )
    if args.plan_only:
        print(json_text(plan), end="")
        return 0
    if args.output_dir is None:
        parser.error("--output-dir is required unless --plan-only is used")
    return execute_audit(plan, args.output_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, ValueError) as error:
        print(f"static analysis: {error}", file=sys.stderr)
        raise SystemExit(1)
