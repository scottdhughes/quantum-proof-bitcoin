#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

"""Run the versioned Valgrind constant-time audit for the isolated wrapper."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

import run_wrapper_tests as wrapper_contract


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
ENGINEERING_ROOT = "contrib/ml-dsa-engineering"
WRAPPER_SOURCE = f"{ENGINEERING_ROOT}/pqbtc_mldsa44.c"
PUBLIC_HEADER = f"{ENGINEERING_ROOT}/pqbtc_mldsa44.h"
TEST_HEADER = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_test.h"
CONFIG_HEADER = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_config.h"
CT_HARNESS = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_ct_memcheck.c"
CT_PROBE = f"{ENGINEERING_ROOT}/pqbtc_mldsa44_ct_probe.c"
SOURCE_MANIFEST = f"{ENGINEERING_ROOT}/vendor/mldsa-native/SOURCE.json"
VENDOR_SOURCE_ROOT = f"{ENGINEERING_ROOT}/vendor/mldsa-native"
FORBIDDEN_PROJECT_HEADER_SHADOWS = [
    f"{ENGINEERING_ROOT}/valgrind/memcheck.h",
    f"{ENGINEERING_ROOT}/valgrind/valgrind.h",
]

UPSTREAM_REPOSITORY = "https://github.com/pq-code-package/mldsa-native"
UPSTREAM_COMMIT = "9b0ee84f4cf399043eca59eca4e5f8531ca1d61b"
UPSTREAM_TREE = "c73c7029182122fce2f2dd8ac544ae990abd74a2"
UPSTREAM_ARCHIVE_SHA256 = (
    "4fd08a772d0a142863593471f0c26e239bac8babc8e2a960e072f06ee89ff30b"
)
UPSTREAM_VALGRIND_PATCH = "nix/valgrind/valgrind-varlat-patch-20240808.txt"
UPSTREAM_VALGRIND_PATCH_SHA256 = (
    "d54b140f2bacaea91470940a963950b7126685810df2192640cd103328b421f4"
)
UPSTREAM_FLAKE_LOCK = "flake.lock"
UPSTREAM_FLAKE_LOCK_SHA256 = (
    "cdc01dce87b0c9b8488baafb0e0ed5ec94064089f7b4d5b253aecfeef2ac1861"
)
UPSTREAM_NIXPKGS_REV = "23d72dabcb3b12469f57b37170fcbc1789bd7457"
UPSTREAM_NIXPKGS_NAR_HASH = "sha256-z5NJPSBwsLf/OfD8WTmh79tlSU8XgIbwmk6qB1/TFzY="
EXPECTED_NIX_VERSION = "nix (Nix) 2.24.9"
EXPECTED_VALGRIND_VERSION = "valgrind-3.26.0"
EXPECTED_VALGRIND_XML_PROTOCOL = "6"
ERROR_EXIT_CODE = 99

TOOLCHAINS = {
    "valgrind-varlat_clang20": {
        "compiler_family": "clang",
        "compiler_major": 20,
    },
    "valgrind-varlat_gcc13": {
        "compiler_family": "gcc",
        "compiler_major": 13,
    },
}

PROJECT_DECLASSIFICATIONS = [
    {
        "id": "randomizer_all_zero_predicate",
        "observable": "PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO",
    },
    {
        "id": "immediate_repeat_predicate",
        "observable": "PQBTC_MLDSA44_ERR_ENTROPY_REPEAT",
    },
]
PROJECT_SECRET_MARKERS = ["generated_randomizer"]

UPSTREAM_ACTIVE_DECLASSIFICATION_SITES = [
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/poly_kl.c:242",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/poly_kl.c:249",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:344",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:377",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:564",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:722",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:758",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:773",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:793",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:794",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:807",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:873",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:1200",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:1615",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/sign.c:1626",
]
UPSTREAM_INACTIVE_DECLASSIFICATION_SITES = [
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/poly_kl.c:257",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/poly_kl.c:263",
    f"{VENDOR_SOURCE_ROOT}/mldsa/src/poly.c:991",
]

COMMON_C_FLAGS = [
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wno-unused-function",
    "-Wno-unknown-pragmas",
    "-fvisibility=hidden",
    "-g",
    "-fno-omit-frame-pointer",
    "-iquote",
    ENGINEERING_ROOT,
    "-idirafter",
    ENGINEERING_ROOT,
]

VALGRIND_FLAGS = [
    "--tool=memcheck",
    f"--error-exitcode={ERROR_EXIT_CODE}",
    "--error-limit=no",
    "--undef-value-errors=yes",
    "--leak-check=full",
    "--show-leak-kinds=all",
    "--errors-for-leak-kinds=definite,indirect,possible",
    "--vex-guest-max-insns=55",
    "--variable-latency-errors=yes",
]

POSITIVE_CONTROLS = [
    {
        "id": "probe-branch",
        "argument": "branch",
        "expected_diagnostic": (
            "Conditional jump or move depends on uninitialised value"
        ),
        "expected_frame": {
            "file": "pqbtc_mldsa44_ct_probe.c",
            "function": "ProbeBranch",
        },
    },
    {
        "id": "probe-address",
        "argument": "address",
        "expected_diagnostic": "Use of uninitialised value of size",
        "expected_frame": {
            "file": "pqbtc_mldsa44_ct_probe.c",
            "function": "ProbeAddress",
        },
    },
    {
        "id": "probe-variable-latency",
        "argument": "variable-latency",
        "expected_diagnostic": "Variable-latency instruction operand",
        "expected_frame": {
            "file": "pqbtc_mldsa44_ct_probe.c",
            "function": "ProbeVariableLatency",
        },
    },
]

SECRET_KEY_TAINT_CONTROL = {
    "id": "secret-key-taint-control",
    "argument": "secret-key-taint",
    "expected_diagnostic": "Conditional jump or move depends on uninitialised value",
    "expected_frame": {
        "file": "pqbtc_mldsa44_ct_memcheck.c",
        "function": "ProbeSecretKeyTaint",
    },
}

EVIDENCE_SOURCES = [
    ".github/workflows/ml-dsa-44-wrapper-prototype.yml",
    "ci/test/test_ml_dsa_wrapper_prototype.py",
    "contrib/ml-dsa-engineering/README.md",
    "contrib/ml-dsa-engineering/backend_admission.json",
    "contrib/ml-dsa-engineering/run_valgrind_ct_analysis.py",
    "contrib/ml-dsa-engineering/run_wrapper_tests.py",
    "docs/ML_DSA_44_WRAPPER_PROTOTYPE.md",
    "docs/PQSIG_PRODUCTION_READINESS.md",
    WRAPPER_SOURCE,
    PUBLIC_HEADER,
    TEST_HEADER,
    CONFIG_HEADER,
    CT_HARNESS,
    CT_PROBE,
    SOURCE_MANIFEST,
]


class AuditError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def source_hashes() -> dict[str, str]:
    for relative in FORBIDDEN_PROJECT_HEADER_SHADOWS:
        path = REPO_ROOT / relative
        if path.exists() or path.is_symlink():
            raise AuditError(f"project path shadows a Valgrind header: {relative}")
    hashes = {}
    for relative in EVIDENCE_SOURCES:
        path = REPO_ROOT / relative
        if path.is_symlink():
            raise AuditError(f"audit input must not be a symlink: {relative}")
        if not path.is_file():
            raise AuditError(f"required audit input is missing: {relative}")
        hashes[relative] = sha256_file(path)
    return hashes


def marker_inventory(marker: str) -> list[str]:
    pattern = re.compile(rf"^\s*// {re.escape(marker)}: ([a-z0-9_]+)\s*$")
    return [
        match.group(1)
        for line in (REPO_ROOT / WRAPPER_SOURCE).read_text(encoding="utf8").splitlines()
        if (match := pattern.match(line)) is not None
    ]


def macro_call_inventory(relative: str, macro: str) -> list[dict[str, object]]:
    calls = []
    pattern = re.compile(rf"\b{re.escape(macro)}\s*\(")
    for line_number, line in enumerate(
        (REPO_ROOT / relative).read_text(encoding="utf8").splitlines(), start=1
    ):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue
        if pattern.search(line) is not None:
            calls.append(
                {
                    "path": relative,
                    "line": line_number,
                    "call": stripped,
                }
            )
    return calls


def upstream_declassification_inventory() -> dict[str, object]:
    calls = []
    vendor_root = REPO_ROOT / VENDOR_SOURCE_ROOT
    for path in sorted(vendor_root.rglob("*.c")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        calls.extend(macro_call_inventory(relative, "MLD_CT_TESTING_DECLASSIFY"))

    by_site = {f"{entry['path']}:{entry['line']}": entry for entry in calls}
    expected_active = set(UPSTREAM_ACTIVE_DECLASSIFICATION_SITES)
    expected_inactive = set(UPSTREAM_INACTIVE_DECLASSIFICATION_SITES)
    if set(by_site) != expected_active | expected_inactive:
        raise AuditError("upstream declassification call inventory changed")

    inventory: dict[str, object] = {
        "active": [by_site[site] for site in UPSTREAM_ACTIVE_DECLASSIFICATION_SITES],
        "inactive": [
            by_site[site] for site in UPSTREAM_INACTIVE_DECLASSIFICATION_SITES
        ],
    }
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    inventory["sha256"] = hashlib.sha256(encoded).hexdigest()
    return inventory


def wrapper_build_command(compiler: str) -> list[str]:
    return [
        compiler,
        *COMMON_C_FLAGS,
        "-O2",
        "-DPQBTC_MLDSA44_TESTING=1",
        "-DPQBTC_MLDSA44_CT_TESTING=1",
        WRAPPER_SOURCE,
        CT_HARNESS,
        "-pthread",
        "-o",
        "<output-dir>/bin/pqbtc_mldsa44_ct_memcheck",
    ]


def probe_build_command(compiler: str) -> list[str]:
    return [
        compiler,
        *COMMON_C_FLAGS,
        "-O0",
        CT_PROBE,
        "-o",
        "<output-dir>/bin/pqbtc_mldsa44_ct_probe",
    ]


def valgrind_command(
    valgrind: str, binary: str, xml_name: str, arguments: list[str]
) -> list[str]:
    return [
        valgrind,
        *VALGRIND_FLAGS,
        "--xml=yes",
        f"--xml-file=<output-dir>/logs/{xml_name}",
        f"<output-dir>/bin/{binary}",
        *arguments,
    ]


def build_plan(
    compiler: str,
    valgrind: str,
    toolchain_id: str,
) -> dict[str, object]:
    if toolchain_id not in TOOLCHAINS:
        raise AuditError(f"unsupported Valgrind toolchain: {toolchain_id}")
    manifest = wrapper_contract.validate_source_capsule()
    project_secret_calls = macro_call_inventory(
        WRAPPER_SOURCE, "PQBTC_MLDSA44_CT_SECRET"
    )
    project_declassification_calls = macro_call_inventory(
        WRAPPER_SOURCE, "PQBTC_MLDSA44_CT_DECLASSIFY"
    )
    project_valgrind_secret_calls = macro_call_inventory(
        WRAPPER_SOURCE, "VALGRIND_MAKE_MEM_UNDEFINED"
    )
    project_valgrind_declassification_calls = macro_call_inventory(
        WRAPPER_SOURCE, "VALGRIND_MAKE_MEM_DEFINED"
    )
    harness_secret_calls = macro_call_inventory(
        CT_HARNESS, "VALGRIND_MAKE_MEM_UNDEFINED"
    )
    harness_declassification_calls = macro_call_inventory(
        CT_HARNESS, "VALGRIND_MAKE_MEM_DEFINED"
    )
    positive_control_secret_calls = macro_call_inventory(
        CT_PROBE, "VALGRIND_MAKE_MEM_UNDEFINED"
    )
    upstream_inventory = upstream_declassification_inventory()
    checks = []
    for control in POSITIVE_CONTROLS:
        checks.append(
            {
                "id": control["id"],
                "kind": "positive-control",
                "expected_return_code": ERROR_EXIT_CODE,
                "expected_diagnostic": control["expected_diagnostic"],
                "expected_frame": control["expected_frame"],
                "executable": "bin/pqbtc_mldsa44_ct_probe",
                "arguments": [control["argument"]],
                "command": valgrind_command(
                    valgrind,
                    "pqbtc_mldsa44_ct_probe",
                    f"{control['id']}.xml",
                    [control["argument"]],
                ),
            }
        )
    checks.append(
        {
            "id": SECRET_KEY_TAINT_CONTROL["id"],
            "kind": "taint-control",
            "expected_return_code": ERROR_EXIT_CODE,
            "expected_diagnostic": SECRET_KEY_TAINT_CONTROL["expected_diagnostic"],
            "expected_frame": SECRET_KEY_TAINT_CONTROL["expected_frame"],
            "executable": "bin/pqbtc_mldsa44_ct_memcheck",
            "arguments": [SECRET_KEY_TAINT_CONTROL["argument"]],
            "command": valgrind_command(
                valgrind,
                "pqbtc_mldsa44_ct_memcheck",
                f"{SECRET_KEY_TAINT_CONTROL['id']}.xml",
                [SECRET_KEY_TAINT_CONTROL["argument"]],
            ),
        }
    )
    checks.append(
        {
            "id": "wrapper-ct",
            "kind": "wrapper-audit",
            "expected_return_code": 0,
            "expected_error_count": 0,
            "executable": "bin/pqbtc_mldsa44_ct_memcheck",
            "arguments": [],
            "command": valgrind_command(
                valgrind,
                "pqbtc_mldsa44_ct_memcheck",
                "wrapper-ct.xml",
                [],
            ),
        }
    )

    plan: dict[str, object] = {
        "schema_version": 1,
        "audit": "ml-dsa-44-isolated-wrapper-valgrind-ct",
        "scope": {
            "isolated_wrapper_only": True,
            "secret_key_signing": True,
            "wrapper_generated_randomizer_health_checks": True,
            "seeded_key_generation_is_setup_only": True,
            "key_generation_constant_time": False,
            "production_integration": False,
            "release_hold_unchanged": True,
            "observes": [
                "secret-dependent conditional branches",
                "secret-dependent effective addresses",
                "patched-VEX variable-latency operations",
                "Memcheck memory errors",
                "definite, indirect, and possible leaks",
            ],
            "not_covered": [
                "rejection-count statistics",
                "cache or speculative-execution leakage",
                "power or electromagnetic leakage",
                "ARM, macOS, or Windows execution",
                "native assembly",
                "secret erasure",
                "production fitness",
            ],
        },
        "host": {
            "required_system": "Linux",
            "required_machine": "x86_64",
        },
        "optimization": {
            "wrapper": "-O2",
            "positive_controls": "-O0",
        },
        "tools": {
            "nix": {
                "command": "nix",
                "expected_version": EXPECTED_NIX_VERSION,
            },
            "compiler": {
                "command": compiler,
                "toolchain_id": toolchain_id,
                **TOOLCHAINS[toolchain_id],
            },
            "valgrind": {
                "command": valgrind,
                "expected_version": EXPECTED_VALGRIND_VERSION,
                "expected_xml_protocol": EXPECTED_VALGRIND_XML_PROTOCOL,
                "flags": VALGRIND_FLAGS,
                "track_origins": False,
                "upstream_reference_error_exitcode": 1,
                "audit_error_exitcode": ERROR_EXIT_CODE,
                "project_suppressions": [],
            },
        },
        "upstream_environment": {
            "repository": UPSTREAM_REPOSITORY,
            "commit": UPSTREAM_COMMIT,
            "git_tree": UPSTREAM_TREE,
            "git_archive_tar_sha256": UPSTREAM_ARCHIVE_SHA256,
            "nix_shell": toolchain_id,
            "valgrind_patch": UPSTREAM_VALGRIND_PATCH,
            "valgrind_patch_sha256": UPSTREAM_VALGRIND_PATCH_SHA256,
            "flake_lock": UPSTREAM_FLAKE_LOCK,
            "flake_lock_sha256": UPSTREAM_FLAKE_LOCK_SHA256,
            "nixpkgs_rev": UPSTREAM_NIXPKGS_REV,
            "nixpkgs_nar_hash": UPSTREAM_NIXPKGS_NAR_HASH,
        },
        "source_capsule": {
            "commit": manifest["commit"],
            "capsule_sha256": manifest["capsule_hash"]["value"],
            "manifest_sha256": sha256_file(REPO_ROOT / SOURCE_MANIFEST),
            "verified_against_checked_in_files": True,
        },
        "taint_contract": {
            "secret_key_bytes": 2560,
            "randomizer_bytes": 32,
            "successful_hedged_signatures": 5,
            "immediate_repeat_failures": 1,
            "all_zero_failures": 1,
            "project_secret_markers": marker_inventory("PQBTC_CT_SECRET"),
            "project_secret_calls": project_secret_calls,
            "project_declassifications": [
                {
                    **entry,
                    "reason": "predicate is exposed through the public result code",
                }
                for entry in PROJECT_DECLASSIFICATIONS
            ],
            "observed_project_declassification_markers": marker_inventory(
                "PQBTC_CT_DECLASSIFICATION"
            ),
            "project_declassification_calls": project_declassification_calls,
            "project_valgrind_secret_calls": project_valgrind_secret_calls,
            "project_valgrind_declassification_calls": (
                project_valgrind_declassification_calls
            ),
            "harness_secret_calls": harness_secret_calls,
            "harness_declassification_calls": harness_declassification_calls,
            "positive_control_secret_calls": positive_control_secret_calls,
            "upstream_declassification_inventory": upstream_inventory,
            "upstream_active_declassification_sites": len(
                upstream_inventory["active"]
            ),
            "upstream_syntactic_declassification_sites": len(
                upstream_inventory["active"]
            )
            + len(upstream_inventory["inactive"]),
            "combined_active_source_declassification_sites": len(
                upstream_inventory["active"]
            )
            + len(project_declassification_calls),
            "manual_output_declassification": bool(harness_declassification_calls),
        },
        "builds": [
            {
                "id": "build-wrapper",
                "output": "bin/pqbtc_mldsa44_ct_memcheck",
                "command": wrapper_build_command(compiler),
            },
            {
                "id": "build-probe",
                "output": "bin/pqbtc_mldsa44_ct_probe",
                "command": probe_build_command(compiler),
            },
        ],
        "checks": checks,
        "source_files": source_hashes(),
    }
    validate_plan(plan)
    return plan


def validate_plan(plan: dict[str, object]) -> None:
    if plan.get("optimization") != {
        "wrapper": "-O2",
        "positive_controls": "-O0",
    }:
        raise AuditError("Valgrind optimization contract changed")
    tools = plan.get("tools")
    if not isinstance(tools, dict):
        raise AuditError("Valgrind plan has no tool contract")
    valgrind = tools.get("valgrind")
    if not isinstance(valgrind, dict):
        raise AuditError("Valgrind plan has no Memcheck contract")
    if valgrind.get("expected_version") != EXPECTED_VALGRIND_VERSION:
        raise AuditError("Valgrind version pin changed")
    if valgrind.get("expected_xml_protocol") != EXPECTED_VALGRIND_XML_PROTOCOL:
        raise AuditError("Valgrind XML protocol pin changed")
    if valgrind.get("flags") != VALGRIND_FLAGS:
        raise AuditError("Valgrind flags changed")
    if valgrind.get("project_suppressions") != []:
        raise AuditError("project suppressions are not allowed")
    nix = tools.get("nix")
    if not isinstance(nix, dict):
        raise AuditError("Valgrind plan has no Nix contract")
    if nix.get("expected_version") != EXPECTED_NIX_VERSION:
        raise AuditError("Nix version pin changed")

    environment = plan.get("upstream_environment")
    if not isinstance(environment, dict):
        raise AuditError("Valgrind plan has no upstream environment")
    expected_environment = {
        "repository": UPSTREAM_REPOSITORY,
        "commit": UPSTREAM_COMMIT,
        "git_tree": UPSTREAM_TREE,
        "git_archive_tar_sha256": UPSTREAM_ARCHIVE_SHA256,
        "valgrind_patch": UPSTREAM_VALGRIND_PATCH,
        "valgrind_patch_sha256": UPSTREAM_VALGRIND_PATCH_SHA256,
        "flake_lock": UPSTREAM_FLAKE_LOCK,
        "flake_lock_sha256": UPSTREAM_FLAKE_LOCK_SHA256,
        "nixpkgs_rev": UPSTREAM_NIXPKGS_REV,
        "nixpkgs_nar_hash": UPSTREAM_NIXPKGS_NAR_HASH,
    }
    for key, expected in expected_environment.items():
        if environment.get(key) != expected:
            raise AuditError(f"upstream environment pin changed: {key}")

    taint = plan.get("taint_contract")
    if not isinstance(taint, dict):
        raise AuditError("Valgrind plan has no taint contract")
    expected_declassifications = [entry["id"] for entry in PROJECT_DECLASSIFICATIONS]
    observed = taint.get("observed_project_declassification_markers")
    if observed != expected_declassifications:
        raise AuditError(
            f"unexpected project declassification inventory: {observed}"
        )
    if taint.get("project_secret_markers") != PROJECT_SECRET_MARKERS:
        raise AuditError("unexpected project secret-marker inventory")
    if [entry.get("call") for entry in taint.get("project_secret_calls", [])] != [
        "PQBTC_MLDSA44_CT_SECRET(ptr, PQBTC_MLDSA44_RANDOMIZER_BYTES);"
    ]:
        raise AuditError("unexpected project secret-call inventory")
    if [
        entry.get("call")
        for entry in taint.get("project_declassification_calls", [])
    ] != [
        "PQBTC_MLDSA44_CT_DECLASSIFY(&all_zero, sizeof(all_zero));",
        "PQBTC_MLDSA44_CT_DECLASSIFY(&repeated, sizeof(repeated));",
    ]:
        raise AuditError("unexpected project declassification-call inventory")
    if [
        entry.get("call") for entry in taint.get("project_valgrind_secret_calls", [])
    ] != ["VALGRIND_MAKE_MEM_UNDEFINED((ptr), (len))"]:
        raise AuditError("unexpected project Valgrind secret-call inventory")
    if [
        entry.get("call")
        for entry in taint.get("project_valgrind_declassification_calls", [])
    ] != ["VALGRIND_MAKE_MEM_DEFINED((ptr), (len))"]:
        raise AuditError("unexpected project Valgrind declassification-call inventory")
    if [entry.get("call") for entry in taint.get("harness_secret_calls", [])] != [
        "VALGRIND_MAKE_MEM_UNDEFINED(secret_key, sizeof(secret_key));"
    ]:
        raise AuditError("unexpected harness secret-call inventory")
    if taint.get("harness_declassification_calls") != []:
        raise AuditError("audit harness must not contain declassification calls")
    if len(taint.get("positive_control_secret_calls", [])) != 3:
        raise AuditError("positive controls must contain three secret calls")
    upstream_inventory = taint.get("upstream_declassification_inventory")
    if not isinstance(upstream_inventory, dict):
        raise AuditError("upstream declassification inventory is missing")
    if len(upstream_inventory.get("active", [])) != 15:
        raise AuditError("upstream active declassification inventory changed")
    if len(upstream_inventory.get("inactive", [])) != 3:
        raise AuditError("upstream inactive declassification inventory changed")
    inventory_body = {
        "active": upstream_inventory["active"],
        "inactive": upstream_inventory["inactive"],
    }
    expected_inventory_hash = hashlib.sha256(
        json.dumps(inventory_body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if upstream_inventory.get("sha256") != expected_inventory_hash:
        raise AuditError("upstream declassification inventory hash is invalid")
    if taint.get("manual_output_declassification") is not False:
        raise AuditError("audit harness must not declassify released outputs")

    builds = plan.get("builds")
    if not isinstance(builds, list) or len(builds) != 2:
        raise AuditError("Valgrind plan must have two builds")
    for build in builds:
        if not isinstance(build, dict) or not isinstance(build.get("command"), list):
            raise AuditError("invalid Valgrind build contract")
        command = build["command"]
        if "-std=c11" not in command:
            raise AuditError(f"{build.get('id')} lacks the C11 contract")
        for search_flag in ("-iquote", "-idirafter"):
            if search_flag not in command:
                raise AuditError(f"{build.get('id')} lacks {search_flag}")
            if command[command.index(search_flag) + 1] != ENGINEERING_ROOT:
                raise AuditError(f"{build.get('id')} has an unsafe header search path")
    wrapper_build = builds[0]["command"]
    probe_build = builds[1]["command"]
    if "-O2" not in wrapper_build or "-O0" not in probe_build:
        raise AuditError("wrapper/probe optimization contract changed")
    for required in (
        "-DPQBTC_MLDSA44_TESTING=1",
        "-DPQBTC_MLDSA44_CT_TESTING=1",
        WRAPPER_SOURCE,
        CT_HARNESS,
    ):
        if required not in wrapper_build:
            raise AuditError(f"wrapper CT build lacks {required}")

    checks = plan.get("checks")
    if not isinstance(checks, list) or len(checks) != 5:
        raise AuditError("Valgrind plan must have four controls and one audit")
    positive = [check for check in checks if check.get("kind") == "positive-control"]
    taint_controls = [check for check in checks if check.get("kind") == "taint-control"]
    wrapper = [check for check in checks if check.get("kind") == "wrapper-audit"]
    if len(positive) != 3 or len(taint_controls) != 1 or len(wrapper) != 1:
        raise AuditError("unexpected Valgrind check inventory")
    if {check.get("id") for check in positive} != {
        control["id"] for control in POSITIVE_CONTROLS
    }:
        raise AuditError("positive-control ids changed")
    if taint_controls[0].get("id") != SECRET_KEY_TAINT_CONTROL["id"]:
        raise AuditError("secret-key taint-control id changed")
    for check in checks:
        command = check.get("command")
        if not isinstance(command, list):
            raise AuditError("Valgrind check has no command")
        expected_executable = f"<output-dir>/{check.get('executable')}"
        if expected_executable not in command:
            raise AuditError(f"{check.get('id')} executable contract changed")
        executable_index = command.index(expected_executable)
        if command[executable_index + 1 :] != check.get("arguments"):
            raise AuditError(f"{check.get('id')} argument contract changed")
        for flag in VALGRIND_FLAGS:
            if flag not in command:
                raise AuditError(f"{check.get('id')} lacks {flag}")
        if check.get("kind") in ("positive-control", "taint-control"):
            expected_frame = check.get("expected_frame")
            if not isinstance(expected_frame, dict):
                raise AuditError(f"{check.get('id')} lacks stack attribution")


def run_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf8",
        errors="replace",
    )


def run_binary_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
    (resolved / "bin").mkdir()
    return resolved


def resolve_tool(command: str) -> str | None:
    resolved = shutil.which(command)
    if resolved is not None:
        return str(Path(resolved).resolve())
    candidate = Path(command)
    if candidate.is_file():
        return str(candidate.resolve())
    return None


def repository_state() -> dict[str, object]:
    commit = run_command(["git", "rev-parse", "HEAD"])
    unstaged = run_binary_command(["git", "diff", "--name-only", "-z", "--"])
    staged = run_binary_command(
        ["git", "diff", "--cached", "--name-only", "-z", "--"]
    )
    untracked = run_binary_command(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"]
    )
    tracked_sources = run_binary_command(
        ["git", "ls-files", "-z", "--", *EVIDENCE_SOURCES]
    )

    def paths(completed: subprocess.CompletedProcess[bytes]) -> list[str]:
        if completed.returncode != 0:
            return []
        return sorted(
            entry.decode("utf8", errors="surrogateescape")
            for entry in completed.stdout.split(b"\0")
            if entry
        )

    tracked_changes = sorted(set(paths(unstaged)) | set(paths(staged)))
    untracked_files = paths(untracked)
    all_changes = sorted(set(tracked_changes) | set(untracked_files))
    audit_inputs = set(EVIDENCE_SOURCES)
    dirty_audit_inputs = sorted(
        path
        for path in all_changes
        if path in audit_inputs or path.startswith(f"{ENGINEERING_ROOT}/")
    )
    tracked_source_set = set(paths(tracked_sources))
    untracked_evidence_sources = sorted(audit_inputs - tracked_source_set)
    commands_valid = all(
        completed.returncode == 0
        for completed in (unstaged, staged, untracked, tracked_sources)
    )
    return {
        "commit": commit.stdout.strip() if commit.returncode == 0 else "unknown",
        "worktree_dirty": bool(all_changes) if commands_valid else None,
        "tracked_changes": sorted(tracked_changes),
        "untracked_files": untracked_files,
        "audit_input_dirty": bool(dirty_audit_inputs)
        if commands_valid
        else None,
        "dirty_audit_inputs": dirty_audit_inputs,
        "all_audit_inputs_tracked": not untracked_evidence_sources
        if commands_valid
        else None,
        "untracked_evidence_sources": untracked_evidence_sources,
    }


def upstream_identity(source_dir: Path) -> dict[str, object]:
    resolved = source_dir.resolve()
    commit = run_command(["git", "rev-parse", "HEAD"], cwd=resolved)
    tree = run_command(["git", "rev-parse", "HEAD^{tree}"], cwd=resolved)
    status = run_command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=resolved
    )
    archive = run_binary_command(
        ["git", "archive", "--format=tar", "HEAD"], cwd=resolved
    )
    patch = resolved / UPSTREAM_VALGRIND_PATCH
    flake_lock = resolved / UPSTREAM_FLAKE_LOCK
    nixpkgs_locked: dict[str, object] = {}
    if flake_lock.is_file():
        try:
            lock_data = json.loads(flake_lock.read_text(encoding="utf8"))
            if isinstance(lock_data, dict):
                nodes = lock_data.get("nodes", {})
                if isinstance(nodes, dict):
                    nixpkgs = nodes.get("nixpkgs", {})
                    if isinstance(nixpkgs, dict):
                        locked = nixpkgs.get("locked", {})
                        if isinstance(locked, dict):
                            nixpkgs_locked = locked
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "path": str(resolved),
        "commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "git_tree": tree.stdout.strip() if tree.returncode == 0 else None,
        "worktree_clean": status.returncode == 0 and not status.stdout.strip(),
        "worktree_status": status.stdout.splitlines()
        if status.returncode == 0
        else None,
        "git_archive_tar_sha256": hashlib.sha256(archive.stdout).hexdigest()
        if archive.returncode == 0
        else None,
        "valgrind_patch_sha256": sha256_file(patch) if patch.is_file() else None,
        "flake_lock_sha256": sha256_file(flake_lock)
        if flake_lock.is_file()
        else None,
        "nixpkgs_rev": nixpkgs_locked.get("rev"),
        "nixpkgs_nar_hash": nixpkgs_locked.get("narHash"),
        "validation_errors": [
            message
            for valid, message in (
                (
                    commit.returncode == 0 and commit.stdout.strip() == UPSTREAM_COMMIT,
                    "upstream commit mismatch",
                ),
                (
                    tree.returncode == 0 and tree.stdout.strip() == UPSTREAM_TREE,
                    "upstream git tree mismatch",
                ),
                (
                    archive.returncode == 0
                    and hashlib.sha256(archive.stdout).hexdigest()
                    == UPSTREAM_ARCHIVE_SHA256,
                    "upstream git archive mismatch",
                ),
                (
                    patch.is_file()
                    and sha256_file(patch) == UPSTREAM_VALGRIND_PATCH_SHA256,
                    "upstream Valgrind patch mismatch",
                ),
                (
                    status.returncode == 0 and not status.stdout.strip(),
                    "upstream worktree is dirty",
                ),
                (
                    flake_lock.is_file()
                    and sha256_file(flake_lock) == UPSTREAM_FLAKE_LOCK_SHA256,
                    "upstream flake.lock mismatch",
                ),
                (
                    nixpkgs_locked.get("rev") == UPSTREAM_NIXPKGS_REV,
                    "upstream nixpkgs revision mismatch",
                ),
                (
                    nixpkgs_locked.get("narHash") == UPSTREAM_NIXPKGS_NAR_HASH,
                    "upstream nixpkgs narHash mismatch",
                ),
            )
            if not valid
        ],
    }


def compiler_version_matches(version: str, family: str, major: int) -> bool:
    banner = next((line.strip() for line in version.splitlines() if line.strip()), "")
    if family == "clang":
        return (
            re.search(rf"\bclang version {major}(?:\.|\b)", banner, re.I)
            is not None
        )
    return "clang" not in banner.lower() and re.search(
        rf"\b(?:gcc|cc)\b.*\b{major}(?:\.|\b)", banner, re.I
    ) is not None


def predefined_macros(output: str) -> dict[str, str]:
    macros = {}
    for line in output.splitlines():
        match = re.fullmatch(r"#define\s+([A-Za-z0-9_]+)(?:\s+(.*))?", line)
        if match is not None:
            macros[match.group(1)] = match.group(2) or ""
    return macros


def compiler_macros_match(
    macros: dict[str, str], family: str, major: int
) -> bool:
    if family == "clang":
        return macros.get("__clang__") == "1" and macros.get(
            "__clang_major__"
        ) == str(major)
    return (
        "__clang__" not in macros
        and macros.get("__GNUC__") == str(major)
    )


def materialize_command(
    command: list[str],
    output_dir: Path,
    configured_compiler: str,
    resolved_compiler: str,
    configured_valgrind: str,
    resolved_valgrind: str,
) -> list[str]:
    materialized = []
    for argument in command:
        if argument == configured_compiler:
            argument = resolved_compiler
        elif argument == configured_valgrind:
            argument = resolved_valgrind
        materialized.append(argument.replace("<output-dir>", str(output_dir)))
    return materialized


def valgrind_frame_matches(
    frame: dict[str, object], expected_frame: dict[str, object]
) -> bool:
    actual_file = str(frame.get("file", "")).replace("\\", "/")
    expected_file = str(expected_frame.get("file", "")).replace("\\", "/")
    actual_parts = PurePosixPath(actual_file).parts
    expected_parts = PurePosixPath(expected_file).parts
    expected_function = str(expected_frame.get("function", ""))
    actual_function = str(frame.get("function", ""))
    return (
        bool(expected_parts)
        and len(actual_parts) >= len(expected_parts)
        and actual_parts[-len(expected_parts) :] == expected_parts
        and bool(expected_function)
        and (
            actual_function == expected_function
            or actual_function.startswith(f"{expected_function}.")
        )
    )


def parse_valgrind_xml(
    path: Path, expected_executable: Path, expected_arguments: list[str]
) -> dict[str, object]:
    root = ET.parse(path).getroot()
    validation_errors = []
    if root.tag != "valgrindoutput":
        validation_errors.append(f"unexpected XML root: {root.tag}")
    if root.findtext("protocolversion") != EXPECTED_VALGRIND_XML_PROTOCOL:
        validation_errors.append("unexpected Valgrind XML protocol version")
    if root.findtext("protocoltool") != "memcheck":
        validation_errors.append("unexpected Valgrind XML protocol tool")
    if root.findtext("tool") != "memcheck":
        validation_errors.append("unexpected Valgrind XML runtime tool")

    argv = root.find("args/argv")
    recorded_executable = argv.findtext("exe") if argv is not None else None
    recorded_arguments = (
        [argument.text or "" for argument in argv.findall("arg")]
        if argv is not None
        else []
    )
    if recorded_executable is None or Path(recorded_executable).resolve() != (
        expected_executable.resolve()
    ):
        validation_errors.append("Valgrind XML executable does not match the check")
    if recorded_arguments != expected_arguments:
        validation_errors.append("Valgrind XML arguments do not match the check")

    states = [status.findtext("state") or "" for status in root.findall("status")]
    if states != ["RUNNING", "FINISHED"]:
        validation_errors.append("Valgrind XML does not record terminal completion")

    error_summary: dict[str, int] = {}
    for field in (
        "errors",
        "error_contexts",
        "suppressed",
        "suppressed_contexts",
    ):
        value = root.findtext(f"error_summary/{field}")
        try:
            parsed = int(value) if value is not None else -1
        except ValueError:
            parsed = -1
        if parsed < 0:
            validation_errors.append(
                f"Valgrind XML has no valid protocol-6 {field} summary"
            )
        else:
            error_summary[field] = parsed
    summary_error_count = error_summary.get("errors")

    errors = []
    for error in root.findall("error"):
        what = error.findtext("what")
        if what is None:
            what = error.findtext("xwhat/text")
        frames = []
        for stack in error.findall("stack"):
            for frame in stack.findall("frame"):
                frames.append(
                    {
                        "function": frame.findtext("fn") or "",
                        "file": frame.findtext("file") or "",
                        "line": frame.findtext("line") or "",
                        "object": frame.findtext("obj") or "",
                    }
                )
        errors.append(
            {
                "kind": error.findtext("kind") or "unknown",
                "what": what or "",
                "frames": frames,
            }
        )
    return {
        "valid": not validation_errors,
        "validation_errors": validation_errors,
        "protocol_version": root.findtext("protocolversion"),
        "protocol_tool": root.findtext("protocoltool"),
        "runtime_tool": root.findtext("tool"),
        "recorded_executable": recorded_executable,
        "recorded_arguments": recorded_arguments,
        "states": states,
        "error_summary": error_summary,
        "summary_error_count": summary_error_count,
        "error_count": len(errors),
        "errors": errors,
        "variable_latency_count": sum(
            "Variable-latency instruction operand" in error["what"]
            for error in errors
        ),
        "leak_error_count": sum(
            str(error["kind"]).startswith("Leak_") for error in errors
        ),
    }


def write_evidence_hashes(output_dir: Path) -> None:
    lines = []
    resolved_root = output_dir.resolve()
    manifest = resolved_root / "SHA256SUMS"
    if manifest.exists() or manifest.is_symlink():
        raise AuditError("evidence SHA256SUMS already exists")
    for path in sorted(output_dir.rglob("*")):
        if path.is_symlink():
            raise AuditError(f"evidence tree contains a symlink: {path}")
        if path == manifest:
            raise AuditError("evidence SHA256SUMS appeared while hashing")
        if path.is_dir():
            continue
        mode = path.stat(follow_symlinks=False).st_mode
        if not stat.S_ISREG(mode):
            raise AuditError(f"evidence tree contains a non-regular file: {path}")
        resolved = path.resolve(strict=True)
        if resolved_root != resolved and resolved_root not in resolved.parents:
            raise AuditError(f"evidence file escapes output directory: {path}")
        relative = resolved.relative_to(resolved_root).as_posix()
        lines.append(f"{sha256_file(resolved)}  {relative}\n")
    descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "w", encoding="utf8") as manifest_file:
        manifest_file.write("".join(lines))


def execute_audit(
    plan: dict[str, object],
    requested_output_dir: Path,
    upstream_source_dir: Path,
) -> int:
    started = time.monotonic()
    output_dir = prepare_output_dir(requested_output_dir)
    plan_path = output_dir / "valgrind-ct-plan.json"
    plan_path.write_text(json_text(plan), encoding="utf8")

    repository = repository_state()
    upstream = upstream_identity(upstream_source_dir)
    host = {
        "system": platform.system(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }
    report: dict[str, object] = {
        "schema_version": 1,
        "audit": plan["audit"],
        "status": "failed",
        "repository": repository,
        "upstream_environment": upstream,
        "host": host,
        "plan_sha256": sha256_file(plan_path),
        "tools": {},
        "builds": [],
        "checks": [],
        "errors": [],
    }
    errors = report["errors"]
    assert isinstance(errors, list)
    if repository["audit_input_dirty"] is not False:
        errors.append(
            "audit inputs must be clean: "
            + ", ".join(repository["dirty_audit_inputs"])
        )
    if repository["all_audit_inputs_tracked"] is not True:
        errors.append(
            "all audit inputs must be Git-tracked: "
            + ", ".join(repository["untracked_evidence_sources"])
        )
    errors.extend(upstream["validation_errors"])
    if host["system"] != "Linux" or host["machine"] not in ("x86_64", "amd64"):
        errors.append(
            f"audit requires x86_64 Linux, got {host['machine']} {host['system']}"
        )

    tools = plan["tools"]
    assert isinstance(tools, dict)
    nix_contract = tools["nix"]
    compiler_contract = tools["compiler"]
    valgrind_contract = tools["valgrind"]
    assert isinstance(nix_contract, dict)
    assert isinstance(compiler_contract, dict)
    assert isinstance(valgrind_contract, dict)
    configured_nix = str(nix_contract["command"])
    configured_compiler = str(compiler_contract["command"])
    configured_valgrind = str(valgrind_contract["command"])
    resolved_nix = resolve_tool(configured_nix)
    resolved_compiler = resolve_tool(configured_compiler)
    resolved_valgrind = resolve_tool(configured_valgrind)

    nix_result: dict[str, object] = {
        "configured_command": configured_nix,
        "resolved_command": resolved_nix,
        "status": "failed",
    }
    compiler_result: dict[str, object] = {
        "configured_command": configured_compiler,
        "resolved_command": resolved_compiler,
        "status": "failed",
    }
    valgrind_result: dict[str, object] = {
        "configured_command": configured_valgrind,
        "resolved_command": resolved_valgrind,
        "status": "failed",
    }
    report_tools = report["tools"]
    assert isinstance(report_tools, dict)
    report_tools["nix"] = nix_result
    report_tools["compiler"] = compiler_result
    report_tools["valgrind"] = valgrind_result

    if resolved_nix is None:
        errors.append(f"required Nix is unavailable: {configured_nix}")
    else:
        completed = run_command([resolved_nix, "--version"])
        version = completed.stdout.strip()
        valid = completed.returncode == 0 and version == EXPECTED_NIX_VERSION
        nix_result.update(
            {
                "status": "passed" if valid else "failed",
                "version": version,
                "sha256": sha256_file(Path(resolved_nix)),
            }
        )
        if not valid:
            errors.append("Nix identity does not match the pinned installer")

    if resolved_compiler is None:
        errors.append(f"required compiler is unavailable: {configured_compiler}")
    else:
        completed = run_command([resolved_compiler, "--version"])
        macros_completed = run_command(
            [resolved_compiler, "-dM", "-E", "-x", "c", "/dev/null"]
        )
        version = "\n".join(
            part for part in (completed.stdout.strip(), completed.stderr.strip()) if part
        )
        family = str(compiler_contract["compiler_family"])
        major = int(compiler_contract["compiler_major"])
        macros = predefined_macros(macros_completed.stdout)
        valid = (
            completed.returncode == 0
            and compiler_version_matches(version, family, major)
            and macros_completed.returncode == 0
            and compiler_macros_match(macros, family, major)
        )
        compiler_result.update(
            {
                "status": "passed" if valid else "failed",
                "version": version,
                "sha256": sha256_file(Path(resolved_compiler)),
                "predefined_macros": {
                    name: macros[name]
                    for name in ("__clang__", "__clang_major__", "__GNUC__")
                    if name in macros
                },
            }
        )
        if not valid:
            errors.append("compiler identity does not match the pinned Nix shell")

    valgrind_help = ""
    if resolved_valgrind is None:
        errors.append(f"required Valgrind is unavailable: {configured_valgrind}")
    else:
        version_completed = run_command([resolved_valgrind, "--version"])
        help_completed = run_command([resolved_valgrind, "--help"])
        version = version_completed.stdout.strip()
        valgrind_help = "\n".join(
            part
            for part in (help_completed.stdout.strip(), help_completed.stderr.strip())
            if part
        )
        valid = (
            version_completed.returncode == 0
            and version == EXPECTED_VALGRIND_VERSION
            and help_completed.returncode == 0
            and "--variable-latency-errors" in valgrind_help
        )
        valgrind_result.update(
            {
                "status": "passed" if valid else "failed",
                "version": version,
                "sha256": sha256_file(Path(resolved_valgrind)),
                "variable_latency_option_present": (
                    "--variable-latency-errors" in valgrind_help
                ),
            }
        )
        if not valid:
            errors.append("Valgrind identity or variable-latency patch check failed")

    (output_dir / "logs" / "toolchain.log").write_text(
        json_text(
            {
                "host": host,
                "upstream_environment": upstream,
                "nix": nix_result,
                "compiler": compiler_result,
                "valgrind": valgrind_result,
            }
        ),
        encoding="utf8",
    )

    builds = plan["builds"]
    assert isinstance(builds, list)
    build_status: dict[str, bool] = {}
    build_results = report["builds"]
    assert isinstance(build_results, list)
    tools_valid = (
        nix_result["status"] == "passed"
        and compiler_result["status"] == "passed"
        and valgrind_result["status"] == "passed"
    )
    preconditions_valid = (
        repository["audit_input_dirty"] is False
        and repository["all_audit_inputs_tracked"] is True
        and not upstream["validation_errors"]
        and host["system"] == "Linux"
        and host["machine"] in ("x86_64", "amd64")
    )
    for build in builds:
        assert isinstance(build, dict)
        build_id = str(build["id"])
        log_relative = f"logs/{build_id}.log"
        if not tools_valid or not preconditions_valid:
            reason = "tool, source, or host validation failed"
            write_log(output_dir / log_relative, list(build["command"]), 125, "", reason)
            build_results.append(
                {
                    "id": build_id,
                    "status": "skipped",
                    "reason": reason,
                    "log": log_relative,
                }
            )
            build_status[build_id] = False
            continue
        assert resolved_compiler is not None
        assert resolved_valgrind is not None
        command = materialize_command(
            list(build["command"]),
            output_dir,
            configured_compiler,
            resolved_compiler,
            configured_valgrind,
            resolved_valgrind,
        )
        completed = run_command(command)
        write_log(
            output_dir / log_relative,
            command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
        passed = completed.returncode == 0
        build_status[build_id] = passed
        build_results.append(
            {
                "id": build_id,
                "status": "passed" if passed else "failed",
                "return_code": completed.returncode,
                "log": log_relative,
                "binary": build["output"],
                "binary_sha256": sha256_file(output_dir / str(build["output"]))
                if passed
                else None,
            }
        )
        if not passed:
            errors.append(f"{build_id} failed with return code {completed.returncode}")

    check_results = report["checks"]
    assert isinstance(check_results, list)
    checks = plan["checks"]
    assert isinstance(checks, list)
    for check in checks:
        assert isinstance(check, dict)
        check_id = str(check["id"])
        kind = str(check["kind"])
        required_build = "build-probe" if kind == "positive-control" else "build-wrapper"
        log_relative = f"logs/{check_id}.log"
        xml_relative = f"logs/{check_id}.xml"
        if not build_status.get(required_build, False):
            reason = f"{required_build} did not pass"
            write_log(output_dir / log_relative, list(check["command"]), 125, "", reason)
            check_results.append(
                {
                    "id": check_id,
                    "kind": kind,
                    "status": "skipped",
                    "reason": reason,
                    "log": log_relative,
                    "xml": xml_relative,
                }
            )
            continue
        assert resolved_compiler is not None
        assert resolved_valgrind is not None
        command = materialize_command(
            list(check["command"]),
            output_dir,
            configured_compiler,
            resolved_compiler,
            configured_valgrind,
            resolved_valgrind,
        )
        completed = run_command(command)
        write_log(
            output_dir / log_relative,
            command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
        )
        if check_id == "wrapper-ct":
            (output_dir / "logs" / "wrapper-ct.stdout").write_text(
                completed.stdout, encoding="utf8"
            )
        xml_path = output_dir / xml_relative
        xml_result: dict[str, object]
        try:
            xml_result = parse_valgrind_xml(
                xml_path,
                output_dir / str(check["executable"]),
                [str(argument) for argument in check["arguments"]],
            )
        except (ET.ParseError, OSError) as error:
            xml_result = {
                "valid": False,
                "validation_errors": [str(error)],
                "error_count": None,
                "errors": [],
                "variable_latency_count": None,
                "leak_error_count": None,
                "parse_error": str(error),
            }

        passed = (
            completed.returncode == int(check["expected_return_code"])
            and xml_result.get("valid") is True
        )
        if kind in ("positive-control", "taint-control"):
            expected = str(check["expected_diagnostic"])
            expected_frame = check["expected_frame"]
            assert isinstance(expected_frame, dict)
            passed = (
                passed
                and int(xml_result.get("summary_error_count") or 0) > 0
                and any(
                    expected in str(error["what"])
                    and any(
                        valgrind_frame_matches(frame, expected_frame)
                        for frame in error.get("frames", [])
                    )
                    for error in xml_result.get("errors", [])
                )
            )
        else:
            passed = (
                passed
                and xml_result.get("error_count") == 0
                and xml_result.get("summary_error_count") == 0
            )
        check_results.append(
            {
                "id": check_id,
                "kind": kind,
                "status": "passed" if passed else "failed",
                "return_code": completed.returncode,
                "expected_return_code": check["expected_return_code"],
                "log": log_relative,
                "xml": xml_relative,
                "valgrind": xml_result,
            }
        )
        if not passed:
            errors.append(f"{check_id} did not meet its Valgrind contract")

    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report["status"] = "passed" if not errors else "failed"
    report_path = output_dir / "valgrind-ct-report.json"
    report_path.write_text(json_text(report), encoding="utf8")
    write_evidence_hashes(output_dir)
    if report["status"] == "passed":
        print(f"ML-DSA-44 Valgrind CT audit passed; evidence: {output_dir}")
        return 0
    print(f"ML-DSA-44 Valgrind CT audit failed; evidence: {output_dir}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit the isolated ML-DSA-44 wrapper with patched Valgrind"
    )
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--upstream-source-dir", type=Path)
    parser.add_argument(
        "--toolchain-id",
        choices=sorted(TOOLCHAINS),
        default="valgrind-varlat_clang20",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--valgrind", default="valgrind")
    args = parser.parse_args()

    plan = build_plan(args.cc, args.valgrind, args.toolchain_id)
    if args.plan_only:
        print(json_text(plan), end="")
        return 0
    if args.output_dir is None:
        parser.error("--output-dir is required unless --plan-only is used")
    if args.upstream_source_dir is None:
        parser.error("--upstream-source-dir is required unless --plan-only is used")
    return execute_audit(plan, args.output_dir, args.upstream_source_dir)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditError, OSError, ValueError) as error:
        print(f"Valgrind CT analysis: {error}", file=sys.stderr)
        raise SystemExit(1)
