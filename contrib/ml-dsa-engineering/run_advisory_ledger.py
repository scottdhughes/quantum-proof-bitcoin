#!/usr/bin/env python3
"""Validate the fail-closed ML-DSA-44 advisory and dependency ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib
from typing import Any


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
LEDGER_PATH = HERE / "advisory_ledger.json"
VECTORS_PATH = REPO_ROOT / "contrib" / "ml-dsa-ref" / "vectors.json"
RUSTSEC_ID = re.compile(r"^RUSTSEC-\d{4}-\d{4}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_ADVISORY_IDS = {
    "RUSTSEC-2019-0035",
    "RUSTSEC-2021-0023",
    "RUSTSEC-2025-0133",
    "RUSTSEC-2026-0074",
    "RUSTSEC-2026-0076",
    "RUSTSEC-2026-0077",
    "RUSTSEC-2026-0097",
    "RUSTSEC-2026-0125",
    "RUSTSEC-2026-0126",
    "RUSTSEC-2026-0207",
    "RUSTSEC-2026-0208",
    "RUSTSEC-2026-0212",
}
EXPECTED_ADVISORY_DISPOSITIONS = {
    "RUSTSEC-2019-0035": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_ABOVE_FIXED_LEGACY_API",
        "REVIEW_ON_RAND_CORE_REPIN",
    ),
    "RUSTSEC-2021-0023": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_ABOVE_FIXED_LEGACY_API",
        "REVIEW_ON_RAND_CORE_REPIN",
    ),
    "RUSTSEC-2025-0133": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_ABOVE_FIXED_AND_ARCH_OUT_OF_SCOPE",
        "REVIEW_AND_TEST_BEFORE_AARCH64_ADMISSION",
    ),
    "RUSTSEC-2026-0074": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_ABOVE_FIXED_AND_API_OUT_OF_SCOPE",
        "REVIEW_IF_INCREMENTAL_API_SCOPE_CHANGES",
    ),
    "RUSTSEC-2026-0076": (
        "APPLICABLE",
        "PASS",
        "PIN_ABOVE_FIXED_WITH_BOUNDED_REGRESSION",
        "RERUN_EXACT_REGRESSION_ON_REPIN",
    ),
    "RUSTSEC-2026-0077": (
        "APPLICABLE",
        "UNTESTED",
        "PIN_ABOVE_FIXED_EXACT_PARAMETER_REGRESSION_MISSING",
        "EXACT_ML_DSA_44_REGRESSION_REQUIRED_BEFORE_PRODUCTION",
    ),
    "RUSTSEC-2026-0097": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_AT_FIXED_AND_FEATURE_CONDITION_OUT_OF_SCOPE",
        "REVIEW_IF_RAND_FEATURE_OR_API_SCOPE_CHANGES",
    ),
    "RUSTSEC-2026-0125": (
        "NOT_APPLICABLE",
        "UNTESTED",
        "PIN_ABOVE_FIXED_AND_OPTIMIZED_BACKEND_DISABLED",
        "BLOCKED_UNTIL_EXACT_SIMD256_REGRESSION_PASSES",
    ),
    "RUSTSEC-2026-0126": (
        "NOT_APPLICABLE",
        "UNTESTED",
        "PIN_ABOVE_FIXED_AND_OPTIMIZED_BACKEND_DISABLED",
        "BLOCKED_UNTIL_EXACT_SIMD256_REGRESSION_PASSES",
    ),
    "RUSTSEC-2026-0207": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_AT_FIXED_AND_API_OUT_OF_SCOPE",
        "REVIEW_IF_INCREMENTAL_API_SCOPE_CHANGES",
    ),
    "RUSTSEC-2026-0208": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_AT_FIXED_AND_OPTIMIZED_BACKEND_DISABLED",
        "REVIEW_AND_TEST_BEFORE_SIMD256_ADMISSION",
    ),
    "RUSTSEC-2026-0212": (
        "NOT_APPLICABLE",
        "NOT_APPLICABLE",
        "PIN_AT_FIXED_AND_ARCH_OUT_OF_SCOPE",
        "REVIEW_AND_TEST_BEFORE_AARCH64_ADMISSION",
    ),
}
EXPECTED_SCANNER_FINDINGS = {
    ("RUSTSEC-2024-0436", "paste", "1.0.15", "warning", "unmaintained"),
    ("RUSTSEC-2026-0162", "pqcrypto-traits", "0.3.5", "warning", "unmaintained"),
    ("RUSTSEC-2026-0163", "pqcrypto-internals", "0.2.11", "warning", "unmaintained"),
    ("RUSTSEC-2026-0166", "pqcrypto-mldsa", "0.1.2", "warning", "unmaintained"),
    ("RUSTSEC-2026-0173", "proc-macro-error2", "2.0.1", "warning", "unmaintained"),
    ("RUSTSEC-2026-0190", "anyhow", "1.0.102", "warning", "unsound"),
    ("RUSTSEC-2026-0204", "crossbeam-epoch", "0.9.18", "vulnerability", None),
}
EXPECTED_EXECUTION = {
    "parameter_set": 44,
    "default_features": False,
    "features": ["mldsa44", "std"],
    "compiled_backend": "portable",
    "called_backend": "portable",
    "architecture": "x86_64",
    "target_triple": "x86_64-unknown-linux-gnu",
    "required_environment": {
        "LIBCRUX_DISABLE_SIMD128": "1",
        "LIBCRUX_DISABLE_SIMD256": "1",
    },
    "simd128_admitted": False,
    "simd256_admitted": False,
    "production_backend": "NONE",
    "release_hold": True,
    "miri_role": "SUPPLEMENTARY",
}


class AuditError(RuntimeError):
    """The retained evidence does not satisfy the checked-in contract."""


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AuditError(f"non-finite JSON value: {value}")


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf8"),
            object_pairs_hook=_reject_duplicate,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, AuditError) as exc:
        raise AuditError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"{label} must be a JSON object")
    return value


def _require_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise AuditError(f"{label} keys drifted; missing={missing}, extra={extra}")


def _unique_rows(
    rows: list[dict[str, Any]], fields: tuple[str, ...], label: str
) -> set[tuple[Any, ...]]:
    normalized: set[tuple[Any, ...]] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise AuditError(f"{label} entries must be objects")
        key = tuple(row.get(field) for field in fields)
        if key in normalized:
            raise AuditError(f"duplicate {label} entry: {key}")
        normalized.add(key)
    return normalized


def _source_by_name(ledger: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = ledger["source_contract"]["oracles"]
    if not isinstance(sources, list):
        raise AuditError("source_contract.oracles must be a list")
    result: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("name"), str):
            raise AuditError("oracle source entries require a name")
        if source["name"] in result:
            raise AuditError(f"duplicate oracle source: {source['name']}")
        result[source["name"]] = source
    return result


def validate_ledger(ledger: dict[str, Any], vectors: dict[str, Any]) -> None:
    _require_keys(
        ledger,
        {
            "schema_version",
            "ledger_id",
            "inventory_date",
            "tracking_issue",
            "profile",
            "source_contract",
            "execution_contract",
            "tools",
            "advisories",
            "scanners",
            "miri",
            "scope",
        },
        "ledger",
    )
    if ledger["schema_version"] != 1:
        raise AuditError("ledger schema_version must be 1")
    if ledger["ledger_id"] != "ML-DSA-44-LIBCRUX-ADVISORY-LEDGER":
        raise AuditError("ledger_id mismatch")
    if ledger["inventory_date"] != "2026-07-21":
        raise AuditError("inventory_date must be the reviewed 2026-07-21 snapshot")
    if ledger["tracking_issue"] != 189 or ledger["profile"] != "ML-DSA-44":
        raise AuditError("ledger issue/profile mismatch")

    if ledger["execution_contract"] != EXPECTED_EXECUTION:
        raise AuditError("portable execution contract drifted")

    sources = _source_by_name(ledger)
    if set(sources) != {"openssl", "mldsa_native", "libcrux"}:
        raise AuditError("oracle inventory must contain exactly three pinned sources")
    vector_sources = vectors.get("sources", {})
    expected_source_values = {
        "openssl": ("3.6.3", vector_sources.get("openssl", {}).get("commit")),
        "mldsa_native": (
            "v1.0.0-beta2",
            vector_sources.get("mldsa_native", {}).get("commit"),
        ),
        "libcrux": ("0.0.10", vector_sources.get("libcrux", {}).get("commit")),
    }
    for name, (version, commit) in expected_source_values.items():
        source = sources[name]
        if source.get("version") != version or source.get("commit") != commit:
            raise AuditError(f"{name} source pin differs from vectors.json")
        if HEX_40.fullmatch(str(source.get("commit", ""))) is None:
            raise AuditError(f"{name} commit is not a full Git SHA")
        inventory = source.get("advisory_inventory")
        if not isinstance(inventory, dict):
            raise AuditError(f"{name} has no dated advisory inventory")
        _require_keys(
            inventory,
            {"as_of", "source", "status", "current_affected_ids", "refresh"},
            f"{name} advisory inventory",
        )
        if inventory["as_of"] != ledger["inventory_date"]:
            raise AuditError(f"{name} advisory inventory date drifted")
        if not all(
            isinstance(inventory[field], str) and inventory[field]
            for field in ("source", "status", "refresh")
        ):
            raise AuditError(f"{name} advisory inventory is incomplete")
        if not isinstance(inventory["current_affected_ids"], list):
            raise AuditError(f"{name} current advisory IDs must be a list")
    libcrux = sources["libcrux"]
    vector_libcrux = vector_sources.get("libcrux", {})
    for field in ("tag", "crate_sha256"):
        if libcrux.get(field) != vector_libcrux.get(field):
            raise AuditError(f"libcrux {field} differs from vectors.json")
    for field in ("crate_sha256", "cargo_lock_sha256", "cargo_toml_sha256"):
        if HEX_64.fullmatch(str(libcrux.get(field, ""))) is None:
            raise AuditError(f"libcrux {field} must be SHA256")
    if libcrux.get("full_lock_package_count") != 139:
        raise AuditError("libcrux full lock must contain 139 packages")
    expected_oracle_inventory = {
        "openssl": ("NO_PUBLISHED_ADVISORY_AFFECTS_PIN", set()),
        "mldsa_native": ("NO_PUBLISHED_REPOSITORY_ADVISORIES", set()),
        "libcrux": (
            "EXPLICIT_SELECTED_ADVISORIES_AND_EXACT_FULL_LOCK_SCAN",
            {row[0] for row in EXPECTED_SCANNER_FINDINGS},
        ),
    }
    for name, (status, current_ids) in expected_oracle_inventory.items():
        inventory = sources[name]["advisory_inventory"]
        if inventory["status"] != status or set(inventory["current_affected_ids"]) != current_ids:
            raise AuditError(f"{name} dated advisory disposition drifted")

    full_lock = ledger["source_contract"].get("full_lock", {})
    full_lock_rows = full_lock.get("packages")
    if not isinstance(full_lock_rows, list):
        raise AuditError("full Cargo.lock inventory must be a list")
    full_lock_set = _unique_rows(full_lock_rows, ("name", "version"), "full lock")
    if full_lock.get("package_count") != 139 or len(full_lock_set) != 139:
        raise AuditError("full Cargo.lock inventory must contain 139 unique packages")

    ledger_pointer = vector_libcrux.get("advisory_ledger")
    expected_pointer = {
        "path": "contrib/ml-dsa-engineering/advisory_ledger.json",
        "schema_version": 1,
        "inventory_date": "2026-07-21",
    }
    if ledger_pointer != expected_pointer:
        raise AuditError("vectors.json advisory-ledger pointer mismatch")
    if "fixed_advisories" in vector_libcrux:
        raise AuditError("vectors.json retains the superseded two-advisory contract")

    graph = ledger["source_contract"].get("selected_graph", {})
    graph_rows = graph.get("packages")
    if not isinstance(graph_rows, list):
        raise AuditError("selected graph packages must be a list")
    graph_set = _unique_rows(graph_rows, ("name", "version"), "selected graph")
    if graph.get("package_count") != 16 or len(graph_set) != 16:
        raise AuditError("selected normal/build graph must contain exactly 16 packages")
    required_selected = {
        ("libcrux-ml-dsa", "0.0.10"),
        ("libcrux-intrinsics", "0.0.8"),
        ("libcrux-secrets", "0.0.6"),
        ("libcrux-sha3", "0.0.10"),
    }
    if not required_selected.issubset(graph_set):
        raise AuditError("selected graph is missing a security-relevant libcrux package")
    if not graph_set.issubset(full_lock_set):
        raise AuditError("selected graph is not a subset of the exact full lock")
    sbom_graph = ledger["source_contract"].get("sbom_graph", {})
    sbom_rows = sbom_graph.get("components")
    if not isinstance(sbom_rows, list):
        raise AuditError("SBOM graph components must be a list")
    sbom_set = _unique_rows(sbom_rows, ("name", "version"), "SBOM graph")
    if sbom_graph.get("component_count") != 24 or len(sbom_set) != 24:
        raise AuditError("CycloneDX normal closure must contain exactly 24 components")
    if not graph_set.issubset(sbom_set):
        raise AuditError("CycloneDX normal closure omits an executed selected package")
    if sbom_graph.get("target_triple") != EXPECTED_EXECUTION["target_triple"]:
        raise AuditError("CycloneDX target triple drifted")
    expected_root = {
        "name": "libcrux-ml-dsa",
        "version": "0.0.10",
        "type": "library",
    }
    expected_nested = [
        {"name": "libcrux_ml_dsa", "version": "0.0.10", "type": "library"}
    ]
    if (
        sbom_graph.get("root") != expected_root
        or sbom_graph.get("nested_targets") != expected_nested
    ):
        raise AuditError("CycloneDX root or nested target drifted")
    dependency_rows = sbom_graph.get("dependency_nodes")
    if not isinstance(dependency_rows, list):
        raise AuditError("CycloneDX dependency graph must be a list")
    dependency_ids = _unique_rows(dependency_rows, ("component",), "SBOM dependency node")
    expected_component_ids = {f"{name}@{version}" for name, version in sbom_set}
    nested_ids = {
        f"{entry['name']}@{entry['version']}" for entry in expected_nested
    }
    if {row[0] for row in dependency_ids} != expected_component_ids - nested_ids:
        raise AuditError("CycloneDX dependency node inventory drifted")
    edge_count = 0
    dependency_map: dict[str, set[str]] = {}
    for row in dependency_rows:
        _require_keys(row, {"component", "depends_on"}, "SBOM dependency node")
        dependencies = row["depends_on"]
        if not isinstance(dependencies, list) or not all(
            isinstance(item, str) and item for item in dependencies
        ):
            raise AuditError("CycloneDX dependency edges must be component IDs")
        if len(dependencies) != len(set(dependencies)):
            raise AuditError(f"duplicate CycloneDX dependency edge from {row['component']}")
        if not set(dependencies).issubset(expected_component_ids - nested_ids):
            raise AuditError(f"unresolved CycloneDX dependency edge from {row['component']}")
        dependency_map[row["component"]] = set(dependencies)
        edge_count += len(dependencies)
    if sbom_graph.get("dependency_node_count") != len(dependency_map):
        raise AuditError("CycloneDX dependency node count drifted")
    if sbom_graph.get("dependency_edge_count") != edge_count:
        raise AuditError("CycloneDX dependency edge count drifted")
    reachable: set[str] = set()
    pending = ["libcrux-ml-dsa@0.0.10"]
    while pending:
        component = pending.pop()
        if component in reachable:
            continue
        reachable.add(component)
        pending.extend(dependency_map[component])
    if reachable != set(dependency_map):
        raise AuditError("CycloneDX dependency ledger contains unreachable components")

    advisories = ledger["advisories"]
    if not isinstance(advisories, list):
        raise AuditError("advisories must be a list")
    advisory_ids = _unique_rows(advisories, ("id",), "advisory")
    if {row[0] for row in advisory_ids} != EXPECTED_ADVISORY_IDS:
        raise AuditError("selected-graph RustSec inventory is incomplete or unexpected")
    aliases: set[str] = set()
    selected_versions = dict(graph_set)
    for entry in advisories:
        required_fields = {
            "id",
            "rustsec_sha256",
            "package",
            "pinned_version",
            "aliases",
            "affected_versions",
            "fixed_versions",
            "affected_architectures",
            "affected_backends_or_functions",
            "affected_status",
            "current_path_applicability",
            "test_status",
            "reason_code",
            "reason",
            "evidence",
            "future_admission",
        }
        _require_keys(entry, required_fields, f"advisory {entry.get('id')}")
        if RUSTSEC_ID.fullmatch(str(entry["id"])) is None:
            raise AuditError(f"invalid RustSec ID: {entry['id']}")
        if HEX_64.fullmatch(str(entry["rustsec_sha256"])) is None:
            raise AuditError(f"{entry['id']} RustSec entry must be pinned by SHA256")
        if selected_versions.get(entry["package"]) != entry["pinned_version"]:
            raise AuditError(f"{entry['id']} package/version is not in the selected graph")
        if entry["affected_status"] != "NOT_AFFECTED":
            raise AuditError(f"{entry['id']} has an unreviewed affected status")
        if entry["current_path_applicability"] not in {"APPLICABLE", "NOT_APPLICABLE"}:
            raise AuditError(f"{entry['id']} has an unknown applicability")
        if entry["test_status"] not in {"PASS", "NOT_APPLICABLE", "UNTESTED"}:
            raise AuditError(f"{entry['id']} has an invalid test status")
        if entry["test_status"] == "UNTESTED" and not re.search(
            r"BLOCKED|REQUIRED", entry["future_admission"]
        ):
            raise AuditError(f"{entry['id']} is untested without a future admission block")
        if entry["test_status"] == "PASS" and not entry["evidence"]:
            raise AuditError(f"{entry['id']} claims PASS without named evidence")
        if entry["current_path_applicability"] == "NOT_APPLICABLE" and not entry["reason_code"]:
            raise AuditError(f"{entry['id']} has no machine-readable N/A predicate")
        actual_disposition = (
            entry["current_path_applicability"],
            entry["test_status"],
            entry["reason_code"],
            entry["future_admission"],
        )
        if actual_disposition != EXPECTED_ADVISORY_DISPOSITIONS[entry["id"]]:
            raise AuditError(f"{entry['id']} dated disposition drifted")
        if entry["id"] == "RUSTSEC-2026-0076" and entry["evidence"] != [
            "compare_oracles.py ML-DSA-44 malformed-hint cases",
            "upstream ML-DSA-65 bad_hint_out_of_bounds",
        ]:
            raise AuditError("RUSTSEC-2026-0076 PASS is not bound to exact evidence")
        for alias in entry["aliases"]:
            if alias in aliases:
                raise AuditError(f"duplicate advisory alias: {alias}")
            aliases.add(alias)

    scanner = ledger["scanners"]
    if scanner.get("require_exact_finding_set") is not True:
        raise AuditError("scanner policy must require the exact finding set")
    if scanner.get("cargo_audit_expected_exit_code") != 1:
        raise AuditError("cargo-audit expected exit code must retain findings")
    if scanner.get("osv_expected_exit_code") != 1:
        raise AuditError("OSV expected exit code must retain findings")
    findings = scanner.get("expected_findings")
    if not isinstance(findings, list):
        raise AuditError("expected scanner findings must be a list")
    finding_set = _unique_rows(
        findings,
        ("id", "package", "version", "cargo_audit_kind", "cargo_audit_category"),
        "scanner finding",
    )
    if finding_set != EXPECTED_SCANNER_FINDINGS:
        raise AuditError("expected full-lock scanner findings drifted")
    selected_names = {name for name, _ in graph_set}
    for finding in findings:
        if finding.get("selected_graph") is not False:
            raise AuditError(f"{finding['id']} is not classified outside the selected graph")
        if finding["package"] in selected_names:
            raise AuditError(f"{finding['id']} conflicts with the selected graph inventory")
        if finding.get("disposition") != "NOT_APPLICABLE_CURRENT_SELECTED_GRAPH":
            raise AuditError(f"{finding['id']} lacks an exact selected-graph disposition")

    expected_tools = {
        "cargo_audit": (
            "0.22.2",
            "ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39",
        ),
        "osv_scanner": (
            "2.4.0",
            "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
        ),
        "cargo_cyclonedx": (
            "0.5.9",
            "fb8dbee9f182173e062a64a387b21a0badc6fab8b2abf9294973f012972bf6d8",
        ),
    }
    for name, (version, digest) in expected_tools.items():
        tool = ledger["tools"].get(name, {})
        if tool.get("version") != version or tool.get("linux_x86_64_sha256") != digest:
            raise AuditError(f"{name} tool pin drifted")
    miri_tool = ledger["tools"].get("miri", {})
    if miri_tool.get("toolchain") != "nightly-2026-07-20":
        raise AuditError("Miri toolchain drifted")
    if ledger["tools"].get("cargo_cyclonedx", {}).get("spec_version") != "1.5":
        raise AuditError("CycloneDX spec version must be 1.5")
    miri = ledger["miri"]
    if miri.get("required") is not True or miri.get("role") != "SUPPLEMENTARY":
        raise AuditError("supplementary Miri evidence must remain required")
    if HEX_64.fullmatch(str(miri.get("source_sha256", ""))) is None:
        raise AuditError("Miri source must be pinned by SHA256")

    scope = ledger["scope"]
    if scope.get("issue_189") != "REMAINS_OPEN_PENDING_RE_REVIEW":
        raise AuditError("issue #189 must remain open pending exact-commit re-review")
    if (
        scope.get("production_change") is not False
        or scope.get("release_hold_changed") is not False
    ):
        raise AuditError("the advisory tranche cannot change production or release-hold state")


def _finding_tuple(entry: dict[str, Any], kind: str, category: str | None) -> tuple[Any, ...]:
    advisory = entry.get("advisory")
    package = entry.get("package")
    if not isinstance(advisory, dict) or not isinstance(package, dict):
        raise AuditError("cargo-audit finding is missing advisory/package objects")
    finding_id = advisory.get("id")
    name = package.get("name")
    version = package.get("version")
    if RUSTSEC_ID.fullmatch(str(finding_id)) is None:
        raise AuditError(f"cargo-audit returned unknown identifier {finding_id!r}")
    if not all(isinstance(value, str) and value for value in (name, version)):
        raise AuditError(f"cargo-audit {finding_id} has an invalid package identity")
    return finding_id, name, version, kind, category


def parse_cargo_audit(report: dict[str, Any]) -> set[tuple[Any, ...]]:
    database = report.get("database")
    lockfile = report.get("lockfile")
    vulnerabilities = report.get("vulnerabilities")
    warnings = report.get("warnings")
    if (
        not isinstance(database, dict)
        or not isinstance(database.get("advisory-count"), int)
        or database["advisory-count"] <= 0
    ):
        raise AuditError("cargo-audit database identity is missing")
    if not isinstance(lockfile, dict) or lockfile.get("dependency-count") != 139:
        raise AuditError("cargo-audit did not scan the exact 139-package lock")
    if not isinstance(vulnerabilities, dict) or not isinstance(warnings, dict):
        raise AuditError("cargo-audit report is incomplete")
    items = vulnerabilities.get("list")
    if not isinstance(items, list) or vulnerabilities.get("count") != len(items):
        raise AuditError("cargo-audit vulnerability list/count mismatch")
    findings = {_finding_tuple(item, "vulnerability", None) for item in items}
    for category, entries in warnings.items():
        if not isinstance(category, str) or not isinstance(entries, list):
            raise AuditError("cargo-audit warning structure is invalid")
        for entry in entries:
            findings.add(_finding_tuple(entry, "warning", category))
    if not findings:
        raise AuditError("cargo-audit report unexpectedly contains no retained findings")
    return findings


def _advisory_alias_map(ledger: dict[str, Any]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for entry in ledger["advisories"]:
        aliases[entry["id"]] = entry["id"]
        for alias in entry["aliases"]:
            aliases[alias] = entry["id"]
    for finding in ledger["scanners"]["expected_findings"]:
        aliases[finding["id"]] = finding["id"]
    return aliases


def _resolve_osv_identifiers(
    value: dict[str, Any],
    *,
    primary_field: str,
    aliases: dict[str, str],
    label: str,
) -> str:
    primary = value.get(primary_field)
    extra = value.get("aliases", [])
    if not isinstance(extra, list) or not all(isinstance(item, str) for item in extra):
        raise AuditError(f"{label} aliases are malformed")
    if primary_field == "ids":
        if not isinstance(primary, list) or not all(isinstance(item, str) for item in primary):
            raise AuditError(f"{label} IDs are malformed")
        identifiers = [*primary, *extra]
    else:
        if not isinstance(primary, str) or not primary:
            raise AuditError(f"{label} ID is malformed")
        identifiers = [primary, *extra]
    canonical = {aliases[identifier] for identifier in identifiers if identifier in aliases}
    if len(canonical) != 1:
        raise AuditError(
            f"{label} does not resolve to exactly one reviewed advisory: {identifiers}"
        )
    return canonical.pop()


def parse_osv(report: dict[str, Any], ledger: dict[str, Any]) -> set[tuple[str, str, str]]:
    results = report.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise AuditError("OSV report must contain exactly one lockfile scan result")
    aliases = _advisory_alias_map(ledger)
    result = results[0]
    if not isinstance(result, dict) or not isinstance(result.get("packages"), list):
        raise AuditError("OSV result is incomplete")
    source = result.get("source")
    if (
        not isinstance(source, dict)
        or source.get("type") != "lockfile"
        or not isinstance(source.get("path"), str)
        or Path(source["path"]).name != "Cargo.lock"
    ):
        raise AuditError("OSV source is not the retained Cargo.lock")
    expected_packages = {
        (entry["name"], entry["version"])
        for entry in ledger["source_contract"]["full_lock"]["packages"]
    }
    actual_packages: set[tuple[str, str]] = set()
    vulnerability_findings: set[tuple[str, str, str]] = set()
    group_findings: set[tuple[str, str, str]] = set()
    for item in result["packages"]:
        if not isinstance(item, dict):
            raise AuditError("OSV package entry is malformed")
        package = item.get("package")
        if not isinstance(package, dict):
            raise AuditError("OSV package identity is missing")
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise AuditError("OSV package name/version is missing")
        if package.get("ecosystem") != "crates.io":
            raise AuditError(f"OSV returned an unexpected ecosystem for {name}")
        package_key = (name, version)
        if package_key in actual_packages:
            raise AuditError(f"OSV returned a duplicate package: {package_key}")
        actual_packages.add(package_key)
        vulnerabilities = item.get("vulnerabilities", [])
        groups = item.get("groups", [])
        if not isinstance(vulnerabilities, list) or not isinstance(groups, list):
            raise AuditError(f"OSV advisory lists are malformed for {package_key}")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise AuditError("OSV vulnerability entry is malformed")
            finding_id = _resolve_osv_identifiers(
                vulnerability,
                primary_field="id",
                aliases=aliases,
                label=f"OSV vulnerability for {package_key}",
            )
            finding = (finding_id, name, version)
            if finding in vulnerability_findings:
                raise AuditError(f"OSV returned a duplicate vulnerability: {finding}")
            vulnerability_findings.add(finding)
        for group in groups:
            if not isinstance(group, dict):
                raise AuditError("OSV group entry is malformed")
            finding_id = _resolve_osv_identifiers(
                group,
                primary_field="ids",
                aliases=aliases,
                label=f"OSV group for {package_key}",
            )
            finding = (finding_id, name, version)
            if finding in group_findings:
                raise AuditError(f"OSV returned a duplicate group: {finding}")
            group_findings.add(finding)
    if actual_packages != expected_packages:
        raise AuditError(
            "OSV full-lock package inventory drifted; "
            f"missing={sorted(expected_packages - actual_packages)}, "
            f"extra={sorted(actual_packages - expected_packages)}"
        )
    if vulnerability_findings != group_findings:
        raise AuditError("OSV vulnerability/group classifications disagree")
    if not vulnerability_findings:
        raise AuditError("OSV report unexpectedly contains no retained findings")
    return vulnerability_findings


def validate_sbom(ledger: dict[str, Any], sbom: dict[str, Any]) -> set[tuple[str, str]]:
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.5":
        raise AuditError("SBOM must be CycloneDX 1.5")
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        raise AuditError("CycloneDX metadata root component is missing")
    properties = metadata.get("properties")
    if not isinstance(properties, list):
        raise AuditError("CycloneDX target properties are missing")
    target_values = [
        item.get("value")
        for item in properties
        if isinstance(item, dict) and item.get("name") == "cdx:rustc:sbom:target:triple"
    ]
    expected_graph = ledger["source_contract"]["sbom_graph"]
    if target_values != [expected_graph["target_triple"]]:
        raise AuditError("CycloneDX target triple is missing or ambiguous")

    root = metadata["component"]
    nested = root.get("components")
    top = sbom.get("components")
    if not isinstance(nested, list) or not isinstance(top, list):
        raise AuditError("CycloneDX component hierarchy is incomplete")
    root_identity = (root.get("name"), root.get("version"), root.get("type"))
    expected_root = expected_graph["root"]
    if root_identity != (
        expected_root["name"],
        expected_root["version"],
        expected_root["type"],
    ):
        raise AuditError("CycloneDX metadata root identity drifted")
    expected_nested = {
        (item["name"], item["version"], item["type"])
        for item in expected_graph["nested_targets"]
    }
    actual_nested = {
        (item.get("name"), item.get("version"), item.get("type"))
        for item in nested
        if isinstance(item, dict)
    }
    if len(actual_nested) != len(nested) or actual_nested != expected_nested:
        raise AuditError("CycloneDX nested target identity drifted")

    components = [root, *nested, *top]
    identities: set[tuple[str, str]] = set()
    refs: dict[str, str] = {}
    purls: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise AuditError("CycloneDX component must be an object")
        name = component.get("name")
        version = component.get("version")
        component_type = component.get("type")
        bom_ref = component.get("bom-ref")
        purl = component.get("purl")
        if not all(isinstance(value, str) and value for value in (name, version, bom_ref, purl)):
            raise AuditError("CycloneDX component identity/ref/purl is missing")
        if component_type != "library" or not purl.startswith("pkg:cargo/"):
            raise AuditError(f"CycloneDX component type/purl is invalid for {name}")
        identity = (name, version)
        component_id = f"{name}@{version}"
        if identity in identities or bom_ref in refs or purl in purls:
            raise AuditError(f"duplicate CycloneDX component identity/ref/purl: {identity}")
        identities.add(identity)
        refs[bom_ref] = component_id
        purls.add(purl)
        if (
            component is not root
            and component not in nested
            and component.get("components", []) != []
        ):
            raise AuditError(f"unexpected nested CycloneDX children under {component_id}")

    expected = {
        (entry["name"], entry["version"])
        for entry in expected_graph["components"]
    }
    if identities != expected:
        raise AuditError(
            f"normal-closure SBOM drifted; missing={sorted(expected - identities)}, "
            f"extra={sorted(identities - expected)}"
        )

    dependency_rows = sbom.get("dependencies")
    if not isinstance(dependency_rows, list):
        raise AuditError("CycloneDX dependency graph is missing")
    actual_dependencies: dict[str, set[str]] = {}
    for row in dependency_rows:
        if not isinstance(row, dict) or not isinstance(row.get("ref"), str):
            raise AuditError("CycloneDX dependency node is malformed")
        source_ref = row["ref"]
        targets = row.get("dependsOn", [])
        if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
            raise AuditError("CycloneDX dependency edges are malformed")
        if source_ref not in refs or any(target not in refs for target in targets):
            raise AuditError("CycloneDX dependency graph contains a dangling bom-ref")
        source_id = refs[source_ref]
        target_ids = {refs[target] for target in targets}
        if len(target_ids) != len(targets) or source_id in actual_dependencies:
            raise AuditError(f"duplicate CycloneDX dependency node/edge for {source_id}")
        actual_dependencies[source_id] = target_ids
    expected_dependencies = {
        row["component"]: set(row["depends_on"])
        for row in expected_graph["dependency_nodes"]
    }
    if actual_dependencies != expected_dependencies:
        raise AuditError("CycloneDX normalized dependency graph drifted")
    root_id = f"{expected_root['name']}@{expected_root['version']}"
    reachable: set[str] = set()
    pending = [root_id]
    while pending:
        component_id = pending.pop()
        if component_id in reachable:
            continue
        reachable.add(component_id)
        pending.extend(actual_dependencies[component_id])
    if reachable != set(actual_dependencies):
        raise AuditError("CycloneDX dependency graph contains unreachable nodes")
    return identities


def validate_miri(ledger: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    contract = ledger["execution_contract"]
    expected_identity = {
        "schema_version": 1,
        "status": "PASS",
        "role": "SUPPLEMENTARY",
        "toolchain": ledger["tools"]["miri"]["toolchain"],
        "rustc": ledger["tools"]["miri"]["rustc"],
        "compiled_backend": contract["compiled_backend"],
        "called_backend": contract["called_backend"],
        "architecture": contract["architecture"],
        "target_triple": contract["target_triple"],
    }
    for field, expected in expected_identity.items():
        if report.get(field) != expected:
            raise AuditError(f"Miri {field} mismatch: expected {expected!r}")
    tests = report.get("tests")
    if not isinstance(tests, list):
        raise AuditError("Miri report has no tests")
    actual = _unique_rows(tests, ("name", "status"), "Miri test")
    expected = {(name, "PASS") for name in ledger["miri"]["checks"]}
    if actual != expected:
        raise AuditError("Miri checks are incomplete or unexpected")
    return {"role": report["role"], "status": report["status"], "tests": len(actual)}


def validate_evidence(
    *,
    ledger: dict[str, Any],
    cargo_audit: dict[str, Any] | None,
    osv: dict[str, Any] | None,
    sbom: dict[str, Any] | None,
    miri: dict[str, Any] | None,
    compiled_backend: str,
    called_backend: str,
    architecture: str,
    cargo_audit_exit_code: int,
    osv_exit_code: int,
) -> dict[str, Any]:
    if any(value is None for value in (cargo_audit, osv, sbom, miri)):
        raise AuditError("cargo-audit, OSV, SBOM, and Miri evidence are all required")
    vectors = load_json_object(VECTORS_PATH, "reference vectors")
    validate_ledger(ledger, vectors)
    contract = ledger["execution_contract"]
    for label, actual, expected in (
        ("compiled backend", compiled_backend, contract["compiled_backend"]),
        ("called backend", called_backend, contract["called_backend"]),
        ("architecture", architecture, contract["architecture"]),
    ):
        if actual != expected:
            raise AuditError(f"{label} drifted: expected {expected!r}, got {actual!r}")
    if cargo_audit_exit_code != ledger["scanners"]["cargo_audit_expected_exit_code"]:
        raise AuditError("cargo-audit exit code does not match the classified finding set")
    if osv_exit_code != ledger["scanners"]["osv_expected_exit_code"]:
        raise AuditError("OSV exit code does not match the classified finding set")

    expected = EXPECTED_SCANNER_FINDINGS
    actual_cargo = parse_cargo_audit(cargo_audit)
    if actual_cargo != expected:
        unknown = sorted(actual_cargo - expected, key=str)
        missing = sorted(expected - actual_cargo, key=str)
        raise AuditError(f"cargo-audit finding drift; unknown={unknown}, missing={missing}")
    expected_osv = {(row[0], row[1], row[2]) for row in expected}
    actual_osv = parse_osv(osv, ledger)
    if actual_osv != expected_osv:
        unknown = sorted(actual_osv - expected_osv)
        missing = sorted(expected_osv - actual_osv)
        raise AuditError(f"OSV finding drift; unknown={unknown}, missing={missing}")

    selected = validate_sbom(ledger, sbom)
    miri_summary = validate_miri(ledger, miri)
    finding_ids_by_package: dict[tuple[str, str], list[str]] = {}
    for finding in ledger["scanners"]["expected_findings"]:
        finding_ids_by_package.setdefault(
            (finding["package"], finding["version"]), []
        ).append(finding["id"])
    return {
        "schema_version": 1,
        "status": "PASS",
        "inventory_date": ledger["inventory_date"],
        "execution_contract": contract,
        "scanner_exit_codes": {"cargo_audit": cargo_audit_exit_code, "osv": osv_exit_code},
        "classified_scanner_findings": [
            {
                "id": finding["id"],
                "package": finding["package"],
                "version": finding["version"],
                "disposition": finding["disposition"],
            }
            for finding in ledger["scanners"]["expected_findings"]
        ],
        "oracle_advisory_inventory": [
            {
                "name": source["name"],
                "version": source["version"],
                **source["advisory_inventory"],
            }
            for source in ledger["source_contract"]["oracles"]
        ],
        "full_lock_inventory": [
            {
                "name": package["name"],
                "version": package["version"],
                "current_finding_ids": sorted(
                    finding_ids_by_package.get(
                        (package["name"], package["version"]), []
                    )
                ),
            }
            for package in ledger["source_contract"]["full_lock"]["packages"]
        ],
        "sbom_components": len(selected),
        "advisory_dispositions": [
            {
                "id": entry["id"],
                "affected_status": entry["affected_status"],
                "applicability": entry["current_path_applicability"],
                "test_status": entry["test_status"],
                "future_admission": entry["future_admission"],
            }
            for entry in ledger["advisories"]
        ],
        "miri": miri_summary,
        "scope": ledger["scope"],
    }


def validate_crate(ledger: dict[str, Any], crate_dir: Path) -> dict[str, Any]:
    source = _source_by_name(ledger)["libcrux"]
    required = {
        "Cargo.lock": source["cargo_lock_sha256"],
        "Cargo.toml": source["cargo_toml_sha256"],
    }
    for name, expected in required.items():
        path = crate_dir / name
        if not path.is_file():
            raise AuditError(f"extracted libcrux crate is missing {name}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise AuditError(f"extracted libcrux {name} SHA256 mismatch")
    vcs = load_json_object(crate_dir / ".cargo_vcs_info.json", "libcrux VCS metadata")
    if vcs.get("git", {}).get("sha1") != source["commit"]:
        raise AuditError("extracted libcrux VCS commit mismatch")
    try:
        lock = tomllib.loads((crate_dir / "Cargo.lock").read_text(encoding="utf8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise AuditError(f"invalid embedded Cargo.lock: {exc}") from exc
    packages = lock.get("package")
    if not isinstance(packages, list) or len(packages) != source["full_lock_package_count"]:
        raise AuditError("embedded Cargo.lock package count mismatch")
    package_set = {(package.get("name"), package.get("version")) for package in packages}
    if len(package_set) != len(packages):
        raise AuditError("embedded Cargo.lock contains duplicate package identities")
    expected_full_lock = {
        (package["name"], package["version"])
        for package in ledger["source_contract"]["full_lock"]["packages"]
    }
    if package_set != expected_full_lock:
        raise AuditError(
            "embedded Cargo.lock inventory drifted; "
            f"missing={sorted(expected_full_lock - package_set)}, "
            f"extra={sorted(package_set - expected_full_lock)}"
        )
    selected = {
        (package["name"], package["version"])
        for package in ledger["source_contract"]["selected_graph"]["packages"]
    }
    if not selected.issubset(package_set):
        raise AuditError("embedded Cargo.lock is missing a selected-graph package")
    return {
        "crate_sha256": source["crate_sha256"],
        "cargo_lock_sha256": source["cargo_lock_sha256"],
        "cargo_toml_sha256": source["cargo_toml_sha256"],
        "full_lock_packages": len(packages),
    }


def validate_selected_graph(
    ledger: dict[str, Any], crate_dir: Path
) -> dict[str, Any]:
    contract = ledger["execution_contract"]
    command = [
        "cargo",
        "tree",
        "--manifest-path",
        str(crate_dir / "Cargo.toml"),
        "--locked",
        "--target",
        contract["target_triple"],
        "--edges",
        "normal,build",
        "--no-default-features",
        "--features",
        ",".join(contract["features"]),
        "--prefix",
        "none",
    ]
    environment = os.environ.copy()
    environment.update(contract["required_environment"])
    environment["CARGO_NET_OFFLINE"] = "true"
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
    except subprocess.CalledProcessError as exc:
        raise AuditError(f"selected cargo tree failed: {exc.stderr.strip()}") from exc
    actual: set[tuple[str, str]] = set()
    for line in result.stdout.splitlines():
        match = re.match(r"^([A-Za-z0-9_.+-]+) v([^ ]+)", line)
        if match is not None:
            actual.add((match.group(1), match.group(2)))
    expected = {
        (entry["name"], entry["version"])
        for entry in ledger["source_contract"]["selected_graph"]["packages"]
    }
    if actual != expected:
        raise AuditError(
            f"selected cargo graph drifted; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )
    return {
        "target": contract["target_triple"],
        "compiled_backend": contract["compiled_backend"],
        "called_backend": contract["called_backend"],
        "packages": [
            {"name": name, "version": version} for name, version in sorted(actual)
        ],
        "cargo_tree_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
    }


def prepare_miri_crate(
    ledger: dict[str, Any], crate_dir: Path, miri_source: Path
) -> dict[str, Any]:
    """Remove broad dev-only edges and install the reviewed example source."""
    original = validate_crate(ledger, crate_dir)
    expected_source = ledger["miri"].get("source_sha256")
    if not miri_source.is_file() or _sha256(miri_source) != expected_source:
        raise AuditError("PQBTC Miri source SHA256 mismatch")
    manifest_path = crate_dir / "Cargo.toml"
    manifest = manifest_path.read_text(encoding="utf8")
    dev_section = re.compile(
        r"(?ms)^\[(?:dev-dependencies(?:\.[^\]]+)?|"
        r"target\..*?\.dev-dependencies(?:\.[^\]]+)?)\]\n"
        r".*?(?=^\[|\Z)"
    )
    stripped, count = dev_section.subn("", manifest)
    if count != 6:
        raise AuditError(f"expected to remove 6 libcrux dev-dependency sections, removed {count}")
    if re.search(r"(?m)^\[.*dev-dependencies", stripped):
        raise AuditError("generated Miri manifest retains a dev-dependency section")
    if re.search(r'(?m)^name = "pqbtc_oracle"$', stripped):
        raise AuditError("published libcrux manifest unexpectedly defines pqbtc_oracle")
    stripped += (
        "\n[[example]]\n"
        'name = "pqbtc_oracle"\n'
        'path = "examples/pqbtc_oracle.rs"\n'
    )
    manifest_path.write_text(stripped, encoding="utf8")
    destination = crate_dir / "examples" / "pqbtc_oracle.rs"
    if not destination.parent.is_dir():
        raise AuditError("extracted libcrux crate has no examples directory")
    shutil.copyfile(miri_source, destination)
    return {
        **original,
        "miri_source_sha256": expected_source,
        "removed_dev_dependency_sections": count,
        "added_example_target": "pqbtc_oracle",
        "prepared_manifest_sha256": _sha256(manifest_path),
        "example_sha256": _sha256(destination),
    }


def validate_rustsec_database(ledger: dict[str, Any], database: Path) -> dict[str, Any]:
    expected = {entry["id"]: entry for entry in ledger["advisories"]}
    discovered: dict[str, dict[str, Any]] = {}
    selected_packages = sorted(
        {entry["name"] for entry in ledger["source_contract"]["selected_graph"]["packages"]}
    )
    for package in selected_packages:
        package_dir = database / "crates" / package
        if not package_dir.is_dir():
            continue
        for path in sorted(package_dir.glob("RUSTSEC-*.md")):
            text = path.read_text(encoding="utf8")
            match = re.match(r"```toml\n(.*?)\n```", text, re.DOTALL)
            if match is None:
                raise AuditError(f"cannot parse RustSec front matter: {path}")
            try:
                metadata = tomllib.loads(match.group(1))
            except tomllib.TOMLDecodeError as exc:
                raise AuditError(f"invalid RustSec metadata in {path}: {exc}") from exc
            advisory = metadata.get("advisory", {})
            finding_id = advisory.get("id")
            if RUSTSEC_ID.fullmatch(str(finding_id)) is None:
                raise AuditError(f"invalid RustSec database advisory ID in {path}")
            if advisory.get("package") != package:
                raise AuditError(f"RustSec database package/path mismatch in {path}")
            if finding_id in discovered:
                raise AuditError(f"duplicate RustSec database advisory: {finding_id}")
            discovered[finding_id] = {
                "id": finding_id,
                "package": advisory.get("package"),
                "aliases": sorted(advisory.get("aliases", [])),
                "path": str(path.relative_to(database)),
                "sha256": _sha256(path),
            }
    if set(discovered) != set(expected):
        unknown = sorted(set(discovered) - set(expected))
        missing = sorted(set(expected) - set(discovered))
        raise AuditError(f"RustSec package inventory drift; unknown={unknown}, missing={missing}")
    for finding_id, item in discovered.items():
        entry = expected[finding_id]
        if (
            item["package"] != entry["package"]
            or item["aliases"] != sorted(entry["aliases"])
            or item["sha256"] != entry["rustsec_sha256"]
        ):
            raise AuditError(f"RustSec identity, alias, or content drift for {finding_id}")
    try:
        commit = subprocess.run(
            ["git", "-C", str(database), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        committed_at = subprocess.run(
            ["git", "-C", str(database), "show", "-s", "--format=%cI", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise AuditError(f"cannot identify RustSec database commit: {exc.stderr.strip()}") from exc
    if HEX_40.fullmatch(commit) is None:
        raise AuditError("RustSec database commit is not a full Git SHA")
    return {
        "commit": commit,
        "committed_at": committed_at,
        "tracked_packages": selected_packages,
        "advisories": [discovered[finding_id] for finding_id in sorted(discovered)],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256s(directory: Path) -> None:
    checksum_path = directory / "SHA256SUMS"
    files = sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path != checksum_path and not path.is_symlink()
    )
    lines = [f"{_sha256(path)}  {path.relative_to(directory)}" for path in files]
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf8")


def build_plan(ledger: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "ledger_id": ledger["ledger_id"],
        "inventory_date": ledger["inventory_date"],
        "execution_contract": ledger["execution_contract"],
        "expected_scanner_ids": sorted(
            finding["id"] for finding in ledger["scanners"]["expected_findings"]
        ),
        "selected_graph_packages": ledger["source_contract"]["selected_graph"]["package_count"],
        "tracked_advisory_ids": sorted(entry["id"] for entry in ledger["advisories"]),
        "miri": {
            "role": ledger["miri"]["role"],
            "required": ledger["miri"]["required"],
            "toolchain": ledger["tools"]["miri"]["toolchain"],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--prepare-miri-crate", action="store_true")
    parser.add_argument("--validate-selected-graph", action="store_true")
    parser.add_argument("--ledger", type=Path, default=LEDGER_PATH)
    parser.add_argument("--vectors", type=Path, default=VECTORS_PATH)
    parser.add_argument("--cargo-audit", type=Path)
    parser.add_argument("--osv", type=Path)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--miri", type=Path)
    parser.add_argument("--rustsec-db", type=Path)
    parser.add_argument("--crate-dir", type=Path)
    parser.add_argument(
        "--miri-source",
        type=Path,
        default=HERE / "libcrux-miri" / "pqbtc_miri.rs",
    )
    parser.add_argument("--cargo-audit-exit-code", type=int)
    parser.add_argument("--osv-exit-code", type=int)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--compiled-backend", default=os.environ.get("ML_DSA_COMPILED_BACKEND")
    )
    parser.add_argument("--called-backend", default=os.environ.get("ML_DSA_CALLED_BACKEND"))
    parser.add_argument("--architecture", default=os.environ.get("ML_DSA_ARCHITECTURE"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir
    try:
        ledger = load_json_object(args.ledger, "advisory ledger")
        vectors = load_json_object(args.vectors, "reference vectors")
        validate_ledger(ledger, vectors)
        if args.plan_only:
            print(json.dumps(build_plan(ledger), indent=2, sort_keys=True))
            return 0
        if args.prepare_miri_crate:
            if args.crate_dir is None:
                raise AuditError("--prepare-miri-crate requires --crate-dir")
            prepared = prepare_miri_crate(
                ledger, args.crate_dir, args.miri_source
            )
            print(json.dumps(prepared, indent=2, sort_keys=True))
            return 0
        if args.validate_selected_graph:
            if args.crate_dir is None:
                raise AuditError("--validate-selected-graph requires --crate-dir")
            selected = validate_selected_graph(ledger, args.crate_dir)
            print(json.dumps(selected, indent=2, sort_keys=True))
            return 0
        required = {
            "--cargo-audit": args.cargo_audit,
            "--osv": args.osv,
            "--sbom": args.sbom,
            "--miri": args.miri,
            "--rustsec-db": args.rustsec_db,
            "--crate-dir": args.crate_dir,
            "--cargo-audit-exit-code": args.cargo_audit_exit_code,
            "--osv-exit-code": args.osv_exit_code,
            "--output-dir": output_dir,
            "--compiled-backend": args.compiled_backend,
            "--called-backend": args.called_backend,
            "--architecture": args.architecture,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise AuditError(f"missing required arguments: {', '.join(missing)}")
        assert args.cargo_audit is not None
        assert args.osv is not None
        assert args.sbom is not None
        assert args.miri is not None
        assert args.rustsec_db is not None
        assert args.crate_dir is not None
        assert args.cargo_audit_exit_code is not None
        assert args.osv_exit_code is not None
        assert output_dir is not None

        report = validate_evidence(
            ledger=ledger,
            cargo_audit=load_json_object(args.cargo_audit, "cargo-audit report"),
            osv=load_json_object(args.osv, "OSV report"),
            sbom=load_json_object(args.sbom, "CycloneDX SBOM"),
            miri=load_json_object(args.miri, "Miri report"),
            compiled_backend=args.compiled_backend,
            called_backend=args.called_backend,
            architecture=args.architecture,
            cargo_audit_exit_code=args.cargo_audit_exit_code,
            osv_exit_code=args.osv_exit_code,
        )
        report["crate"] = validate_crate(ledger, args.crate_dir)
        report["selected_graph"] = validate_selected_graph(ledger, args.crate_dir)
        report["rustsec_database"] = validate_rustsec_database(ledger, args.rustsec_db)
        report["inputs_sha256"] = {
            "ledger": _sha256(args.ledger),
            "vectors": _sha256(args.vectors),
            "cargo_audit": _sha256(args.cargo_audit),
            "osv": _sha256(args.osv),
            "sbom": _sha256(args.sbom),
            "miri": _sha256(args.miri),
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "advisory-ledger-report.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf8")
        write_sha256s(output_dir)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (AuditError, OSError) as exc:
        failure = {"schema_version": 1, "status": "FAIL", "error": str(exc)}
        if output_dir is not None:
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "advisory-ledger-report.json").write_text(
                    json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf8"
                )
                write_sha256s(output_dir)
            except OSError:
                pass
        print(json.dumps(failure, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
