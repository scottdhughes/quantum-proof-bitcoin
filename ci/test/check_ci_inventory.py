#!/usr/bin/env python3
"""Validate the CI functional-suite inventory and PQ gate list."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FUNCTIONAL_DIR = REPO_ROOT / "test" / "functional"
PQ_TESTS_PATH = REPO_ROOT / "ci" / "test" / "pq_functional_tests.txt"
INVENTORY_PATH = REPO_ROOT / "ci" / "test" / "functional_suite_inventory.json"
HELPERS = {"combine_logs.py", "create_cache.py", "test_runner.py"}
VALID_POLICY_CLASSES = {"pq_required", "pq_backlog", "dual_profile", "legacy_only"}
VALID_TAPROOT_MATRIX_BUCKETS = {"legacy_only", "replacement_migration", "deferred"}
REQUIRED_TAPROOT_MATRIX_BUCKETS = {
    "feature_taproot.py": "legacy_only",
    "feature_taproot_replacement_active_boundary.py": "replacement_migration",
    "feature_taproot_replacement_active_semantic_guard.py": "replacement_migration",
    "feature_taproot_replacement_compat.py": "replacement_migration",
    "feature_taproot_replacement_deployment.py": "replacement_migration",
    "rpc_createmultisig.py": "deferred",
    "rpc_psbt.py": "deferred",
    "wallet_address_types.py": "deferred",
    "wallet_createwalletdescriptor.py": "deferred",
    "wallet_miniscript.py": "deferred",
    "wallet_miniscript_decaying_multisig_descriptor_psbt.py": "deferred",
    "wallet_taproot.py": "legacy_only",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_functional_tests() -> list[str]:
    return sorted(
        path.name for path in FUNCTIONAL_DIR.glob("*.py") if path.name not in HELPERS
    )


def load_pq_gate_list() -> list[str]:
    entries = [line.strip() for line in PQ_TESTS_PATH.read_text(encoding="utf-8").splitlines()]
    entries = [line for line in entries if line]
    if len(entries) != len(set(entries)):
        fail(f"{PQ_TESTS_PATH} contains duplicate entries")
    return entries


def load_inventory() -> list[dict[str, object]]:
    data = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        fail(f"{INVENTORY_PATH} must contain a JSON array")
    return data


def main() -> int:
    functional_tests = load_functional_tests()
    functional_set = set(functional_tests)
    pq_gate_list = load_pq_gate_list()
    inventory = load_inventory()

    seen: set[str] = set()
    pq_required: list[str] = []

    for entry in inventory:
        if not isinstance(entry, dict):
            fail("inventory entries must be JSON objects")

        name = entry.get("name")
        policy_class = entry.get("policy_class")
        owner = entry.get("owner")
        taproot_matrix_bucket = entry.get("taproot_matrix_bucket")

        if not isinstance(name, str) or not name:
            fail("inventory entries must contain a non-empty string 'name'")
        if name in seen:
            fail(f"duplicate inventory entry for {name}")
        seen.add(name)

        if name not in functional_set:
            fail(f"inventory entry references unknown functional test {name}")
        if policy_class not in VALID_POLICY_CLASSES:
            fail(f"{name} has unknown policy_class {policy_class!r}")
        if not isinstance(owner, str) or not owner.strip():
            fail(f"{name} has an empty owner")
        if name in REQUIRED_TAPROOT_MATRIX_BUCKETS:
            expected_bucket = REQUIRED_TAPROOT_MATRIX_BUCKETS[name]
            if taproot_matrix_bucket != expected_bucket:
                fail(
                    f"{name} must set taproot_matrix_bucket to {expected_bucket!r}, "
                    f"got {taproot_matrix_bucket!r}"
                )
        elif taproot_matrix_bucket is not None:
            fail(
                f"{name} unexpectedly sets taproot_matrix_bucket; this field is reserved "
                "for the curated Taproot migration subset"
            )

        if taproot_matrix_bucket is not None and taproot_matrix_bucket not in VALID_TAPROOT_MATRIX_BUCKETS:
            fail(f"{name} has unknown taproot_matrix_bucket {taproot_matrix_bucket!r}")

        if policy_class == "pq_required":
            pq_required.append(name)

    missing = sorted(functional_set - seen)
    if missing:
        fail(f"inventory is missing functional tests: {', '.join(missing)}")

    extra = sorted(seen - functional_set)
    if extra:
        fail(f"inventory contains unexpected entries: {', '.join(extra)}")

    if pq_gate_list != pq_required:
        fail(
            "pq gate list does not exactly match pq_required inventory entries: "
            f"list={pq_gate_list!r} inventory={pq_required!r}"
        )

    counts = Counter(entry["policy_class"] for entry in inventory)
    taproot_bucket_counts = Counter(
        entry["taproot_matrix_bucket"]
        for entry in inventory
        if "taproot_matrix_bucket" in entry
    )
    print("CI inventory validation passed")
    for label in sorted(VALID_POLICY_CLASSES):
        print(f"{label}: {counts[label]}")
    for label in sorted(VALID_TAPROOT_MATRIX_BUCKETS):
        print(f"taproot_matrix_bucket:{label}: {taproot_bucket_counts[label]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
