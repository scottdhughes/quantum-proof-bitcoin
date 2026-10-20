#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
DRIVER = ENGINEERING_DIR / "run_cbmc_reproduction.py"
MANIFEST = ENGINEERING_DIR / "cbmc_proof_manifest.json"
SOURCE_MANIFEST = ENGINEERING_DIR / "vendor" / "mldsa-native" / "SOURCE.json"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-cbmc-reproduction.yml"

SPEC = importlib.util.spec_from_file_location("run_cbmc_reproduction", DRIVER)
assert SPEC is not None and SPEC.loader is not None
cbmc = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cbmc
SPEC.loader.exec_module(cbmc)


def valid_result(proof_uids: list[str]) -> dict[str, object]:
    return {
        "mldsa_parameter_set": "44",
        "summary": {
            "total": len(proof_uids),
            "success": len(proof_uids),
            "failed": 0,
            "timeout": 0,
        },
        "failures": [],
        "runtimes": [
            {"name": name, "unit": "seconds", "value": index}
            for index, name in enumerate(proof_uids)
        ],
    }


class MlDsaCbmcReproductionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf8"))

    def test_manifest_pins_complete_upstream_ml_dsa_44_lane(self):
        manifest = self.manifest
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(
            manifest["profile"],
            {
                "parameter_set": 44,
                "reduce_ram": False,
                "coverage": False,
                "parallel_jobs": 2,
                "per_proof_timeout_seconds": 1800,
            },
        )
        upstream = manifest["upstream"]
        self.assertEqual(
            upstream["commit"],
            "834a90d5e846ffa1e1611bd24e160bb2e9b86d35",
        )
        self.assertEqual(
            upstream["git_tree"],
            "e61bc2b09d705cbc378e3e8c6d556cae05750fd6",
        )
        self.assertEqual(
            upstream["git_archive_tar_sha256"],
            "1bb12c7eac6a44ea96bc2043b8c8b5bb2f2b2a85a3a9b5926fa2eb5ed86e27b7",
        )
        self.assertEqual(
            upstream["flake_lock_sha256"],
            "8f1762cc57561256465ef3b467f44b99b606c3b196870b81a329b8de0cebdd69",
        )
        self.assertEqual(len(upstream["critical_files"]), 10)

        inventory = manifest["proof_inventory"]
        self.assertEqual(inventory["directory_count"], 210)
        self.assertEqual(inventory["proof_uid_count"], 210)
        self.assertEqual(
            inventory["sorted_directory_names_sha256"],
            "fd224096e52ce48b71f7f52bd0075efe81d9fce11f882e10a62345678dca94e4",
        )
        self.assertEqual(
            inventory["sorted_proof_uids_sha256"],
            "9a014b78cdea6d8e1ddb226f09e4c2776bcf74b964b170edb17af78421a5106e",
        )
        self.assertEqual(manifest["tools"]["cbmc"], "6.10.0")
        self.assertEqual(manifest["tools"]["ninja"], "1.13.2")
        self.assertEqual(manifest["tools"]["z3"], "4.15.3")
        self.assertEqual(manifest["source_capsule"]["file_count"], 35)

    def test_plan_only_cli_is_machine_readable_and_bounded(self):
        completed = subprocess.run(
            [sys.executable, str(DRIVER), "--plan-only"],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        plan = json.loads(completed.stdout)
        self.assertEqual(plan["profile"], self.manifest["profile"])
        self.assertEqual(plan["result_contract"]["total"], 210)
        self.assertEqual(plan["result_contract"]["success"], 210)
        self.assertEqual(plan["result_contract"]["failed"], 0)
        self.assertEqual(plan["result_contract"]["timeout"], 0)
        self.assertEqual(
            plan["command"],
            [
                "<upstream>/scripts/tests",
                "cbmc",
                "-j",
                "2",
                "--mldsa-parameter-set",
                "44",
                "--per-proof-timeout",
                "1800",
                "--output-result-json",
                "<output>/cbmc-result.json",
            ],
        )

    def test_cli_rejects_noncanonical_proof_timeout(self):
        completed = subprocess.run(
            [
                sys.executable,
                str(DRIVER),
                "--plan-only",
                "--per-proof-timeout",
                "1801",
            ],
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("must match the pinned manifest contract", completed.stderr)

    def test_json_loader_rejects_duplicate_keys_and_nonfinite_numbers(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ambiguous.json"
            for payload in ('{"key": 1, "key": 2}', '{"key": NaN}'):
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding="utf8")
                    with self.assertRaises(cbmc.AuditError):
                        cbmc.load_json_object(path, "test evidence")

    def test_result_validator_accepts_exact_success_inventory(self):
        proof_uids = ["proof-a", "proof-b", "proof-c"]
        self.assertEqual(
            cbmc.validate_result(valid_result(proof_uids), proof_uids, 44), []
        )

    def test_result_validator_rejects_incomplete_or_malformed_evidence(self):
        proof_uids = ["proof-a", "proof-b"]
        mutations = {
            "wrong parameter": lambda value: value.update(
                {"mldsa_parameter_set": "65"}
            ),
            "wrong total": lambda value: value["summary"].update({"total": 1}),
            "boolean total": lambda value: value["summary"].update({"total": True}),
            "reported failure": lambda value: value.update(
                {"failures": [{"name": "proof-a", "status": "Failure"}]}
            ),
            "missing proof": lambda value: value["runtimes"].pop(),
            "duplicate proof": lambda value: value["runtimes"].append(
                copy.deepcopy(value["runtimes"][0])
            ),
            "failed status": lambda value: value["runtimes"][0].update(
                {"status": "failed"}
            ),
            "boolean runtime": lambda value: value["runtimes"][0].update(
                {"value": True}
            ),
            "wrong unit": lambda value: value["runtimes"][0].update(
                {"unit": "milliseconds"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                result = valid_result(proof_uids)
                mutate(result)
                self.assertTrue(cbmc.validate_result(result, proof_uids, 44))

    def test_capsule_manifest_hash_matches_exact_checked_in_file_set(self):
        source = json.loads(SOURCE_MANIFEST.read_text(encoding="utf8"))
        self.assertEqual(
            source["capsule_hash"]["construction"],
            "SHA256 of '<file-sha256>  ./<relative-path>\\n' lines ordered "
            "by relative path",
        )
        root = SOURCE_MANIFEST.parent
        actual_files = sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path != SOURCE_MANIFEST
        )
        self.assertEqual(actual_files, source["files"])
        digest_lines = []
        for relative in actual_files:
            digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            digest_lines.append(f"{digest}  ./{relative}\n")
        aggregate = hashlib.sha256("".join(digest_lines).encode("utf8")).hexdigest()
        self.assertEqual(aggregate, self.manifest["source_capsule"]["aggregate_sha256"])
        self.assertEqual(aggregate, source["capsule_hash"]["value"])

    def test_workflow_is_read_only_pinned_and_retains_failure_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        for required in (
            "pull_request:",
            "push:",
            "- main",
            "workflow_dispatch:",
            "contents: read",
            "timeout-minutes: 180",
            "Pinned upstream ML-DSA-44 (210 proofs)",
            "834a90d5e846ffa1e1611bd24e160bb2e9b86d35",
            "--no-update-lock-file --no-write-lock-file",
            "run_cbmc_reproduction.py",
            "--parallel-jobs 2",
            "--per-proof-timeout 1800",
            "if: always()",
            "if-no-files-found: error",
            "retention-days: 90",
            "github.run_id",
            "github.run_attempt",
        ):
            self.assertIn(required, workflow)
        for action in (
            "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
            "cachix/install-nix-action@08dcb3a5e62fa31e2da3d490afc4176ef55ecd72",
            "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
        ):
            self.assertIn(action, workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 2)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("gh-pages", workflow)
        self.assertNotIn("gh pr", workflow)

    def test_scope_boundary_keeps_production_and_review_gates_open(self):
        scope = self.manifest["scope"]
        self.assertTrue(scope["checked_in_capsule_byte_equivalence_required"])
        self.assertFalse(scope["pqbtc_wrapper_proven"])
        self.assertFalse(scope["functional_correctness_proven"])
        self.assertFalse(scope["constant_time_or_leakage_resistance_proven"])
        self.assertFalse(scope["production_integration"])
        self.assertTrue(scope["release_hold_unchanged"])

        readme = (ENGINEERING_DIR / "README.md").read_text(encoding="utf8")
        wrapper_doc = (REPO_ROOT / "docs" / "ML_DSA_44_WRAPPER_PROTOTYPE.md").read_text(
            encoding="utf8"
        )
        for text in (readme, wrapper_doc):
            self.assertIn("Pinned Upstream CBMC Reproduction", text)
            self.assertIn("210", text)
            self.assertIn("does not", text)
            self.assertIn("release hold", text.lower())
        self.assertIn("independent human cryptographic review", wrapper_doc)


if __name__ == "__main__":
    unittest.main()
