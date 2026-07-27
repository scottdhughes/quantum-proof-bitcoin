# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
DRIVER = ENGINEERING_DIR / "run_libcrux_simd256_regressions.py"
HARNESS = ENGINEERING_DIR / "libcrux_simd256_regression.rs"
SOURCE_MANIFEST = (
    ENGINEERING_DIR / "fuzz_sources" / "wycheproof" / "SOURCE.json"
)
VECTOR_FILE = (
    ENGINEERING_DIR
    / "fuzz_sources"
    / "wycheproof"
    / "mldsa_44_verify_test.json"
)
LEDGER = ENGINEERING_DIR / "advisory_ledger.json"
BACKEND_ADMISSION = ENGINEERING_DIR / "backend_admission.json"
WORKFLOW = (
    REPO_ROOT / ".github" / "workflows" / "ml-dsa-44-simd256-regressions.yml"
)

SPEC = importlib.util.spec_from_file_location(
    "run_libcrux_simd256_regressions",
    DRIVER,
)
assert SPEC is not None and SPEC.loader is not None
simd256 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = simd256
SPEC.loader.exec_module(simd256)


class MlDsaSimd256RegressionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = simd256.load_wycheproof_cases()
        cls.plan = simd256.plan_document(cls.cases)

    def test_wycheproof_cases_are_exactly_bound(self):
        self.assertEqual(
            simd256.sha256_file(SOURCE_MANIFEST),
            "3522cf3ae87aaa929f8d6b0e3be809665d809ce97b71cc01aa3256d7f2b0f1f2",
        )
        self.assertEqual(
            simd256.sha256_file(VECTOR_FILE),
            "5ec04790c240c443ca8b662b8fc871834602c7cce87fcd36a193110745b2b9ea",
        )
        self.assertEqual(
            [case["test_case_id"] for case in self.cases],
            [147, 148],
        )
        self.assertEqual(
            [case["expected_valid"] for case in self.cases],
            [True, False],
        )
        self.assertEqual(
            [case["signature_sha256"] for case in self.cases],
            [
                "5306515480c0f680da054413c248876024870eaccf8032703aaf06105c1a2191",
                "0642b1cb6f51243aa6292fc11caa41e6f21ac7072988b0fa939c5d73cfcc6629",
            ],
        )
        for field in ("public_key_hex", "message_hex", "context_hex"):
            self.assertEqual(self.cases[0][field], self.cases[1][field])

    def test_wycheproof_mutation_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            mutated = Path(temporary) / VECTOR_FILE.name
            shutil.copyfile(VECTOR_FILE, mutated)
            value = bytearray(mutated.read_bytes())
            value[-2] ^= 1
            mutated.write_bytes(value)
            with self.assertRaisesRegex(
                simd256.RegressionError,
                "Wycheproof vector file SHA256 mismatch",
            ):
                simd256.load_wycheproof_cases(
                    source_manifest_path=SOURCE_MANIFEST,
                    vector_file_path=mutated,
                )

    def test_execution_contract_is_test_only_and_fail_closed(self):
        execution = self.plan["execution_contract"]
        self.assertEqual(execution["architecture"], "x86_64")
        self.assertEqual(execution["required_cpu_feature"], "avx2")
        self.assertEqual(execution["target_triple"], "x86_64-unknown-linux-gnu")
        self.assertFalse(execution["default_features"])
        self.assertEqual(execution["features"], ["mldsa44", "simd256", "std"])
        self.assertEqual(execution["compiled_backends"], ["portable", "simd256"])
        self.assertEqual(execution["called_backends"], ["portable", "avx2"])
        self.assertEqual(
            execution["required_environment"],
            {
                "LIBCRUX_DISABLE_SIMD128": "1",
                "LIBCRUX_DISABLE_SIMD256": "UNSET",
                "LIBCRUX_ENABLE_SIMD256": "1",
            },
        )
        self.assertEqual(execution["production_backend"], "NONE")
        self.assertFalse(execution["simd256_admitted"])
        self.assertTrue(execution["release_hold"])
        self.assertFalse(execution["release_hold_changed"])
        self.assertEqual(execution["rustsec_2026_0125_profile"], "debug")
        self.assertEqual(
            execution["rustsec_2026_0126_profiles"],
            ["debug", "release"],
        )
        self.assertEqual(
            self.plan["source_contract"]["crate_tree_sha256"],
            "26b2206e58eb6cf4de2a49c3185a85c3961bf9b5b43cc020f63a1d1b92b75faa",
        )

    def test_exact_upstream_invntt_regressions_are_frozen(self):
        self.assertEqual(
            self.plan["advisories"]["RUSTSEC-2026-0126"][
                "upstream_libtest_paths"
            ],
            [
                "simd::avx2::invntt::tests::inv_ntt_unreduced_max",
                "simd::avx2::invntt::tests::inv_ntt_reduced",
                "simd::avx2::invntt::tests::inv_ntt_reduced_large",
            ],
        )
        source = DRIVER.read_text(encoding="utf8")
        self.assertIn('"--lib",\n                    test_name,', source)
        self.assertIn('"--",\n                    "--exact",', source)
        self.assertIn('("release", ["--release"])', source)
        self.assertIn("timeout_seconds=300", source)
        self.assertNotIn("source patch", source.lower())
        self.assertNotIn("cfg(test)", source)

    def test_libtest_success_requires_one_exact_named_test(self):
        test_name = simd256.INVNTT_TESTS[0]
        valid = (
            "running 1 test\n"
            f"test {test_name} ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; "
            "0 measured; 73 filtered out; finished in 0.00s\n"
        )
        simd256.require_exact_libtest_success(valid, test_name)

        zero_tests = (
            "running 0 tests\n\n"
            "test result: ok. 0 passed; 0 failed; 0 ignored; "
            "0 measured; 74 filtered out; finished in 0.00s\n"
        )
        with self.assertRaisesRegex(
            simd256.RegressionError,
            "did not select exactly one",
        ):
            simd256.require_exact_libtest_success(zero_tests, test_name)

        wrong_test = valid.replace(test_name, simd256.INVNTT_TESTS[1])
        with self.assertRaisesRegex(
            simd256.RegressionError,
            "did not run and pass exactly once",
        ):
            simd256.require_exact_libtest_success(wrong_test, test_name)

    def test_rust_toolchain_version_is_exact(self):
        self.assertEqual(
            simd256.require_tool_version(
                "rustc 1.89.0 (29483883e 2025-08-04)\n",
                "rustc",
            ),
            "rustc 1.89.0 (29483883e 2025-08-04)",
        )
        with self.assertRaisesRegex(simd256.RegressionError, "version drifted"):
            simd256.require_tool_version("cargo 1.90.0 (unknown)\n", "cargo")

    def test_harness_calls_portable_and_avx2_explicitly(self):
        source = HARNESS.read_text(encoding="utf8")
        self.assertIn("portable::verify(", source)
        self.assertIn("avx2::verify(", source)
        self.assertIn('std::is_x86_feature_detected!("avx2")', source)
        self.assertIn("arguments.len() > 5", source)
        self.assertIn("raw_arguments.next().is_some()", source)
        self.assertIn("PUBLIC_KEY_SIZE: usize = 1312", source)
        self.assertIn("SIGNATURE_SIZE: usize = 2420", source)
        self.assertEqual(
            simd256.sha256_file(HARNESS),
            "babe124c26ce5ea6d0056c6314bd0475e6f98004fa099fc679429db3fca53008",
        )

    def test_subprocesses_never_use_a_shell(self):
        tree = ast.parse(DRIVER.read_text(encoding="utf8"))
        subprocess_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        ]
        self.assertTrue(subprocess_calls)
        for call in subprocess_calls:
            keywords = {keyword.arg: keyword.value for keyword in call.keywords}
            self.assertNotIn("shell", keywords)
        environment = simd256.regression_environment()
        self.assertEqual(environment["LIBCRUX_DISABLE_SIMD128"], "1")
        self.assertEqual(environment["LIBCRUX_ENABLE_SIMD256"], "1")
        self.assertNotIn("LIBCRUX_DISABLE_SIMD256", environment)

    def test_pr_and_main_evidence_have_distinct_trust(self):
        pull_request = simd256.classify_trust(
            "pull_request",
            "refs/pull/211/merge",
        )
        self.assertEqual(pull_request["label"], "UNTRUSTED_PR_EVIDENCE")
        self.assertFalse(pull_request["may_report_pass"])
        self.assertFalse(pull_request["eligible_for_ledger_promotion"])

        main = simd256.classify_trust("push", "refs/heads/main")
        self.assertEqual(main["label"], "TRUSTED_MAIN_EVIDENCE")
        self.assertTrue(main["may_report_pass"])
        self.assertTrue(main["eligible_for_ledger_promotion"])

        branch = simd256.classify_trust("workflow_dispatch", "refs/heads/topic")
        self.assertEqual(branch["label"], "UNTRUSTED_NON_MAIN_EVIDENCE")
        self.assertFalse(branch["may_report_pass"])
        self.assertIn(
            '"UNTRUSTED_OBSERVATION"',
            DRIVER.read_text(encoding="utf8"),
        )

    def test_main_failure_evidence_is_never_promotion_eligible(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            simd256.claim_output_directory(output)
            simd256.failure_report(
                output_dir=output,
                event_name="push",
                ref="refs/heads/main",
                repository_commit="0" * 40,
                run_id="123",
                run_attempt="1",
                error=simd256.RegressionError("expected failure"),
            )
            report = json.loads(
                (output / "simd256-regression-report.json").read_text(
                    encoding="utf8"
                )
            )
            self.assertEqual(report["status"], "FAIL")
            self.assertEqual(report["trust"]["label"], "TRUSTED_MAIN_EVIDENCE")
            self.assertFalse(report["trust"]["may_report_pass"])
            self.assertFalse(report["trust"]["eligible_for_ledger_promotion"])
            self.assertFalse(report["trust"]["actual_pass_capable"])

    def test_crate_archive_path_validation_rejects_escape_and_links(self):
        with self.assertRaisesRegex(simd256.RegressionError, "unsafe"):
            simd256._safe_member_path("../escape")
        with self.assertRaisesRegex(simd256.RegressionError, "unexpected"):
            simd256._safe_member_path("different-crate/file")
        self.assertEqual(
            simd256._safe_member_path("libcrux-ml-dsa-0.0.10/src/lib.rs"),
            simd256.PurePosixPath("libcrux-ml-dsa-0.0.10/src/lib.rs"),
        )

    def test_read_only_source_contract_is_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "crate"
            nested = root / "src"
            nested.mkdir(parents=True)
            source = nested / "lib.rs"
            source.write_text("pub fn marker() {}\n", encoding="utf8")
            before = simd256.tree_digest(root)
            simd256.make_tree_read_only(root)
            simd256.require_tree_read_only(root)
            self.assertEqual(before, simd256.tree_digest(root))
            self.assertFalse(source.stat().st_mode & stat.S_IWUSR)

    def test_evidence_directory_requires_an_exact_ownership_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            empty = Path(temporary) / "empty"
            simd256.claim_output_directory(empty)
            marker = empty / simd256.EVIDENCE_MARKER
            self.assertEqual(
                marker.read_text(encoding="utf8"),
                simd256.EVIDENCE_MARKER_CONTENT,
            )
            simd256.claim_output_directory(empty)

            unrelated = Path(temporary) / "unrelated"
            unrelated.mkdir()
            retained = unrelated / "keep.txt"
            retained.write_text("do not overwrite\n", encoding="utf8")
            with self.assertRaisesRegex(
                simd256.RegressionError,
                "not owned",
            ):
                simd256.claim_output_directory(unrelated)
            self.assertEqual(retained.read_text(encoding="utf8"), "do not overwrite\n")

            link = empty / "evidence-link"
            link.symlink_to(marker)
            with self.assertRaisesRegex(
                simd256.RegressionError,
                "evidence contains a symlink",
            ):
                simd256.claim_output_directory(empty)
            link.unlink()

            stale = empty / "stale.log"
            stale.write_text("stale\n", encoding="utf8")
            with self.assertRaisesRegex(
                simd256.RegressionError,
                "contains stale files",
            ):
                simd256.claim_output_directory(empty)

    def test_checked_in_ledger_and_backend_remain_unpromoted(self):
        ledger = json.loads(LEDGER.read_text(encoding="utf8"))
        advisories = {entry["id"]: entry for entry in ledger["advisories"]}
        for advisory_id in ("RUSTSEC-2026-0125", "RUSTSEC-2026-0126"):
            entry = advisories[advisory_id]
            self.assertEqual(entry["current_path_applicability"], "NOT_APPLICABLE")
            self.assertEqual(entry["test_status"], "UNTESTED")
            self.assertEqual(
                entry["future_admission"],
                "BLOCKED_UNTIL_EXACT_SIMD256_REGRESSION_PASSES",
            )
        self.assertFalse(ledger["execution_contract"]["simd256_admitted"])
        self.assertEqual(ledger["execution_contract"]["production_backend"], "NONE")
        self.assertTrue(ledger["execution_contract"]["release_hold"])

        admission = json.loads(BACKEND_ADMISSION.read_text(encoding="utf8"))
        serialized = json.dumps(admission, sort_keys=True)
        self.assertIn('"release_hold": true', serialized)
        self.assertIn('"production_backend": "NONE"', serialized)

    def test_workflow_is_x86_64_test_only_and_retains_untrusted_pr_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf8")
        self.assertIn("runs-on: ubuntu-24.04", workflow)
        self.assertIn("pull_request:", workflow)
        self.assertIn("push:", workflow)
        self.assertIn("branches:\n      - main", workflow)
        self.assertIn("--event-name \"$GITHUB_EVENT_NAME\"", workflow)
        self.assertIn("--ref \"$GITHUB_REF\"", workflow)
        self.assertIn("--repository-commit \"$AUDIT_SHA\"", workflow)
        self.assertIn("--run-id \"$AUDIT_RUN_ID\"", workflow)
        self.assertIn("--run-attempt \"$AUDIT_RUN_ATTEMPT\"", workflow)
        self.assertIn("PINNED_RUST_TOOLCHAIN: \"1.89.0\"", workflow)
        self.assertIn(
            'echo "RUSTUP_TOOLCHAIN=$PINNED_RUST_TOOLCHAIN" >> "$GITHUB_ENV"',
            workflow,
        )
        self.assertGreaterEqual(
            workflow.count(
                'test "$(git rev-parse HEAD)" = "$AUDIT_SHA"'
            ),
            2,
        )
        self.assertGreaterEqual(
            workflow.count(
                'git status --porcelain=v1 --untracked-files=all'
            ),
            2,
        )
        self.assertIn("LIBCRUX_DISABLE_SIMD128: \"1\"", workflow)
        self.assertIn("LIBCRUX_ENABLE_SIMD256: \"1\"", workflow)
        self.assertNotIn("LIBCRUX_DISABLE_SIMD256:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("sha256sum --check SHA256SUMS", workflow)
        self.assertIn('find "$EVIDENCE" -type l -print -quit', workflow)
        self.assertIn("${{ runner.temp }}/ml-dsa-44-simd256-evidence/", workflow)
        self.assertIn("timeout-minutes: 20", workflow)
        self.assertIn("ml-dsa-44-simd256-candidate-", workflow)
        self.assertIn("ml-dsa-44-simd256-main-", workflow)
        upload_v6 = (
            "actions/upload-artifact@"
            "b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6"
        )
        self.assertEqual(workflow.count(upload_v6), 2)
        self.assertEqual(workflow.count("include-hidden-files: true"), 2)
        self.assertNotIn("actions/upload-artifact@ea165f8d", workflow)
        self.assertIn("id: finalize_evidence", workflow)
        self.assertEqual(
            workflow.count(
                "steps.finalize_evidence.outcome == 'success'"
            ),
            2,
        )
        self.assertIn(
            "783ebed7cb27de6d44ef2aa662648d1a0869694f2f754f2f1ed45e959ef3b48e",
            workflow,
        )

    def test_plan_only_cli(self):
        completed = subprocess.run(
            [sys.executable, str(DRIVER), "--plan-only"],
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result, self.plan)


if __name__ == "__main__":
    unittest.main()
