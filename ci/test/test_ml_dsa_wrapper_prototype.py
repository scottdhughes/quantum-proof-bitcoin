#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import json
from pathlib import Path
import subprocess
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
SOURCE_MANIFEST = ENGINEERING_DIR / "vendor" / "mldsa-native" / "SOURCE.json"
ADMISSION = ENGINEERING_DIR / "backend_admission.json"
PROTOTYPE_DOCUMENT = REPO_ROOT / "docs" / "ML_DSA_44_WRAPPER_PROTOTYPE.md"
FUZZ_MANIFEST = ENGINEERING_DIR / "verifier_fuzz_corpus.json"
STATIC_ANALYSIS = ENGINEERING_DIR / "run_static_analysis.py"
VALGRIND_CT_ANALYSIS = ENGINEERING_DIR / "run_valgrind_ct_analysis.py"


def load_static_analysis_plan() -> dict:
    completed = subprocess.run(
        [sys.executable, str(STATIC_ANALYSIS), "--plan-only"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout)


def load_valgrind_ct_plan(toolchain: str, compiler: str) -> dict:
    completed = subprocess.run(
        [
            sys.executable,
            str(VALGRIND_CT_ANALYSIS),
            "--plan-only",
            "--toolchain-id",
            toolchain,
            "--cc",
            compiler,
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return json.loads(completed.stdout)


class MlDsaWrapperPrototypeTest(unittest.TestCase):
    def test_source_capsule_is_exact_portable_pin(self):
        manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf8"))
        self.assertEqual(manifest["tag"], "v1.0.0-beta2")
        self.assertEqual(
            manifest["commit"], "9b0ee84f4cf399043eca59eca4e5f8531ca1d61b"
        )
        self.assertEqual(len(manifest["files"]), 34)
        self.assertEqual(
            manifest["capsule_hash"]["value"],
            "2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb",
        )
        self.assertEqual(
            manifest["upstream_git_archive_tar_sha256"],
            "4fd08a772d0a142863593471f0c26e239bac8babc8e2a960e072f06ee89ff30b",
        )
        self.assertFalse(any("/native/" in path for path in manifest["files"]))
        self.assertFalse(any(path.endswith(".S") for path in manifest["files"]))

    def test_build_contract_is_frozen(self):
        config = (ENGINEERING_DIR / "pqbtc_mldsa44_config.h").read_text(
            encoding="utf8"
        )
        for required in (
            "#define MLD_CONFIG_PARAMETER_SET 44",
            "#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static",
            "#define MLD_CONFIG_INTERNAL_API_QUALIFIER static",
            "#define MLD_CONFIG_NO_SUPERCOP",
            "#define MLD_CONFIG_NO_ASM",
            "#define MLD_CONFIG_MAX_SIGNING_ATTEMPTS 814",
            "#define MLD_CONFIG_CUSTOM_RANDOMBYTES",
            "#define MLD_CONFIG_CUSTOM_ZEROIZE",
        ):
            self.assertIn(required, config)

    def test_production_header_has_no_test_or_randomizer_control(self):
        header = (ENGINEERING_DIR / "pqbtc_mldsa44.h").read_text(encoding="utf8")
        self.assertIn("pqbtc_mldsa44_sign_hedged", header)
        self.assertIn("pqbtc_mldsa44_verify_strict", header)
        self.assertNotIn("test_", header)
        self.assertNotIn("fixed_randomizer", header)
        self.assertNotIn("entropy_callback", header)

    def test_production_hold_and_isolation_remain_explicit(self):
        admission = json.loads(ADMISSION.read_text(encoding="utf8"))
        self.assertEqual(admission["decision"]["production_backend"], "NONE")
        self.assertTrue(admission["decision"]["release_hold"])
        evidence = admission["admitted_prototype"]["implementation_evidence"]
        self.assertFalse(evidence["node_linkage"])
        self.assertFalse(evidence["wallet_linkage"])
        self.assertFalse(evidence["consensus_linkage"])
        document = PROTOTYPE_DOCUMENT.read_text(encoding="utf8")
        self.assertIn("ISOLATED_PROTOTYPE_IMPLEMENTED - RELEASE_HOLD", document)
        self.assertIn("backend remains `NONE`", document)
        self.assertIn("Issues `#181` and `#184` through `#190` remain open", document)

    def test_wrapper_build_and_behavior(self):
        subprocess.run(
            [sys.executable, str(ENGINEERING_DIR / "run_wrapper_tests.py")],
            cwd=REPO_ROOT,
            check=True,
        )

    def test_verifier_fuzz_corpus_is_frozen(self):
        manifest = json.loads(FUZZ_MANIFEST.read_text(encoding="utf8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["frame_version"], 1)
        self.assertEqual(manifest["fuzz_limits"]["frame_bytes"], 8096)
        self.assertEqual(manifest["generated_corpus"]["total_cases"], 207)
        self.assertEqual(manifest["generated_corpus"]["unique_frames"], 202)
        self.assertEqual(
            manifest["generated_corpus"]["source_counts"],
            {"project": 27, "wycheproof": 180},
        )
        subprocess.run(
            [
                sys.executable,
                str(ENGINEERING_DIR / "run_verifier_fuzz.py"),
                "--manifest-only",
            ],
            cwd=REPO_ROOT,
            check=True,
        )

    def test_static_analysis_plan_is_pinned(self):
        plan = load_static_analysis_plan()
        self.assertEqual(plan["schema_version"], 1)
        self.assertEqual(plan["expected_llvm_major"], 20)
        self.assertEqual(
            plan["tools"]["iwyu"]["source_commit"],
            "6e08906c66b3009f2d590e4bd40d60fa303bf803",
        )
        self.assertEqual(
            plan["tools"]["iwyu"]["source_dir"], "/include-what-you-use"
        )
        self.assertTrue(plan["scope"]["isolated_wrapper_only"])
        self.assertTrue(plan["scope"]["clang_tidy_wrapper_implementation"])
        self.assertFalse(plan["scope"]["iwyu_wrapper_implementation"])
        self.assertTrue(
            plan["scope"]["iwyu_first_party_leaf_units_and_headers"]
        )
        self.assertFalse(plan["scope"]["production_integration"])
        self.assertTrue(plan["scope"]["release_hold_unchanged"])
        self.assertTrue(
            plan["source_capsule"]["verified_against_checked_in_files"]
        )
        self.assertEqual(
            plan["reporting_boundary"]["vendor_root"],
            "contrib/ml-dsa-engineering/vendor",
        )
        self.assertTrue(
            plan["reporting_boundary"]["vendor_files_are_never_main_inputs"]
        )
        self.assertEqual(
            plan["reporting_boundary"]["clang_tidy_local_suppression"],
            {
                "check": "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling",
                "annotation": "NOLINTNEXTLINE",
                "occurrences": 13,
                "expected_occurrences": 13,
                "reason": (
                    "C11 Annex K _s functions are optional and unavailable on "
                    "the supported Linux toolchain"
                ),
            },
        )
        for evidence_source in (
            ".github/workflows/ml-dsa-44-wrapper-prototype.yml",
            ".github/workflows/promotion-matrix.yml",
            "ci/test/00_setup_env_native_tidy.sh",
            "ci/test/01_base_install.sh",
            "ci/test/03_test_script.sh",
            "ci/test/test_ml_dsa_wrapper_prototype.py",
            "contrib/ml-dsa-engineering/README.md",
        ):
            self.assertRegex(
                plan["source_files"][evidence_source], r"^[0-9a-f]{64}$"
            )

        checks = plan["checks"]
        counts = {
            kind: sum(check["kind"] == kind for check in checks)
            for kind in (
                "clang-tidy",
                "iwyu",
                "header-self-containment",
            )
        }
        self.assertEqual(
            counts,
            {
                "clang-tidy": 4,
                "iwyu": 2,
                "header-self-containment": 2,
            },
        )
        for check in checks:
            self.assertNotIn("/vendor/", check["input"])
            if check["kind"] == "clang-tidy":
                self.assertIn(
                    "--checks=clang-analyzer-*",
                    check["command"],
                )
                self.assertIn(
                    "--exclude-header-filter="
                    + plan["reporting_boundary"]["vendor_header_exclude"],
                    check["command"],
                )
                self.assertIn("--warnings-as-errors=*", check["command"])
            if check["kind"] == "iwyu":
                self.assertNotEqual(
                    check["input"],
                    "contrib/ml-dsa-engineering/pqbtc_mldsa44.c",
                )
                self.assertIn("--error=1", check["command"])
                self.assertTrue(check["check_also"])
                self.assertFalse(
                    any("/vendor/" in path for path in check["check_also"])
                )

    def test_static_analysis_plan_matches_wrapper_build_variants(self):
        plan = load_static_analysis_plan()
        self.assertEqual(plan["tools"]["clang"]["command"], "clang-20")
        self.assertEqual(
            plan["tools"]["clang-tidy"]["command"], "clang-tidy-20"
        )
        self.assertEqual(
            plan["tools"]["iwyu"]["command"], "include-what-you-use"
        )

        checks = {check["id"]: check for check in plan["checks"]}
        expected_ids = {
            "clang-tidy-wrapper-production",
            "clang-tidy-wrapper-testing",
            "clang-tidy-smoke-testing",
            "clang-tidy-verifier-fuzz",
            "iwyu-smoke-testing",
            "iwyu-verifier-fuzz",
            "header-self-contained-production",
            "header-self-contained-testing",
        }
        self.assertEqual(set(checks), expected_ids)
        for check in checks.values():
            self.assertIn("-std=c11", check["command"])

        testing_define = "-DPQBTC_MLDSA44_TESTING=1"
        self.assertNotIn(
            testing_define, checks["clang-tidy-wrapper-production"]["command"]
        )
        self.assertIn(
            testing_define, checks["clang-tidy-wrapper-testing"]["command"]
        )
        self.assertIn(testing_define, checks["clang-tidy-smoke-testing"]["command"])
        self.assertIn(testing_define, checks["iwyu-smoke-testing"]["command"])
        self.assertIn("-pthread", checks["clang-tidy-smoke-testing"]["command"])
        self.assertIn("-pthread", checks["iwyu-smoke-testing"]["command"])
        self.assertNotIn(
            testing_define, checks["clang-tidy-verifier-fuzz"]["command"]
        )
        self.assertNotIn(testing_define, checks["iwyu-verifier-fuzz"]["command"])

        for check_id in (
            "header-self-contained-production",
            "header-self-contained-testing",
        ):
            self.assertIn("-x", checks[check_id]["command"])
            self.assertIn("c-header", checks[check_id]["command"])
            self.assertIn("-fsyntax-only", checks[check_id]["command"])

    def test_valgrind_ct_plan_is_pinned(self):
        expected_toolchains = {
            "valgrind-varlat_clang20": ("clang", "clang", 20),
            "valgrind-varlat_gcc13": ("gcc", "gcc", 13),
        }
        for toolchain, (compiler, family, major) in expected_toolchains.items():
            plan = load_valgrind_ct_plan(toolchain, compiler)
            self.assertEqual(plan["schema_version"], 1)
            self.assertEqual(
                plan["optimization"],
                {"wrapper": "-O2", "positive_controls": "-O0"},
            )
            self.assertEqual(plan["host"]["required_system"], "Linux")
            self.assertEqual(plan["host"]["required_machine"], "x86_64")
            self.assertEqual(plan["tools"]["compiler"]["toolchain_id"], toolchain)
            self.assertEqual(plan["tools"]["compiler"]["compiler_family"], family)
            self.assertEqual(plan["tools"]["compiler"]["compiler_major"], major)
            self.assertEqual(plan["upstream_environment"]["nix_shell"], toolchain)

        plan = load_valgrind_ct_plan("valgrind-varlat_clang20", "clang")
        upstream = plan["upstream_environment"]
        self.assertEqual(
            upstream["commit"], "9b0ee84f4cf399043eca59eca4e5f8531ca1d61b"
        )
        self.assertEqual(
            upstream["git_tree"], "c73c7029182122fce2f2dd8ac544ae990abd74a2"
        )
        self.assertEqual(
            upstream["git_archive_tar_sha256"],
            "4fd08a772d0a142863593471f0c26e239bac8babc8e2a960e072f06ee89ff30b",
        )
        self.assertEqual(
            upstream["valgrind_patch_sha256"],
            "d54b140f2bacaea91470940a963950b7126685810df2192640cd103328b421f4",
        )
        self.assertEqual(
            upstream["flake_lock_sha256"],
            "cdc01dce87b0c9b8488baafb0e0ed5ec94064089f7b4d5b253aecfeef2ac1861",
        )
        self.assertEqual(
            upstream["nixpkgs_rev"],
            "23d72dabcb3b12469f57b37170fcbc1789bd7457",
        )
        self.assertEqual(
            upstream["nixpkgs_nar_hash"],
            "sha256-z5NJPSBwsLf/OfD8WTmh79tlSU8XgIbwmk6qB1/TFzY=",
        )
        self.assertEqual(
            plan["tools"]["nix"]["expected_version"], "nix (Nix) 2.24.9"
        )
        valgrind = plan["tools"]["valgrind"]
        self.assertEqual(valgrind["expected_version"], "valgrind-3.26.0")
        self.assertEqual(valgrind["expected_xml_protocol"], "6")
        self.assertEqual(valgrind["project_suppressions"], [])
        for required in (
            "--tool=memcheck",
            "--error-exitcode=99",
            "--leak-check=full",
            "--errors-for-leak-kinds=definite,indirect,possible",
            "--vex-guest-max-insns=55",
            "--variable-latency-errors=yes",
        ):
            self.assertIn(required, valgrind["flags"])
        self.assertNotIn("--track-origins=yes", valgrind["flags"])
        self.assertFalse(valgrind["track_origins"])
        self.assertEqual(valgrind["upstream_reference_error_exitcode"], 1)
        self.assertEqual(valgrind["audit_error_exitcode"], 99)

        taint = plan["taint_contract"]
        self.assertEqual(taint["secret_key_bytes"], 2560)
        self.assertEqual(taint["randomizer_bytes"], 32)
        self.assertEqual(taint["successful_hedged_signatures"], 5)
        self.assertEqual(taint["immediate_repeat_failures"], 1)
        self.assertEqual(taint["all_zero_failures"], 1)
        self.assertEqual(taint["project_secret_markers"], ["generated_randomizer"])
        self.assertEqual(len(taint["project_secret_calls"]), 1)
        self.assertEqual(
            taint["observed_project_declassification_markers"],
            ["randomizer_all_zero_predicate", "immediate_repeat_predicate"],
        )
        self.assertEqual(len(taint["project_declassification_calls"]), 2)
        self.assertEqual(len(taint["project_valgrind_secret_calls"]), 1)
        self.assertEqual(len(taint["project_valgrind_declassification_calls"]), 1)
        self.assertEqual(len(taint["harness_secret_calls"]), 1)
        self.assertEqual(taint["harness_declassification_calls"], [])
        self.assertEqual(len(taint["positive_control_secret_calls"]), 3)
        self.assertEqual(taint["upstream_active_declassification_sites"], 15)
        self.assertEqual(taint["upstream_syntactic_declassification_sites"], 18)
        self.assertEqual(taint["combined_active_source_declassification_sites"], 17)
        upstream_declassifications = taint["upstream_declassification_inventory"]
        self.assertEqual(len(upstream_declassifications["active"]), 15)
        self.assertEqual(len(upstream_declassifications["inactive"]), 3)
        self.assertRegex(upstream_declassifications["sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(taint["manual_output_declassification"])
        self.assertTrue(plan["scope"]["isolated_wrapper_only"])
        self.assertTrue(plan["scope"]["secret_key_signing"])
        self.assertTrue(plan["scope"]["seeded_key_generation_is_setup_only"])
        self.assertFalse(plan["scope"]["key_generation_constant_time"])
        self.assertFalse(plan["scope"]["production_integration"])
        self.assertTrue(plan["scope"]["release_hold_unchanged"])

        for source in (
            ".github/workflows/ml-dsa-44-wrapper-prototype.yml",
            "ci/test/test_ml_dsa_wrapper_prototype.py",
            "contrib/ml-dsa-engineering/README.md",
            "contrib/ml-dsa-engineering/pqbtc_mldsa44.c",
            "contrib/ml-dsa-engineering/pqbtc_mldsa44_ct_memcheck.c",
            "contrib/ml-dsa-engineering/pqbtc_mldsa44_ct_probe.c",
            "contrib/ml-dsa-engineering/run_valgrind_ct_analysis.py",
            "docs/PQSIG_PRODUCTION_READINESS.md",
        ):
            self.assertRegex(plan["source_files"][source], r"^[0-9a-f]{64}$")

    def test_valgrind_ct_plan_matches_wrapper_boundary(self):
        plan = load_valgrind_ct_plan("valgrind-varlat_clang20", "clang")
        builds = {build["id"]: build for build in plan["builds"]}
        self.assertEqual(set(builds), {"build-wrapper", "build-probe"})
        for build in builds.values():
            self.assertIn("-std=c11", build["command"])
            self.assertIn("-iquote", build["command"])
            self.assertIn("-idirafter", build["command"])
        wrapper_build = builds["build-wrapper"]["command"]
        probe_build = builds["build-probe"]["command"]
        self.assertIn("-O2", wrapper_build)
        self.assertIn("-O0", probe_build)
        self.assertIn("-DPQBTC_MLDSA44_TESTING=1", wrapper_build)
        self.assertIn("-DPQBTC_MLDSA44_CT_TESTING=1", wrapper_build)
        self.assertIn(
            "contrib/ml-dsa-engineering/pqbtc_mldsa44_ct_memcheck.c",
            wrapper_build,
        )

        checks = {check["id"]: check for check in plan["checks"]}
        self.assertEqual(
            set(checks),
            {
                "probe-branch",
                "probe-address",
                "probe-variable-latency",
                "secret-key-taint-control",
                "wrapper-ct",
            },
        )
        for check_id in (
            "probe-branch",
            "probe-address",
            "probe-variable-latency",
            "secret-key-taint-control",
        ):
            self.assertEqual(checks[check_id]["expected_return_code"], 99)
            self.assertTrue(checks[check_id]["expected_diagnostic"])
            self.assertTrue(checks[check_id]["expected_frame"])
        self.assertEqual(checks["secret-key-taint-control"]["kind"], "taint-control")
        self.assertEqual(checks["wrapper-ct"]["expected_return_code"], 0)
        self.assertEqual(checks["wrapper-ct"]["expected_error_count"], 0)

        config = (ENGINEERING_DIR / "pqbtc_mldsa44_config.h").read_text(
            encoding="utf8"
        )
        self.assertIn("#if defined(PQBTC_MLDSA44_CT_TESTING)", config)
        self.assertIn("#error PQBTC_MLDSA44_CT_TESTING requires", config)
        self.assertIn("#define MLD_CONFIG_CT_TESTING_ENABLED", config)

        wrapper = (ENGINEERING_DIR / "pqbtc_mldsa44.c").read_text(encoding="utf8")
        self.assertEqual(wrapper.count("// PQBTC_CT_SECRET:"), 1)
        self.assertEqual(wrapper.count("// PQBTC_CT_DECLASSIFICATION:"), 2)
        fill = wrapper.index("if (FillEntropy(ptr, len, &received) != 0)")
        secret = wrapper.index("// PQBTC_CT_SECRET: generated_randomizer")
        length = wrapper.index("if (received != len)")
        self.assertLess(fill, secret)
        self.assertLess(secret, length)

        harness = (ENGINEERING_DIR / "pqbtc_mldsa44_ct_memcheck.c").read_text(
            encoding="utf8"
        )
        self.assertIn("VALGRIND_MAKE_MEM_UNDEFINED(secret_key", harness)
        self.assertNotIn("VALGRIND_MAKE_MEM_DEFINED", harness)
        self.assertIn("ProbeSecretKeyTaint", harness)
        self.assertIn('strcmp(argv[1], "secret-key-taint")', harness)
        self.assertIn("scenario < 5", harness)
        self.assertIn("PQBTC_MLDSA44_ERR_ENTROPY_REPEAT", harness)
        self.assertIn("PQBTC_MLDSA44_ERR_ENTROPY_ALL_ZERO", harness)

        workflow = (
            REPO_ROOT / ".github/workflows/ml-dsa-44-wrapper-prototype.yml"
        ).read_text(encoding="utf8")
        valgrind_job = workflow.split("  valgrind-ct:\n", maxsplit=1)[1]
        self.assertIn("valgrind-varlat_clang20", valgrind_job)
        self.assertIn("valgrind-varlat_gcc13", valgrind_job)
        self.assertIn("matrix.nix_shell", valgrind_job)
        self.assertNotIn("matrix.nix-shell", valgrind_job)
        self.assertNotIn("runner.temp", valgrind_job)
        self.assertIn(
            "cachix/install-nix-action@08dcb3a5e62fa31e2da3d490afc4176ef55ecd72",
            valgrind_job,
        )
        self.assertIn("run_valgrind_ct_analysis.py", valgrind_job)
        self.assertIn("Upload Valgrind constant-time evidence", valgrind_job)
        self.assertIn("--no-update-lock-file --no-write-lock-file", valgrind_job)
        self.assertIn("if-no-files-found: error", valgrind_job)
        self.assertIn("timeout-minutes: 120", valgrind_job)


if __name__ == "__main__":
    unittest.main()
