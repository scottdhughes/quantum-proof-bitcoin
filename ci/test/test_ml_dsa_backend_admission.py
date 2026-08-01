import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
ADMISSION_PATH = ENGINEERING_DIR / "backend_admission.json"
REFERENCE_PATH = REPO_ROOT / "contrib" / "ml-dsa-ref" / "vectors.json"
CONFIG_PATH = ENGINEERING_DIR / "pqbtc_mldsa44_config.h"
DECISION_PATH = REPO_ROOT / "docs" / "ML_DSA_44_BACKEND_ADMISSION.md"


class MLDSABackendAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.admission = json.loads(ADMISSION_PATH.read_text(encoding="utf8"))
        self.reference = json.loads(REFERENCE_PATH.read_text(encoding="utf8"))

    def test_decision_is_prototype_only(self):
        decision = self.admission["decision"]
        self.assertEqual(
            decision["id"], "MLDSA_NATIVE_PORTABLE_C_ISOLATED_PROTOTYPE"
        )
        self.assertEqual(decision["production_backend"], "NONE")
        self.assertTrue(decision["release_hold"])
        self.assertEqual(
            set(decision["prohibited_integrations"]),
            {
                "node",
                "wallet",
                "script",
                "consensus",
                "alg_id",
                "functional_suite_inventory",
            },
        )

    def test_profile_matches_frozen_reference(self):
        profile = self.admission["profile"]
        reference = self.reference["profile"]
        for key in (
            "name",
            "standard",
            "signature_interface",
            "message_mode",
            "public_key_bytes",
            "private_key_bytes",
            "signature_bytes",
            "randomizer_bytes",
        ):
            self.assertEqual(profile[key], reference[key])
        self.assertEqual(profile["production_signing"], "hedged_randomized_only")

    def test_candidate_pins_match_reference_evidence(self):
        assessments = self.admission["candidate_assessments"]
        sources = self.reference["sources"]
        expected = {
            "openssl_3_6_3": sources["openssl"]["commit"],
            "mldsa_native_portable_c": sources["mldsa_native"]["commit"],
            "libcrux_ml_dsa_0_0_10_portable": sources["libcrux"]["commit"],
        }
        self.assertEqual(
            {name: candidate["source_commit"] for name, candidate in assessments.items()},
            expected,
        )
        for candidate in assessments.values():
            self.assertRegex(candidate["source_tree"], r"^[0-9a-f]{40}$")
            self.assertEqual(candidate["conformance"], "PASS")

    def test_exactly_one_isolated_prototype_is_admitted(self):
        assessments = self.admission["candidate_assessments"]
        admitted = [
            name
            for name, candidate in assessments.items()
            if candidate["outcome"] == "ISOLATED_PROTOTYPE_ADMITTED"
        ]
        self.assertEqual(admitted, ["mldsa_native_portable_c"])
        self.assertEqual(assessments["openssl_3_6_3"]["outcome"], "ORACLE_ONLY")
        self.assertEqual(
            assessments["libcrux_ml_dsa_0_0_10_portable"]["outcome"],
            "ORACLE_ONLY",
        )

    def test_prototype_build_contract_hides_test_and_deterministic_apis(self):
        build = self.admission["admitted_prototype"]["build_contract"]
        self.assertEqual(build["language"], "portable_c")
        self.assertEqual(build["translation_units"], 1)
        self.assertEqual(build["parameter_set"], 44)
        self.assertFalse(build["native_arithmetic_backend"])
        self.assertFalse(build["native_fips202_backend"])
        self.assertEqual(build["external_api_qualifier"], "static")
        self.assertFalse(build["supercop_aliases"])
        self.assertEqual(build["max_signing_attempts"], 821)
        config = CONFIG_PATH.read_text(encoding="utf8")
        self.assertIn(
            f"#define MLD_CONFIG_MAX_SIGNING_ATTEMPTS "
            f"{build['max_signing_attempts']}",
            config,
        )
        self.assertEqual(build["randomized_entry_point"], "mldsa_signature")
        self.assertFalse(build["deterministic_entry_points_exported"])
        self.assertTrue(build["custom_randombytes_inside_wrapper_module"])
        self.assertTrue(build["custom_zeroize_required"])
        self.assertTrue(build["self_verify_before_release"])

    def test_implemented_prototype_remains_isolated(self):
        evidence = self.admission["admitted_prototype"]["implementation_evidence"]
        self.assertEqual(evidence["status"], "ISOLATED_PROTOTYPE_IMPLEMENTED")
        self.assertEqual(evidence["source_capsule"]["files"], 34)
        self.assertEqual(
            evidence["source_capsule"]["capsule_sha256"],
            "2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb",
        )
        self.assertEqual(evidence["source_capsule"]["native_backend_files"], 0)
        self.assertEqual(
            evidence["production_shaped_exports"],
            ["pqbtc_mldsa44_sign_hedged", "pqbtc_mldsa44_verify_strict"],
        )
        self.assertTrue(evidence["test_build_separate"])
        self.assertFalse(evidence["test_controls_in_production_shaped_build"])
        self.assertFalse(evidence["node_linkage"])
        self.assertFalse(evidence["wallet_linkage"])
        self.assertFalse(evidence["consensus_linkage"])

    def test_all_release_gates_remain_open(self):
        gates = self.admission["open_gates"]
        self.assertEqual(
            {
                gate["tracking_issue"]: (gate["id"], gate["status"])
                for gate in gates
            },
            {
                181: ("independent_human_review", "OPEN"),
                184: (
                    "entropy_and_failure_binding",
                    "ISOLATED_PROTOTYPE_EVIDENCE_PLATFORM_LIFECYCLE_OPEN",
                ),
                185: (
                    "supported_platform_side_channel",
                    "BOUNDED_X86_64_VALGRIND_EVIDENCE_BROADER_PLATFORMS_OPEN",
                ),
                186: ("fault_resistance", "OPEN"),
                187: (
                    "secret_lifecycle_and_erasure",
                    "ISOLATED_SOURCE_AND_SANITIZER_EVIDENCE_OPEN",
                ),
                188: (
                    "structure_aware_fuzzing_and_resources",
                    (
                        "DIFFERENTIAL_STATEFUL_SANITIZER_MIRI_AND_CLI_"
                        "EVIDENCE_RESOURCES_OPEN"
                    ),
                ),
                189: (
                    "backend_advisory_and_sbom_refresh",
                    (
                        "TECHNICAL_REMEDIATION_IMPLEMENTED_EXACT_COMMIT_"
                        "RE_REVIEW_OPEN"
                    ),
                ),
                190: ("wallet_and_key_format", "OPEN"),
            },
        )
        advisory_gate = next(
            gate for gate in gates if gate["tracking_issue"] == 189
        )
        self.assertEqual(
            advisory_gate["status"],
            "TECHNICAL_REMEDIATION_IMPLEMENTED_EXACT_COMMIT_RE_REVIEW_OPEN",
        )
        libcrux = self.admission["candidate_assessments"][
            "libcrux_ml_dsa_0_0_10_portable"
        ]
        self.assertEqual(libcrux["advisory_evidence"]["full_lock_packages"], 139)
        self.assertEqual(libcrux["advisory_evidence"]["selected_graph_packages"], 16)
        self.assertEqual(libcrux["advisory_evidence"]["exact_commit_re_review"], "PENDING")
        self.assertEqual(libcrux["outcome"], "ORACLE_ONLY")
        self.assertEqual(
            libcrux["advisory_evidence"]["simd256_advisory_regressions"],
            {
                "advisories": ["RUSTSEC-2026-0125", "RUSTSEC-2026-0126"],
                "status": "PASS",
                "repository_commit": (
                    "f301227089086dad6918a76814d7227e61e2d71b"
                ),
                "source_manifest": (
                    "docs/reviews/evidence/ml-dsa-44-simd256/"
                    "f301227089086dad6918a76814d7227e61e2d71b/"
                    "run-30242969373-attempt-1/SOURCE.json"
                ),
                "test_only": True,
                "simd256_admitted": False,
            },
        )

    def test_normative_document_records_same_disposition(self):
        decision = DECISION_PATH.read_text(encoding="utf8")
        self.assertIn("MLDSA_NATIVE_PORTABLE_C_ISOLATED_PROTOTYPE", decision)
        self.assertIn("production backend remains `NONE`", decision)
        self.assertIn("OpenSSL 3.6.3", decision)
        self.assertIn("mldsa-native", decision)
        self.assertIn("libcrux", decision)
        self.assertIn("RELEASE_HOLD", decision)


if __name__ == "__main__":
    unittest.main()
