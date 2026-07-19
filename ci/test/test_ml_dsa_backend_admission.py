import json
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINEERING_DIR = REPO_ROOT / "contrib" / "ml-dsa-engineering"
ADMISSION_PATH = ENGINEERING_DIR / "backend_admission.json"
REFERENCE_PATH = REPO_ROOT / "contrib" / "ml-dsa-ref" / "vectors.json"
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
        self.assertEqual(build["max_signing_attempts"], 814)
        self.assertEqual(build["randomized_entry_point"], "mldsa_signature")
        self.assertFalse(build["deterministic_entry_points_exported"])
        self.assertTrue(build["custom_randombytes_inside_wrapper_module"])
        self.assertTrue(build["custom_zeroize_required"])
        self.assertTrue(build["self_verify_before_release"])

    def test_all_release_gates_remain_open(self):
        gates = self.admission["open_gates"]
        self.assertEqual(
            {gate["tracking_issue"] for gate in gates},
            {181, 184, 185, 186, 187, 188, 189, 190},
        )
        self.assertNotIn("CLOSED", {gate["status"] for gate in gates})

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
