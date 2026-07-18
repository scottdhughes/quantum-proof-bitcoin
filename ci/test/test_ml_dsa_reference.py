import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_DIR = REPO_ROOT / "contrib" / "ml-dsa-ref"
DRIVER_PATH = REFERENCE_DIR / "compare_oracles.py"
MANIFEST_PATH = REFERENCE_DIR / "vectors.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compare_oracles = load_module(DRIVER_PATH, "compare_ml_dsa_oracles")


class MLDSAReferenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf8"))

    def test_manifest_contract(self):
        compare_oracles.validate_manifest(self.manifest)

    def test_complete_selected_profile_acvp_contract(self):
        coverage = self.manifest["acvp_coverage"]
        self.assertEqual(coverage["keygen"]["test_case_ids"], list(range(1, 26)))
        self.assertEqual(
            [group["test_case_ids"] for group in coverage["siggen"]],
            [list(range(1, 16)), list(range(181, 196))],
        )
        self.assertEqual(coverage["sigver"]["test_case_ids"], list(range(1, 16)))
        self.assertEqual(coverage["sigver"]["accepted_test_case_ids"], [6, 7, 11])
        self.assertEqual(coverage["total_cases"], 70)

    def test_profile_and_randomized_posture(self):
        profile = self.manifest["profile"]
        self.assertEqual(profile["name"], "ML-DSA-44")
        self.assertEqual(profile["nist_security_category"], 2)
        self.assertEqual(profile["public_key_bytes"], 1312)
        self.assertEqual(profile["private_key_bytes"], 2560)
        self.assertEqual(profile["signature_bytes"], 2420)
        self.assertEqual(profile["randomizer_bytes"], 32)
        self.assertEqual(
            profile["production_signing_if_selected"], "hedged_randomized"
        )

    def test_source_pins_and_lineage_limit(self):
        sources = self.manifest["sources"]
        self.assertEqual(sources["openssl"]["version"], "3.6.3")
        self.assertEqual(sources["mldsa_native"]["tag"], "v1.0.0-beta2")
        for name in ("nist_acvp", "openssl", "mldsa_native"):
            self.assertRegex(sources[name]["commit"], r"^[0-9a-f]{40}$")
        for name in (
            "nist_fips204",
            "nist_fips204_potential_updates",
            "nist_fips204_section6_guidance",
        ):
            self.assertRegex(sources[name]["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn(
            "not independent cryptographic review",
            sources["mldsa_native"]["lineage_limit"],
        )

    def test_manifest_rejects_coverage_drift(self):
        mutated = copy.deepcopy(self.manifest)
        mutated["acvp_coverage"]["sigver"]["test_case_ids"].pop()
        with self.assertRaisesRegex(compare_oracles.ReferenceError, "ACVP coverage"):
            compare_oracles.validate_manifest(mutated)

    def test_hex_mutation_is_bounded(self):
        original = "00112233"
        mutated = compare_oracles.flip_hex_byte(original, 2)
        self.assertEqual(mutated, "00112333")
        self.assertEqual(len(mutated), len(original))

    def test_adapters_enforce_signature_and_key_boundaries(self):
        for source_name in ("openssl_oracle.c", "mldsa_native_oracle.c"):
            source = (REFERENCE_DIR / source_name).read_text(encoding="utf8")
            self.assertIn("if (signature_size != SIGNATURE_SIZE)", source)
            self.assertIn('printf("verified=0\\n")', source)
            self.assertIn('strcmp(argv[1], "public-key")', source)
        openssl_source = (REFERENCE_DIR / "openssl_oracle.c").read_text(encoding="utf8")
        self.assertNotIn("private_key + PRIVATE_KEY_SIZE - PUBLIC_KEY_SIZE", openssl_source)
        native_source = (REFERENCE_DIR / "mldsa_native_oracle.c").read_text(encoding="utf8")
        self.assertIn("mldsa_pk_from_sk", native_source)

    def test_manifest_only_cli(self):
        result = subprocess.run(
            [sys.executable, str(DRIVER_PATH), "--manifest-only"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("manifest validation passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
