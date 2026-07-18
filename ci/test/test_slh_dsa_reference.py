import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
REFERENCE_DIR = REPO_ROOT / "contrib" / "slh-dsa-ref"
DRIVER_PATH = REFERENCE_DIR / "compare_oracles.py"
MANIFEST_PATH = REFERENCE_DIR / "vectors.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compare_oracles = load_module(DRIVER_PATH, "compare_oracles")


class SLHDSAReferenceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf8"))

    def test_manifest_contract(self):
        compare_oracles.validate_manifest(self.manifest)

    def test_private_keys_embed_the_expected_public_keys(self):
        vectors = self.manifest["vectors"]
        for name in ("nist_keygen_tg1_tc1", "pqbtc_sighash_v1"):
            vector = vectors[name]
            self.assertTrue(
                vector["expected_private_key_hex"].endswith(vector["expected_public_key_hex"])
            )

    def test_complete_selected_profile_acvp_contract(self):
        coverage = self.manifest["acvp_coverage"]
        self.assertEqual(coverage["keygen"]["test_case_ids"], list(range(1, 11)))
        self.assertEqual(
            [group["test_case_ids"] for group in coverage["siggen"]],
            [list(range(157, 164)), list(range(469, 476))],
        )
        self.assertEqual(coverage["sigver"]["test_case_ids"], list(range(253, 267)))
        self.assertEqual(coverage["sigver"]["accepted_test_case_ids"], [258, 266])
        self.assertEqual(coverage["total_cases"], 38)

    def test_randomized_posture_and_source_pins(self):
        profile = self.manifest["profile"]
        sources = self.manifest["sources"]
        self.assertEqual(profile["randomizer_bytes"], 16)
        self.assertEqual(
            profile["exact_vector_signing"], "deterministic_or_fixed_randomizer"
        )
        self.assertEqual(profile["production_signing_if_selected"], "randomized")
        self.assertEqual(sources["openssl"]["version"], "3.6.3")
        for name in ("nist_acvp", "openssl", "slhdsa_c"):
            self.assertRegex(sources[name]["commit"], r"^[0-9a-f]{40}$")

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

    def test_adapters_enforce_exact_signature_length(self):
        for source_name in ("openssl_oracle.c", "slhdsa_c_oracle.c"):
            source = (REFERENCE_DIR / source_name).read_text(encoding="utf8")
            self.assertIn("if (signature_size != SIGNATURE_SIZE)", source)
            self.assertIn('printf("verified=0\\n")', source)

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
