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
