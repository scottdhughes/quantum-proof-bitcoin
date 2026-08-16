"""Unit tests for the stateless SHRINCS differential harness."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "check_stateless.py"
SPEC = importlib.util.spec_from_file_location("shrincs_stateless_oracle", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ShrincsStatelessOracleTests(unittest.TestCase):
    def manifest(self) -> dict:
        return {
            "upstream": {
                "draft_specification": {"commit": "a" * 40},
                "libshrincs_wotsc": {"commit": "b" * 40},
            }
        }

    def vector(self, name: str) -> dict:
        return {
            "name": name,
            "mode": "deterministic",
            "opt_rand": None,
            "message": "00" * 32,
            "context": "",
            "public_key": "11" * 48,
            "signature": "22" * 5776,
            "public_key_sha256": "33" * 32,
            "signature_sha256": "44" * 32,
        }

    def write_corpus(self, path: Path, profile: str = CHECKER.VECTOR_PROFILE) -> None:
        path.write_text(
            json.dumps(
                {
                    "profile": profile,
                    "draft_commit": "a" * 40,
                    "libshrincs_commit": "b" * 40,
                    "vectors": [self.vector("a"), self.vector("b")],
                }
            ),
            encoding="utf-8",
        )

    def test_selected_offsets_cover_twelve_regions(self) -> None:
        offsets = CHECKER.selected_signature_offsets(5776)
        self.assertEqual(len(offsets), 12)
        self.assertEqual(offsets[0], 0)
        self.assertEqual(offsets[-1], 5775)
        self.assertIn(16, offsets)
        self.assertIn(2256, offsets)

    def test_valid_vector_corpus_loads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            self.write_corpus(path)
            vectors = CHECKER.read_vectors(path, self.manifest())
            self.assertEqual([vector["name"] for vector in vectors], ["a", "b"])

    def test_vector_profile_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            self.write_corpus(path, profile="wrong")
            with self.assertRaisesRegex(CHECKER.StatelessOracleError, "profile drifted"):
                CHECKER.read_vectors(path, self.manifest())

    def test_vector_pin_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vectors.json"
            self.write_corpus(path)
            manifest = self.manifest()
            manifest["upstream"]["draft_specification"]["commit"] = "c" * 40
            with self.assertRaisesRegex(CHECKER.StatelessOracleError, "draft pin drifted"):
                CHECKER.read_vectors(path, manifest)

    def test_invalid_hex_is_rejected(self) -> None:
        vector = self.vector("bad")
        vector["signature"] = "zz"
        with self.assertRaisesRegex(CHECKER.StatelessOracleError, "invalid hex"):
            CHECKER.bytes_from_vector(vector, "signature")


if __name__ == "__main__":
    unittest.main()
