"""Unit tests for the strict dual-mode SHRINCS verifier harness."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "check_full.py"
SPEC = importlib.util.spec_from_file_location("shrincs_full_verifier", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ShrincsFullVerifierTests(unittest.TestCase):
    def vector(self, name: str, signature_bytes: int) -> dict[str, str]:
        return {
            "name": name,
            "public_key": "11" * CHECKER.PUBLIC_KEY_BYTES,
            "signature": "22" * signature_bytes,
            "message": "33" * 32,
            "context": "",
        }

    def test_stateful_bounds_are_disjoint_from_stateless(self) -> None:
        self.assertLess(CHECKER.STATEFUL_MAX, CHECKER.STATELESS_BYTES)

    def test_corpus_requires_vectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.json"
            path.write_text(json.dumps({"vectors": []}), encoding="utf-8")
            with self.assertRaisesRegex(CHECKER.FullVerifierError, "must contain vectors"):
                CHECKER.read_corpus(path)

    def test_invalid_hex_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.FullVerifierError, "invalid hex"):
            CHECKER.decode_hex("zz", "signature")

    def test_unpack_rejects_wrong_public_key_size(self) -> None:
        vector = self.vector("bad-key", CHECKER.STATEFUL_MIN)
        vector["public_key"] = "11" * (CHECKER.PUBLIC_KEY_BYTES - 1)
        with self.assertRaisesRegex(CHECKER.FullVerifierError, "public-key length drifted"):
            CHECKER.unpack(vector)

    def test_vector_shapes_cover_both_modes(self) -> None:
        stateful = self.vector("stateful", CHECKER.STATEFUL_MIN)
        stateless = self.vector("stateless", CHECKER.STATELESS_BYTES)
        self.assertEqual(len(CHECKER.unpack(stateful)[1]), CHECKER.STATEFUL_MIN)
        self.assertEqual(len(CHECKER.unpack(stateless)[1]), CHECKER.STATELESS_BYTES)


if __name__ == "__main__":
    unittest.main()
