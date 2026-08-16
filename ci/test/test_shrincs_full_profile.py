"""Unit tests for the strict full-profile SHRINCS envelope."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs-ref" / "check_full_profile.py"
SPEC = importlib.util.spec_from_file_location("shrincs_full_profile", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ShrincsFullProfileTests(unittest.TestCase):
    def test_stateful_length_range_has_exactly_255_shapes(self) -> None:
        lengths = [
            length
            for length in range(CHECKER.MAX_TESTED_SIGNATURE_BYTES + 1)
            if CHECKER.expected_mode(length) == CHECKER.MODE_STATEFUL
        ]
        self.assertEqual(len(lengths), 255)
        self.assertEqual(lengths[0], 554)
        self.assertEqual(lengths[-1], 4618)
        self.assertTrue(all(right - left == 16 for left, right in zip(lengths, lengths[1:])))

    def test_stateless_length_is_unique(self) -> None:
        lengths = [
            length
            for length in range(CHECKER.MAX_TESTED_SIGNATURE_BYTES + 1)
            if CHECKER.expected_mode(length) == CHECKER.MODE_STATELESS
        ]
        self.assertEqual(lengths, [5776])

    def test_adjacent_and_legacy_lengths_are_invalid(self) -> None:
        invalid = [0, 64, 73, 553, 555, 569, 571, 2420, 4480, 4619, 5775, 5777, 6000]
        for length in invalid:
            with self.subTest(length=length):
                self.assertEqual(CHECKER.expected_mode(length), CHECKER.MODE_INVALID)

    def test_deterministic_bytes_are_stable_and_prefix_consistent(self) -> None:
        first = CHECKER.deterministic_bytes(b"label", 100)
        second = CHECKER.deterministic_bytes(b"label", 100)
        prefix = CHECKER.deterministic_bytes(b"label", 32)
        self.assertEqual(first, second)
        self.assertEqual(first[:32], prefix)
        self.assertNotEqual(first, CHECKER.deterministic_bytes(b"other", 100))


if __name__ == "__main__":
    unittest.main()
