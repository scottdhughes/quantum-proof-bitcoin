"""Check that opt-in experimental coverage cannot exempt ordinary PQ tests."""

import contextlib
import copy
import io
import unittest
from unittest import mock

from ci.test import check_ci_inventory


class CIInventoryTests(unittest.TestCase):
    def experimental_entry(self):
        return {
            "name": "feature_mldsa44_demo.py",
            "policy_class": "experimental_only",
            "owner": "@scottdhughes",
            "notes": "Explicit valueless regtest opt-in with separate assembled CI.",
            "experimental_coverage": copy.deepcopy(
                check_ci_inventory.REQUIRED_EXPERIMENTAL_COVERAGE[
                    "feature_mldsa44_demo.py"
                ]
            ),
        }

    def assert_rejected(self, entry, message):
        with (
            mock.patch.object(
                check_ci_inventory, "load_functional_tests", return_value=[entry["name"]]
            ),
            mock.patch.object(check_ci_inventory, "load_pq_gate_list", return_value=[]),
            mock.patch.object(check_ci_inventory, "load_inventory", return_value=[entry]),
            contextlib.redirect_stderr(io.StringIO()) as errors,
            self.assertRaises(SystemExit),
        ):
            check_ci_inventory.main()
        self.assertIn(message, errors.getvalue())

    def test_current_inventory_preserves_required_pq_gate(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(check_ci_inventory.main(), 0)

    def test_ordinary_test_cannot_claim_experimental_exemption(self):
        entry = self.experimental_entry()
        entry["name"] = "feature_ordinary.py"
        self.assert_rejected(entry, "no approved experimental-only coverage decision")

    def test_experimental_test_cannot_change_default_gate_implicitly(self):
        entry = self.experimental_entry()
        entry["policy_class"] = "pq_required"
        self.assert_rejected(entry, "must use the experimental_only policy_class")

    def test_experimental_coverage_must_match_explicit_decision(self):
        entry = self.experimental_entry()
        entry["experimental_coverage"]["build_option"] = "SOME_OTHER_FLAG=ON"
        self.assert_rejected(entry, "must declare its required experimental CI coverage")

    def test_experimental_scope_requires_a_reason(self):
        entry = self.experimental_entry()
        entry["notes"] = " "
        self.assert_rejected(entry, "must explain its experimental-only scope")

    def test_ordinary_class_cannot_carry_experimental_metadata(self):
        entry = self.experimental_entry()
        entry["name"] = "feature_ordinary.py"
        entry["policy_class"] = "dual_profile"
        self.assert_rejected(entry, "no approved experimental-only coverage decision")


if __name__ == "__main__":
    unittest.main()
