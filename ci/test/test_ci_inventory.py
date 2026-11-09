"""Check that opt-in experimental coverage cannot exempt ordinary PQ tests."""

import contextlib
import copy
import io
import runpy
import shlex
import unittest
from unittest import mock

from ci.test import check_ci_inventory


class CIInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = runpy.run_path(
            str(check_ci_inventory.FUNCTIONAL_DIR / "test_runner.py")
        )

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

    def test_standalone_driver_is_acknowledged_outside_default_gate(self):
        name = "feature_mldsa44_demo.py"
        self.assertEqual(self.runner["STANDALONE_SCRIPTS"], [name])
        framework_tests = {script.split()[0] for script in self.runner["ALL_SCRIPTS"]}
        self.assertNotIn(name, framework_tests)
        self.assertNotIn(name, check_ci_inventory.load_pq_gate_list())
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.runner["check_script_list"](
                src_dir=str(check_ci_inventory.REPO_ROOT), fail_on_warn=True
            )
        self.assertEqual(output.getvalue(), "")

    def test_runner_still_rejects_an_unacknowledged_script_in_ci(self):
        names = [path.name for path in check_ci_inventory.FUNCTIONAL_DIR.iterdir()]
        names.append("feature_unacknowledged.py")
        with (
            mock.patch("os.listdir", return_value=names),
            contextlib.redirect_stdout(io.StringIO()) as output,
            self.assertRaises(SystemExit) as failure,
        ):
            self.runner["check_script_list"](
                src_dir=str(check_ci_inventory.REPO_ROOT), fail_on_warn=True
            )
        self.assertEqual(failure.exception.code, 1)
        self.assertIn("feature_unacknowledged.py", output.getvalue())

    def test_standalone_driver_keeps_its_direct_assembled_ci_call(self):
        builder = (
            check_ci_inventory.REPO_ROOT
            / "contrib/ml-dsa-console/container/build_native.sh"
        ).read_text(encoding="utf8")
        commands = [
            shlex.split(line)
            for line in builder.replace("\\\n", "").splitlines()
            if line.startswith("runuser ")
        ]
        expected = [
            "runuser", "-u", "node", "--", "python3",
            "$source_dir/test/functional/feature_mldsa44_demo.py",
            "--binary", "$build_dir/bin/pqbtcd", "--validation-only",
            "--timeout-factor", "4",
        ]
        self.assertTrue(any(command[:len(expected)] == expected for command in commands))
        self.assertTrue(any("-DENABLE_EXPERIMENTAL_MLDSA44=ON" in command for command in commands))
        workflow = (
            check_ci_inventory.REPO_ROOT
            / check_ci_inventory.REQUIRED_EXPERIMENTAL_COVERAGE[
                "feature_mldsa44_demo.py"
            ]["workflow"]
        ).read_text(encoding="utf8")
        self.assertIn("compiler: [gcc, clang]", workflow)
        self.assertIn("python3 contrib/ml-dsa-console/run_assembled_ci.py", workflow)


if __name__ == "__main__":
    unittest.main()
