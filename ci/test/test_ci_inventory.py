"""Check inventory, explicit selections, and Windows functional-gate coverage."""

import contextlib
import copy
import io
import os
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

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


class FunctionalGateSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = runpy.run_path(
            str(check_ci_inventory.FUNCTIONAL_DIR / "test_runner.py")
        )
        cls.gate_names = check_ci_inventory.load_pq_gate_list()
        workflow = yaml.safe_load(
            (check_ci_inventory.REPO_ROOT / ".github/workflows/promotion-matrix.yml")
            .read_text(encoding="utf8")
        )
        cls.windows_steps = []
        for job_name in ("windows-native-dll", "windows-native-test"):
            steps = [
                step for step in workflow["jobs"][job_name]["steps"]
                if step.get("name") == "Run functional tests"
            ]
            assert len(steps) == 1, f"{job_name} must retain its functional step"
            cls.windows_steps.append((job_name, steps[0]))

    def run_windows_loader(self, step, gate_content, *, override=None):
        """Execute the actual loader/guard, replacing only the daemon invocation."""
        invocation = "py -3 test/functional/test_runner.py"
        self.assertEqual(step["run"].count(invocation), 1)
        script = step["run"].split(invocation, 1)[0]
        script += "\nprintf '%s\\0' $PQBTC_FUNCTIONAL_TESTS\n"
        environment = {"PATH": os.defpath, "LC_ALL": "C"}
        if override is not None:
            environment["PQBTC_FUNCTIONAL_TESTS"] = override
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "The Windows functional workflow requires Bash")
        with tempfile.TemporaryDirectory(prefix="pqbtc-windows-gate-") as directory:
            root = Path(directory)
            gate = root / "ci/test/pq_functional_tests.txt"
            gate.parent.mkdir(parents=True)
            gate.write_bytes(gate_content)
            working_directory = root / step.get("working-directory", ".")
            working_directory.mkdir(exist_ok=True)
            result = subprocess.run(
                [bash, "-eu", "-o", "pipefail", "-c", script],
                cwd=working_directory, env=environment, capture_output=True,
            )
        arguments = [part.decode("utf8") for part in result.stdout.split(b"\0") if part]
        return result, arguments

    def test_lf_and_crlf_windows_loaders_select_the_complete_gate(self):
        expected_variants = [
            script for script in self.runner["ALL_SCRIPTS"]
            if script.split()[0] in self.gate_names
        ]
        for job, step in self.windows_steps:
            for newline in ("\n", "\r\n"):
                with self.subTest(job=job, newline=repr(newline)):
                    content = (newline.join(self.gate_names) + newline).encode("utf8")
                    result, arguments = self.run_windows_loader(step, content)
                    self.assertEqual(result.returncode, 0, result.stderr.decode("utf8"))
                    self.assertEqual(arguments, self.gate_names)
                    selected = self.runner["select_explicit_tests"](
                        arguments, fail_on_warn=True
                    )
                    self.assertCountEqual(selected, expected_variants)

    def test_windows_loaders_reject_empty_or_whitespace_gate_files(self):
        for job, step in self.windows_steps:
            for content in (b"", b" \n\t\r\n"):
                with self.subTest(job=job, content=content):
                    result, arguments = self.run_windows_loader(step, content)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(arguments, [])

    def test_windows_loader_overrides_keep_existing_semantics(self):
        content = "\n".join(self.gate_names).encode("utf8")
        for job, step in self.windows_steps:
            with self.subTest(job=job, override="explicit"):
                result, arguments = self.run_windows_loader(
                    step, content, override="wallet_v3_txs.py"
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(arguments, ["wallet_v3_txs.py"])
            with self.subTest(job=job, override="empty"):
                result, arguments = self.run_windows_loader(step, content, override="")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(arguments, self.gate_names)
            with self.subTest(job=job, override="whitespace"):
                result, arguments = self.run_windows_loader(step, content, override=" \t\n")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(arguments, [])

    def test_ci_rejects_mixed_valid_and_unknown_or_cr_tainted_requests(self):
        for unknown in ("feature_not_a_test.py", "feature_assumeutxo.py\r"):
            with (
                self.subTest(unknown=repr(unknown)),
                contextlib.redirect_stdout(io.StringIO()) as output,
                self.assertRaises(SystemExit) as failure,
            ):
                self.runner["select_explicit_tests"](
                    ["wallet_v3_txs.py", unknown], fail_on_warn=True
                )
            self.assertEqual(failure.exception.code, 1)
            self.assertIn("not found in full test list", output.getvalue())

    def test_manual_selection_retains_warning_and_valid_tests(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            selected = self.runner["select_explicit_tests"](
                ["feature_not_a_test.py", "wallet_v3_txs.py"], fail_on_warn=False
            )
        self.assertEqual(selected, ["wallet_v3_txs.py"])
        self.assertIn("not found in full test list", output.getvalue())

    def test_explicit_selection_preserves_paths_suffixes_and_variants(self):
        expected = [
            "wallet_txn_doublespend.py", "wallet_txn_doublespend.py --mineblock"
        ]
        for request in (
            "wallet_txn_doublespend", "test/functional/wallet_txn_doublespend.py"
        ):
            with self.subTest(request=request):
                selected = self.runner["select_explicit_tests"](
                    [request], fail_on_warn=True
                )
                self.assertCountEqual(selected, expected)
        self.assertEqual(
            self.runner["select_explicit_tests"](
                [expected[1]], fail_on_warn=True
            ),
            [expected[1]],
        )


if __name__ == "__main__":
    unittest.main()
