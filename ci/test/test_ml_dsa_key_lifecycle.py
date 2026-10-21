#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "contrib/ml-dsa-key-lifecycle/run_key_lifecycle_tests.py"
WRAPPER = Path("contrib/ml-dsa-engineering")


class KeyLifecycleRunnerTests(unittest.TestCase):
    def runner(self):
        self.assertTrue(RUNNER.is_file(), "key lifecycle source/symbol gate is missing")
        spec = importlib.util.spec_from_file_location("key_lifecycle_runner", RUNNER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, root):
        dest = root / WRAPPER
        dest.mkdir(parents=True)
        for name in (
            "pqbtc_mldsa44.c",
            "pqbtc_mldsa44.h",
            "pqbtc_mldsa44_config.h",
            "pqbtc_mldsa44_test.h",
        ):
            shutil.copyfile(ROOT / WRAPPER / name, dest / name)
        shutil.copytree(ROOT / WRAPPER / "vendor", dest / "vendor")
        shutil.copytree(
            ROOT / "contrib/ml-dsa-key-lifecycle",
            root / "contrib/ml-dsa-key-lifecycle",
            ignore=shutil.ignore_patterns("__pycache__", "._*"),
        )
        for name in (
            "contrib/ml-dsa-engineering/backend_admission.json",
            "contrib/ml-dsa-ref/review_baseline_commit.txt",
            "contrib/shrincs/manifest.json",
        ):
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_extra_owned_module_source_cannot_escape_inventory(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / "contrib/ml-dsa-key-lifecycle/unreviewed.c").write_text(
                "int unreviewed;\n"
            )
            with self.assertRaisesRegex(module.HarnessError, "module.*inventory"):
                module.validate_sources(root)

    def test_frozen_controls_are_checked_by_key_preflight(self):
        module = self.runner()
        for name in (
            "contrib/ml-dsa-engineering/backend_admission.json",
            "contrib/ml-dsa-ref/review_baseline_commit.txt",
            "contrib/shrincs/manifest.json",
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.fixture(root)
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaisesRegex(module.HarnessError, "control"):
                    module.validate_sources(root)

    def test_frozen_source_preflight_accepts_exact_bytes(self):
        module = self.runner()
        result = module.validate_sources(ROOT)
        self.assertEqual(
            result["capsule_sha256"],
            "e07f0f6a9bb46fd9afcbe7699f95f1ce43e6fcf48623d6de7b3e95ed405023cb",
        )

    def test_wrapper_substitution_rejected_before_native_work(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            source = root / WRAPPER / "pqbtc_mldsa44.c"
            source.write_bytes(source.read_bytes() + b"\n/* substituted */\n")
            with self.assertRaisesRegex(module.HarnessError, "frozen source"):
                module.validate_sources(root)

    def test_extra_capsule_file_rejected(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / WRAPPER / "vendor/mldsa-native/injected.c").write_text(
                "int injected;\n"
            )
            with self.assertRaisesRegex(module.HarnessError, "file set"):
                module.validate_sources(root)

    def test_nested_manifest_name_is_not_hidden_from_file_set(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / WRAPPER / "vendor/mldsa-native/mldsa/SOURCE.json").write_text("{}")
            with self.assertRaisesRegex(module.HarnessError, "file set"):
                module.validate_sources(root)

    def test_modified_manifest_cannot_authorize_substituted_source(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            manifest = root / WRAPPER / "vendor/mldsa-native/SOURCE.json"
            manifest.write_text(manifest.read_text() + "\n")
            with self.assertRaisesRegex(module.HarnessError, "frozen source"):
                module.validate_sources(root)

    def test_removed_capsule_input_rejected(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            (root / WRAPPER / "vendor/mldsa-native/mldsa/mldsa_native.c").unlink()
            with self.assertRaisesRegex(module.HarnessError, "file set"):
                module.validate_sources(root)

    def test_incomplete_or_extra_smoke_output_is_not_pass(self):
        module = self.runner()
        for output in (
            "",
            "key lifecycle smoke: PASS (0 checks)\n",
            "key lifecycle smoke: PASS (61 checks)\nFAIL\n",
        ):
            with self.subTest(output=output), self.assertRaises(module.HarnessError):
                module.smoke_result(output, 61)

    def test_wipe_negative_control_requires_observed_cleanup_failure(self):
        module = self.runner()
        self.assertTrue(
            hasattr(module, "require_wipe_rejection"),
            "wipe observation lacks calibration gate",
        )
        for code, error in (
            (0, ""),
            (1, "unrelated failure"),
            (139, "segmentation fault"),
        ):
            with self.subTest(code=code), self.assertRaises(module.HarnessError):
                module.require_wipe_rejection(code, error)
        try:
            module.require_wipe_rejection(
                1, "FAIL runtime mapping: zero_releases == 1 && nonzero_releases == 0\n"
            )
        except module.HarnessError as error:
            self.fail("actual normal-path wipe control marker rejected: " + str(error))

    def test_alias_controls_require_the_corresponding_boundary_failure(self):
        module = self.runner()
        self.assertTrue(
            hasattr(module, "require_alias_rejection"),
            "alias regression controls missing",
        )
        for kind in ("constructor", "allocation-tail"):
            for code, output in ((0, ""), (1, "unrelated failure"), (139, "crash")):
                with self.subTest(kind=kind, code=code), self.assertRaises(
                    module.HarnessError
                ):
                    module.require_alias_rejection(kind, code, output)

    def test_symlink_input_rejected(self):
        module = self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            source = root / WRAPPER / "pqbtc_mldsa44.c"
            original = root / "outside.c"
            original.write_bytes(source.read_bytes())
            source.unlink()
            source.symlink_to(original)
            with self.assertRaisesRegex(module.HarnessError, "symlink"):
                module.validate_sources(root)

    def test_normal_api_cannot_accept_test_or_raw_key_export(self):
        module = self.runner()
        with self.assertRaisesRegex(module.HarnessError, "symbol"):
            module.require_exports(
                module.EXPECTED_EXPORTS | {"pqbtc_mldsa44_test_set_entropy"}
            )
        with self.assertRaisesRegex(module.HarnessError, "symbol"):
            module.require_exports(
                module.EXPECTED_EXPORTS | {"pqbtc_mldsa44_sign_hedged"}
            )
        with self.assertRaisesRegex(module.HarnessError, "symbol"):
            module.require_exports(
                module.EXPECTED_EXPORTS - {"pqbtc_mldsa44_key_destroy"}
            )

    def test_normal_symbol_gate_requires_the_runtime_initializer(self):
        module = self.runner()
        exports = {
            "pqbtc_mldsa44_key_" + name
            for name in (
                "runtime_init",
                "generate",
                "import_seed",
                "public",
                "export_seed",
                "sign_hedged",
                "verify_strict",
                "destroy",
            )
        }
        with self.assertRaises(module.HarnessError):
            module.require_exports(exports - {"pqbtc_mldsa44_key_runtime_init"})
        try:
            module.require_exports(exports)
        except module.HarnessError as error:
            self.fail("complete runtime-initialized API rejected: " + str(error))

    def test_preflight_cli_does_not_build_or_create_artifacts(self):
        self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "not-created"
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--preflight-only",
                    "--output-dir",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"result": "PASS"', result.stdout)
            self.assertFalse(output.exists())


class KeyRuntimeEvidenceTests(unittest.TestCase):
    def module(self):
        path = ROOT / "contrib/ml-dsa-key-lifecycle/run_key_runtime_tests.py"
        self.assertTrue(path.is_file(), "protected-runtime evidence reader is missing")
        spec = importlib.util.spec_from_file_location("key_runtime_reader", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def mapping(self):
        # Native mapping assertions counted by hand: init/import/inventory,
        # body/start/rounding/extent, locked/dump/fork flags and release checks.
        return {
            "schema": 2,
            "scenario": "mapping",
            "checks": 13,
            "result": "PASS",
            "core_zero": True,
            "dump_zero": True,
            "map_flags": 15,
            "entropy_calls": 0,
            "keypair_entries": 0,
            "signature_entries": 0,
            "randomized_entries": 0,
            "zero_releases": 1,
            "nonzero_releases": 0,
        }

    def test_complete_runtime_observation_accepted(self):
        module = self.module()
        self.assertEqual(
            module.runtime_result(json.dumps(self.mapping())), self.mapping()
        )

    def test_incomplete_or_false_runtime_observation_rejected(self):
        module = self.module()
        for field, value in (
            ("checks", 0),
            ("checks", True),
            ("schema", 1),
            ("core_zero", False),
            ("dump_zero", 1),
            ("map_flags", 7),
            ("nonzero_releases", 1),
            ("zero_releases", 0),
            ("entropy_calls", 1),
            ("scenario", "unreviewed"),
        ):
            data = self.mapping()
            data[field] = value
            with self.subTest(field=field), self.assertRaises(module.HarnessError):
                module.runtime_result(json.dumps(data))
        for field in self.mapping():
            data = self.mapping()
            del data[field]
            with self.subTest(missing=field), self.assertRaises(module.HarnessError):
                module.runtime_result(json.dumps(data))

    def test_extra_or_non_json_runtime_output_is_not_pass(self):
        module = self.module()
        for text in ("", json.dumps(self.mapping()) + "\nFAIL\n", "PASS", "[]"):
            with self.subTest(text=text), self.assertRaises(module.HarnessError):
                module.runtime_result(text)
        data = self.mapping()
        data["unexpected"] = True
        with self.assertRaises(module.HarnessError):
            module.runtime_result(json.dumps(data))

    def test_pure_page_arithmetic_does_not_claim_runtime_initialization(self):
        module = self.module()
        data = {
            "schema": 2,
            "scenario": "page-layout",
            "checks": 8,
            "result": "PASS",
            "core_zero": False,
            "dump_zero": False,
            "map_flags": -1,
            "entropy_calls": 0,
            "keypair_entries": 0,
            "signature_entries": 0,
            "randomized_entries": 0,
            "zero_releases": 0,
            "nonzero_releases": 0,
        }
        try:
            self.assertEqual(module.runtime_result(json.dumps(data)), data)
        except module.HarnessError as error:
            self.fail(
                "pure layout test misrepresented as a runtime-policy test: "
                + str(error)
            )

    def test_controls_require_the_specific_native_assertion(self):
        module = self.module()
        markers = {
            "lock": "FAIL runtime mapping: (flags & 9U) == 9U\n",
            "dontdump": "FAIL runtime mapping: (flags & 2U) == 2U\n",
            "dontfork": (
                "FAIL runtime fork-live: mincore(key, 1, vector) == -1 && errno == ENOMEM\n"
                "FAIL runtime fork-live: WIFEXITED(status) && WEXITSTATUS(status) == 0 && summary.failures == 0\n"
            ),
            "origin": (
                "FAIL runtime fork-live: pqbtc_mldsa44_key_runtime_init() == -13\n"
                "FAIL runtime fork-live: WIFEXITED(status) && WEXITSTATUS(status) == 0 && summary.failures == 0\n"
            ),
            "wipe": "FAIL runtime mapping: zero_releases == 1 && nonzero_releases == 0\n",
        }
        for kind, marker in markers.items():
            module.require_runtime_control(kind, 1, marker)
            for code, error in (
                (0, marker),
                (139, marker),
                (1, "unrelated"),
                (1, "echo '" + marker.strip() + "'\n"),
                (1, marker + "FAIL unrelated native assertion\n"),
                (1, "unrelated\n" + marker),
                (1, marker + marker),
                (1, marker.rstrip("\n")),
                (1, marker.replace("\n", "\r\n")),
            ):
                with self.subTest(kind=kind, code=code), self.assertRaises(
                    module.HarnessError
                ):
                    module.require_runtime_control(kind, code, error)

    def test_fork_controls_require_complete_ordered_diagnostics(self):
        module = self.module()
        parent = (
            "FAIL runtime fork-live: WIFEXITED(status) && WEXITSTATUS(status) == 0 && summary.failures == 0\n"
        )
        for kind, child in (
            ("dontfork", "FAIL runtime fork-live: mincore(key, 1, vector) == -1 && errno == ENOMEM\n"),
            ("origin", "FAIL runtime fork-live: pqbtc_mldsa44_key_runtime_init() == -13\n"),
        ):
            module.require_runtime_control(kind, 1, child + parent)
            for stderr in (child, parent, parent + child, child + parent + parent):
                with self.subTest(kind=kind, stderr=stderr):
                    with self.assertRaises(module.HarnessError):
                        module.require_runtime_control(kind, 1, stderr)

    def test_missing_or_extra_required_scenarios_rejected(self):
        module = self.module()
        with self.assertRaises(module.HarnessError):
            module.require_scenarios({"mapping": self.mapping()})
        with self.assertRaises(module.HarnessError):
            module.require_scenarios({})

    def test_all_normal_sanitized_and_unsupported_profiles_required(self):
        module = self.module()
        self.assertTrue(
            callable(getattr(module, "require_profiles", None)),
            "profile completeness gate is missing",
        )
        for data in ({}, {"profiles": {}}, {"profiles": {"O2": {}}}):
            with self.subTest(data=data), self.assertRaises(module.HarnessError):
                module.require_profiles(data)

    def test_private_runtime_helper_cli_is_not_a_silent_passing_proof(self):
        path = ROOT / "contrib/ml-dsa-key-lifecycle/run_key_runtime_tests.py"
        completed = subprocess.run(
            [sys.executable, str(path)], text=True, capture_output=True
        )
        self.assertEqual(
            completed.returncode,
            2,
            "private helper silently claimed a completed command",
        )
        self.assertIn("run_key_lifecycle_tests.py", completed.stderr)
        self.assertEqual(completed.stdout, "")


if __name__ == "__main__":
    unittest.main()
