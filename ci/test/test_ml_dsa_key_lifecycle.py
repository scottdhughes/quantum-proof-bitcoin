#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit.

import importlib.util
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
        for name in ("pqbtc_mldsa44.c", "pqbtc_mldsa44.h", "pqbtc_mldsa44_config.h", "pqbtc_mldsa44_test.h"):
            shutil.copyfile(ROOT / WRAPPER / name, dest / name)
        shutil.copytree(ROOT / WRAPPER / "vendor", dest / "vendor")

    def test_frozen_source_preflight_accepts_exact_bytes(self):
        module = self.runner()
        result = module.validate_sources(ROOT)
        self.assertEqual(result["capsule_sha256"], "2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb")

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
            (root / WRAPPER / "vendor/mldsa-native/injected.c").write_text("int injected;\n")
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
        for output in ("", "key lifecycle smoke: PASS (0 checks)\n",
                       "key lifecycle smoke: PASS (61 checks)\nFAIL\n"):
            with self.subTest(output=output), self.assertRaises(module.HarnessError):
                module.smoke_result(output, 61)

    def test_wipe_negative_control_requires_observed_cleanup_failure(self):
        module = self.runner()
        self.assertTrue(hasattr(module, "require_wipe_rejection"), "wipe observation lacks calibration gate")
        for code, error in ((0, ""), (1, "unrelated failure"), (139, "segmentation fault")):
            with self.subTest(code=code), self.assertRaises(module.HarnessError):
                module.require_wipe_rejection(code, error)
        module.require_wipe_rejection(1, "FAIL: pqbtc_mldsa44_key_test_release_zero() == 1")

    def test_alias_controls_require_the_corresponding_boundary_failure(self):
        module = self.runner()
        self.assertTrue(hasattr(module, "require_alias_rejection"), "alias regression controls missing")
        for kind in ("constructor", "allocation-tail"):
            for code, output in ((0, ""), (1, "unrelated failure"), (139, "crash")):
                with self.subTest(kind=kind, code=code), self.assertRaises(module.HarnessError):
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
            module.require_exports(module.EXPECTED_EXPORTS | {"pqbtc_mldsa44_test_set_entropy"})
        with self.assertRaisesRegex(module.HarnessError, "symbol"):
            module.require_exports(module.EXPECTED_EXPORTS | {"pqbtc_mldsa44_sign_hedged"})
        with self.assertRaisesRegex(module.HarnessError, "symbol"):
            module.require_exports(module.EXPECTED_EXPORTS - {"pqbtc_mldsa44_key_destroy"})

    def test_preflight_cli_does_not_build_or_create_artifacts(self):
        self.runner()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "not-created"
            result = subprocess.run([sys.executable, str(RUNNER), "--preflight-only",
                                     "--output-dir", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('"result": "PASS"', result.stdout)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
