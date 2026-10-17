"""Regression checks for registration of the mined SHRINCS functional gate."""

import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "shrincs_functional_runner", REPO_ROOT / "test" / "functional" / "test_runner.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ShrincsLabnetCITests(unittest.TestCase):
    def test_copied_functional_test_loads_model_from_configured_source(self):
        # Windows CMake copies/hard-links scripts into the build tree, so
        # resolving __file__ does not lead back to the source checkout.
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "build" / "test" / "functional" / "feature_shrincs_regtest.py"
            copied.parent.mkdir(parents=True)
            shutil.copy2(REPO_ROOT / "test" / "functional" / copied.name, copied)
            spec = importlib.util.spec_from_file_location("copied_shrincs_functional", copied)
            assert spec is not None and spec.loader is not None
            functional = importlib.util.module_from_spec(spec)
            sys.path.insert(0, str(REPO_ROOT / "test" / "functional"))
            try:
                spec.loader.exec_module(functional)
                try:
                    model = functional.load_transaction_model({"environment": {"SRCDIR": str(REPO_ROOT)}})
                except FileNotFoundError as error:
                    self.fail(f"copied test looked outside the configured source tree: {error}")
                self.assertEqual(
                    Path(model.__file__).resolve(),
                    REPO_ROOT / "contrib" / "shrincs-tx" / "tx_model.py",
                )
                self.assertEqual(len(model.output_commitment(bytes(48))), 32)
            finally:
                sys.path.pop(0)

    def test_required_gate_is_registered_with_the_real_runner(self):
        required = (REPO_ROOT / "ci" / "test" / "pq_functional_tests.txt").read_text().splitlines()
        self.assertIn("feature_shrincs_regtest.py", required)
        self.assertEqual(runner.BASE_SCRIPTS.count("feature_shrincs_regtest.py"), 1)
        runner.check_script_list(src_dir=str(REPO_ROOT), fail_on_warn=True)
