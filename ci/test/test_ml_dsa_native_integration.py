#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Native integration check; full suite execution belongs in contained Linux."""

import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "contrib/ml-dsa-integration/run_native_tests.py"


class NativeIntegrationTests(unittest.TestCase):
    def test_success_exit_with_diagnostic_is_not_a_pass(self):
        spec = importlib.util.spec_from_file_location("native_integration_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with self.assertRaises(RuntimeError):
            runner.run([sys.executable, "-c", "import sys; print('runtime diagnostic', file=sys.stderr)"])

    def test_real_guarded_signer_and_public_transaction_verifier(self):
        result = subprocess.run([sys.executable, str(RUNNER), "--cc", "gcc", "--cxx", "g++"],
                                cwd=ROOT, capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["verifier_exports"], ["pqbtc_mldsa44_node_verify"])
        self.assertGreaterEqual(report["negative_checks"], 15)
        self.assertEqual(report["python_contract_join"], "PASS")
        self.assertEqual(report["node_linked"], False)


if __name__ == "__main__":
    unittest.main()
