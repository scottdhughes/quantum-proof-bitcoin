#!/usr/bin/env python3
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
"""Native integration check; full suite execution belongs in contained Linux."""

import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "contrib/ml-dsa-integration/run_native_tests.py"


class NativeIntegrationTests(unittest.TestCase):
    def test_all_network_binding_joins_reject_tampered_data(self):
        spec = importlib.util.spec_from_file_location("native_network_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        model = runner.load(ROOT / "contrib/ml-dsa-production-contract/protocol_v1.py", "network_test_model")
        artifact = json.loads((ROOT / "contrib/genesis/generated_constants.json").read_text())
        pk = bytes(1312)
        program = model.key_commitment("regtest", pk)
        script = (b"\x52\x20" + program).hex()
        tx = {"version": 2, "inputs": [{"prev_txid": "01" * 32, "prev_index": 0,
              "sequence": 4294967294, "amount": 100000, "script_pubkey": script}],
              "outputs": [{"amount": 99000, "script_pubkey": script}], "lock_time": 0}
        native = {"networks": {entry["name"]: {
            "binding": (bytes(entry["message_start"]) + bytes.fromhex(entry["genesis_hash"])[::-1]).hex(),
            "program": model.key_commitment(entry["name"], pk).hex(),
            "message": model.signing_message(entry["name"], tx, 0).hex()} for entry in artifact["networks"]}}
        runner.validate_networks(native, model, pk, tx, artifact)
        for network in ("main", "test", "regtest"):
            for field in ("binding", "program", "message"):
                changed = json.loads(json.dumps(native))
                original = changed["networks"][network][field]
                changed["networks"][network][field] = ("01" if original[:2] == "00" else "00") + original[2:]
                with self.subTest(network=network, field=field), self.assertRaises(RuntimeError):
                    runner.validate_networks(changed, model, pk, tx, artifact)

    def test_inherited_sanitizer_log_redirection_is_overridden(self):
        spec = importlib.util.spec_from_file_location("native_environment_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        previous = os.environ.get("ASAN_OPTIONS")
        try:
            os.environ["ASAN_OPTIONS"] = "log_path=/tmp/not-a-proof:detect_leaks=0"
            observed = runner.run([sys.executable, "-c", "import os; print(os.getenv('ASAN_OPTIONS'))"])
            self.assertEqual(observed.strip(), "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0")
        finally:
            if previous is None:
                os.environ.pop("ASAN_OPTIONS", None)
            else:
                os.environ["ASAN_OPTIONS"] = previous

    def test_success_exit_with_diagnostic_is_not_a_pass(self):
        spec = importlib.util.spec_from_file_location("native_integration_runner", RUNNER)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with self.assertRaises(RuntimeError):
            runner.run([sys.executable, "-c", "import sys; print('runtime diagnostic', file=sys.stderr)"])

    def test_real_guarded_signer_and_public_transaction_verifier(self):
        for cc, cxx in [("gcc", "g++"), ("clang", "clang++")]:
            for sanitized in (False, True):
                with self.subTest(cc=cc, sanitized=sanitized):
                    command = [sys.executable, str(RUNNER), "--cc", cc, "--cxx", cxx]
                    if sanitized:
                        command.append("--sanitize")
                    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report["result"], "PASS")
                    self.assertEqual(report["verifier_exports"], ["pqbtc_mldsa44_node_verify"])
                    self.assertGreaterEqual(report["negative_checks"], 15)
                    self.assertEqual(report["python_contract_join"], "PASS")
                    self.assertEqual(report.get("network_artifact_join"), "PASS")
                    dependencies = report.get("compiler_dependency_hashes", {})
                    for required in ("contrib/ml-dsa-key-lifecycle/key_runtime.c",
                                     "contrib/ml-dsa-key-lifecycle/key_lifecycle.h",
                                     "contrib/ml-dsa-engineering/vendor/mldsa-native/mldsa/mldsa_native.h"):
                        self.assertIn(required, dependencies)
                    self.assertEqual(report["node_linked"], False)


if __name__ == "__main__":
    unittest.main()
