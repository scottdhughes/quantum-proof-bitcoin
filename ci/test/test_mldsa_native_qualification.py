"""Fail-closed native qualification gates; no prototype executes on the host."""
import importlib.util
import copy
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "contrib/ml-dsa-qualification/run_native_qualification.py"


class NativeQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = None
        if RUNNER.is_file():
            spec = importlib.util.spec_from_file_location("native_qualification", RUNNER)
            cls.runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.runner)

    def require_runner(self):
        self.assertIsNotNone(self.runner, "Current-source native qualification runner is missing")
        return self.runner

    def runtime(self):
        return {"image": "sha256:" + "ab" * 32, "ro": True, "network": "none",
                "memory": 4 * 1024**3, "cpus": 4_000_000_000, "pids": 512,
                "drop": ["ALL"], "security": ["no-new-privileges"], "mounts": [],
                "tmpfs": {"/tmp": "rw,exec,nosuid,nodev,size=3221225472"}}

    def test_current_source_image_is_accepted_without_a_historical_allowlist(self):
        runner = self.require_runner()
        value = self.runtime()
        runner.validate_runtime(value, value["image"])

    def test_wrong_image_writable_root_network_and_host_mounts_are_refused(self):
        runner = self.require_runner()
        baseline = self.runtime()
        for key, value in (("image", "sha256:" + "cd" * 32), ("ro", False),
                           ("network", "bridge"), ("mounts", [{"Type": "bind", "RW": False}]),
                           ("cpus", 0), ("memory", 0), ("pids", 0)):
            with self.subTest(key=key):
                runtime = {**baseline, key: value}
                with self.assertRaises(ValueError):
                    runner.validate_runtime(runtime, baseline["image"])

    def test_native_architecture_requires_all_three_observations_to_match(self):
        runner = self.require_runner()
        self.assertEqual(runner.validate_native_identity("arm64", "aarch64", "arm64", "aarch64"), "aarch64")
        self.assertEqual(runner.validate_native_identity("x86_64", "amd64", "x86_64", "amd64"), "x86_64")
        for values in (("x86_64", "x86_64", "aarch64", "x86_64"),
                       ("aarch64", "x86_64", "x86_64", "x86_64"),
                       ("x86_64", "x86_64", "x86_64", "aarch64")):
            with self.assertRaisesRegex(ValueError, "native architecture"):
                runner.validate_native_identity(*values)

    def resource_report(self):
        return {"result": "PASS", "timing_class": "release", "release_timing_pass": True,
                "qualification_scope": "RELEASE_RESOURCE_CONFIGURATION",
                "samples": [{"wall_ns": 100_000_000 + index, "block_weight": 4_000_000,
                             "native_verifications": 128, "block_hash": f"{index + 1:064x}",
                             "wire_sha256": f"{index + 31:064x}", "transaction_input_counts": [127, 1],
                             "after": {"peak_rss_bytes": 90_000_000}} for index in range(30)],
                "pressure": {"evicted": 1, "retained": 6000, "initial_mempoolminfee": 0.00001,
                             "mempool": {"usage": 31_999_000, "maxmempool": 32_000_000,
                                         "mempoolminfee": 0.000017}},
                "p95_wall_ns": 100_000_028,
                "node_peak_rss_bytes": 100_000_000}

    def test_partial_instrumented_or_missing_pressure_is_not_release_qualification(self):
        runner = self.require_runner()
        runner.validate_resource_report(self.resource_report())
        mutations = (("result", "DEVELOPMENT_ONLY"), ("timing_class", "instrumented"),
                     ("release_timing_pass", False), ("samples", [{}] * 29),
                     ("pressure", None), ("p95_wall_ns", 2_000_000_001),
                     ("node_peak_rss_bytes", 1_073_741_825))
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_resource_report({**self.resource_report(), key: value})

    def test_replayed_blocks_false_quantiles_and_understated_peak_are_refused(self):
        runner = self.require_runner()
        value = self.resource_report()
        cases = []
        for field in ("block_hash", "wire_sha256"):
            duplicate = copy.deepcopy(value)
            duplicate["samples"][-1][field] = duplicate["samples"][0][field]
            cases.append(duplicate)
        cases.append({**value, "p95_wall_ns": 1})
        cases.append({**value, "node_peak_rss_bytes": 80_000_000})
        incorrect_inputs = copy.deepcopy(value)
        incorrect_inputs["samples"][0]["transaction_input_counts"] = [126, 1]
        cases.append(incorrect_inputs)
        for index, invalid in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                runner.validate_resource_report(invalid)

    def test_rpc_decimal_serialization_keeps_numeric_fee_floor_order(self):
        runner = self.require_runner()
        value = self.resource_report()
        value["pressure"]["mempool"]["mempoolminfee"] = "0.00001700"
        value["pressure"]["initial_mempoolminfee"] = "0.00001000"
        runner.validate_resource_report(value)
        value["pressure"]["mempool"]["mempoolminfee"] = "NaN"
        with self.assertRaises(ValueError):
            runner.validate_resource_report(value)

    def test_dependency_inventory_cannot_escape_the_readonly_pinned_install(self):
        runner = self.require_runner()
        inventory = {"dependencies/openssl/" + name: "ab" * 32
                     for name in ("bin/openssl", "lib/libcrypto.a", "source-archive.sha256")}
        runner.validate_dependency_inventory(inventory)
        for name in ("dependencies/openssl/../../other", "/dependencies/openssl/lib/libcrypto.a"):
            with self.assertRaises(ValueError):
                runner.validate_dependency_inventory({**inventory, name: "cd" * 32})

    def test_cleanup_failure_is_persisted_as_fail_instead_of_a_success_receipt(self):
        runner = self.require_runner()
        with tempfile.TemporaryDirectory() as temporary:
            report = {"result": "FAIL"}
            def cleanup():
                raise ValueError("owned runtime did not stop")
            with self.assertRaisesRegex(ValueError, "did not stop"):
                runner.finish_report(Path(temporary), report, candidate_pass=True, cleanup=cleanup)
            import json
            saved = json.loads((Path(temporary) / "report.json").read_text())
            self.assertEqual(saved["result"], "FAIL")
            self.assertIn("did not stop", saved["cleanup_error"])


if __name__ == "__main__":
    unittest.main()
