import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CI_TEST_DIR = Path(__file__).resolve().parent
REPORT_PATH = CI_TEST_DIR / "report_ci_runtime.py"
FUZZ_SHARD_PATH = CI_TEST_DIR / "fuzz_shard.py"
BUDGET_PATH = CI_TEST_DIR / "ci_runtime_budget.json"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


report_ci_runtime = load_module(REPORT_PATH, "report_ci_runtime")
fuzz_shard = load_module(FUZZ_SHARD_PATH, "fuzz_shard")


class ReportRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.run_json = {
            "jobs": [
                {
                    "name": "job-a",
                    "startedAt": "2026-03-28T12:10:00Z",
                    "completedAt": "2026-03-28T12:25:00Z",
                },
                {
                    "name": "job-b",
                    "startedAt": "2026-03-28T12:12:00Z",
                    "completedAt": "2026-03-28T12:40:00Z",
                },
            ]
        }

    def test_wall_clock_uses_earliest_start_and_latest_finish(self):
        minutes = report_ci_runtime.compute_wall_clock_minutes(self.run_json)
        self.assertEqual(minutes, 30.0)

    def test_cli_accepts_saved_json_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_path = Path(tmpdir) / "run.json"
            run_path.write_text(json.dumps(self.run_json), encoding="utf8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPORT_PATH),
                    "--workflow",
                    "CI",
                    "--budget",
                    str(BUDGET_PATH),
                    "--input",
                    str(run_path),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("status=PASS", result.stdout)

    def test_cli_accepts_stdin(self):
        result = subprocess.run(
            [
                sys.executable,
                str(REPORT_PATH),
                "--workflow",
                "Gatekeeper",
                "--budget",
                str(BUDGET_PATH),
            ],
            input=json.dumps(self.run_json),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("status=FAIL", result.stdout)


class FuzzShardTests(unittest.TestCase):
    def test_shard_assignment_is_deterministic(self):
        targets = ["zeta", "alpha", "gamma", "beta", "delta"]
        shard0 = fuzz_shard.shard_targets(targets, shard_index=0, shard_count=2)
        shard1 = fuzz_shard.shard_targets(targets, shard_index=1, shard_count=2)
        self.assertEqual(shard0, ["alpha", "delta", "zeta"])
        self.assertEqual(shard1, ["beta", "gamma"])

    def test_shard_union_matches_full_target_set(self):
        targets = ["delta", "alpha", "gamma", "beta", "zeta", "eta"]
        shard_count = 2
        shards = [fuzz_shard.shard_targets(targets, shard_index=i, shard_count=shard_count) for i in range(shard_count)]
        flattened = [target for shard in shards for target in shard]
        self.assertEqual(sorted(flattened), sorted(targets))
        self.assertEqual(len(flattened), len(set(flattened)))


if __name__ == "__main__":
    unittest.main()
