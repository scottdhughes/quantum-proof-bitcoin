"""Acceptance checks for the fresh assembled-system runner (no native host code)."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "contrib/ml-dsa-console/run_assembled_ci.py"


class AssembledCITests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), "assembled runner is not implemented")
        spec = importlib.util.spec_from_file_location("assembled_ci", SCRIPT)
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)
        self.state = {"phase": "running", "ready": True,
                      "wallet": {"wallet_id": "ab" * 16, "spendable_sats": 1998000,
                                 "next_receive": 3, "next_change": 2},
                      "nodes": [{"tip": "cd" * 32, "utxo_hash": "ef" * 32, "height": 104},
                                {"tip": "cd" * 32, "utxo_hash": "ef" * 32, "height": 104}]}

    def test_namespace_cannot_target_user_wallet_or_legacy_container(self):
        for name in ("pqbtc-mldsa-local", "pqbtc-mldsa-demo-20261109", "../pqbtc-ci-test", "pqbtc-ci-"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.runner.validate_namespace(name)
        self.assertEqual(self.runner.validate_namespace("pqbtc-ci-gcc-fresh-123"), "pqbtc-ci-gcc-fresh-123-data-v1")

    def test_workflow_job_environment_uses_supported_github_contexts(self):
        text = (ROOT / ".github/workflows/ml-dsa-44-assembled-system.yml").read_text()
        block = re.search(r"^    env:\n((?:^      .*\n)+)", text, re.MULTILINE)
        self.assertIsNotNone(block, "Expected assembled job environment")
        contexts = set(re.findall(r"\$\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\.", block[1]))
        allowed = {"github", "needs", "strategy", "matrix", "vars", "secrets", "inputs"}
        self.assertLessEqual(contexts, allowed, "Job-level env cannot use runner or step-only contexts")

    def test_checkout_guard_accepts_exact_clean_source_and_refuses_untracked_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
            (repo / "source.txt").write_text("public source fixture\n")
            subprocess.run(["git", "-C", str(repo), "add", "source.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                            "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                            "commit", "--quiet", "-m", "public fixture"], check=True)
            identity = self.runner.checkout_identity(repo)
            self.assertEqual(identity, self.runner.checkout_identity(repo, identity["head"]))
            (repo / "local-binary").write_bytes(b"not a build input")
            with self.assertRaisesRegex(ValueError, "clean checkout"):
                self.runner.checkout_identity(repo)

    def test_freshness_guard_rejects_existing_container_or_volume_before_mutation(self):
        for existing in ("container", "volume"):
            seen = []
            def docker(command, **_kwargs):
                seen.append(command)
                is_volume = command[1:3] == ["volume", "inspect"]
                return subprocess.CompletedProcess(command, int((existing == "volume") != is_volume), b"{}", b"")
            with self.subTest(existing=existing), patch.object(subprocess, "run", side_effect=docker):
                with self.assertRaisesRegex(ValueError, "already exists"):
                    self.runner.require_fresh_namespace("pqbtc-ci-fresh-123")
            self.assertTrue(all("inspect" in command for command in seen))

    def test_state_agreement_requires_wallet_balance_and_full_utxo_identity(self):
        baseline = copy.deepcopy(self.state)
        self.runner.require_state(self.state, baseline)
        cases = [lambda s: s["wallet"].update(wallet_id="00" * 16),
                 lambda s: s["wallet"].update(spendable_sats=1997999),
                 lambda s: s["wallet"].update(next_receive=2),
                 lambda s: s["nodes"][1].update(utxo_hash="00" * 32),
                 lambda s: s["nodes"][0].update(tip="00" * 32),
                 lambda s: s.update(ready=False)]
        for mutate in cases:
            candidate = copy.deepcopy(self.state)
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                self.runner.require_state(candidate, baseline)

    def test_descriptor_must_match_actual_checkout_and_selected_compiler(self):
        value = {"schema": "PQBTC-MLDSA44-SOURCE-RUNTIME-1", "image": "sha256:" + "12" * 32,
                 "manifest_sha256": "34" * 32,
                 "manifest": {"source_head": "56" * 20, "compiler": "gcc",
                              "checks": {"native_integration": "PASS", "signer": "PASS", "mldsa44_node_tests": "PASS"}}}
        self.runner.require_descriptor_source(value, "56" * 20, "gcc")
        for head, compiler in (("78" * 20, "gcc"), ("56" * 20, "clang")):
            with self.subTest(head=head, compiler=compiler), self.assertRaises(ValueError):
                self.runner.require_descriptor_source(value, head, compiler)
        value["manifest"]["checks"]["signer"] = "NOT_RUN"
        with self.assertRaisesRegex(ValueError, "native"):
            self.runner.require_descriptor_source(value, "56" * 20, "gcc")

    def test_native_evidence_archive_requires_exact_hashed_regular_files(self):
        payload = b"public evidence\n"
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as handle:
            info = tarfile.TarInfo("./signer.json")
            info.size = len(payload)
            handle.addfile(info, io.BytesIO(payload))
        manifest = {"evidence_sha256": {"signer.json": hashlib.sha256(payload).hexdigest()}}
        self.runner.validate_native_evidence(archive.getvalue(), manifest)
        manifest["evidence_sha256"]["signer.json"] = "00" * 32
        with self.assertRaises(ValueError):
            self.runner.validate_native_evidence(archive.getvalue(), manifest)

    def test_cleanup_failure_cannot_be_written_as_passing_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            report = {"result": "FAIL"}
            with self.assertRaisesRegex(ValueError, "cleanup"):
                self.runner.finish_report(Path(temp), report, [], candidate_pass=True,
                                          cleanup=lambda: (_ for _ in ()).throw(ValueError("cleanup failed")))
            saved = json.loads((Path(temp) / "report.json").read_text())
            self.assertEqual(saved["result"], "FAIL")
            self.assertIn("cleanup failed", saved["cleanup_error"])

    def test_failed_run_preserves_runtime_instead_of_deleting_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            cleanup = []
            report = {"result": "FAIL", "error": "real flow failed"}
            self.runner.finish_report(Path(temp), report, [], candidate_pass=False,
                                      cleanup=lambda: cleanup.append("deleted"))
            self.assertEqual(cleanup, [])
            self.assertEqual(json.loads((Path(temp) / "report.json").read_text())["result"], "FAIL")

    def test_optimized_python_refuses_before_any_docker_command(self):
        result = subprocess.run([sys.executable, "-O", str(SCRIPT), "--help"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Optimized Python is not permitted", result.stderr)


if __name__ == "__main__":
    unittest.main()
