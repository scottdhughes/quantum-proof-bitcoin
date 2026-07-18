import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT_PATH = REPO_ROOT / "contrib" / "pqsig-ref" / "audit_rc2_conformance.py"


class PQSigReleaseHoldTests(unittest.TestCase):
    def run_audit(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(AUDIT_PATH), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_conformance_mode_fails_closed(self):
        result = self.run_audit()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("release_status=HOLD", result.stdout)

    def test_checked_in_release_hold_evidence_reproduces(self):
        result = self.run_audit("--expect-release-hold")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WOTS+C fixed-sum encoding: NONCONFORMANT", result.stdout)
        self.assertIn("PORS+FP distinct-index enforcement: NONCONFORMANT", result.stdout)


if __name__ == "__main__":
    unittest.main()
