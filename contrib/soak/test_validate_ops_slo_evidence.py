from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(SCRIPT_DIR))

import validate_ops_slo_evidence as target  # noqa: E402


FIXTURE_BUNDLE = REPO_ROOT / "docs" / "artifacts" / "ops-slo" / "2026-03-23"


class ValidateOpsSLOEvidenceTest(unittest.TestCase):
    def copy_fixture_bundle(self) -> Path:
        tmpdir = Path(tempfile.mkdtemp(prefix="ops-slo-bundle-"))
        bundle_root = tmpdir / FIXTURE_BUNDLE.name
        shutil.copytree(FIXTURE_BUNDLE, bundle_root)
        return bundle_root

    def test_fixture_bundle_passes_signoff(self) -> None:
        bundle_root = self.copy_fixture_bundle()
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        target.validate_bundle(bundle_root, signoff=True)

    def test_missing_summary_file_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle()
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        (bundle_root / "mempool-pq-stress-summary.json").unlink()

        with self.assertRaisesRegex(target.ValidationError, "mempool-pq-stress-summary.json: missing file"):
            target.validate_bundle(bundle_root)

    def test_malformed_json_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle()
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        (bundle_root / "feature-pq-reorg-summary.json").write_text("{bad json\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "feature-pq-reorg-summary.json: malformed JSON"):
            target.validate_bundle(bundle_root)

    def test_wrong_scenario_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle()
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "mempool-pq-limits-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["scenario"] = "wrong_scenario"
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "mempool-pq-limits-summary.json: unexpected scenario"):
            target.validate_bundle(bundle_root)

    def test_missing_required_field_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle()
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "mempool-pq-stress-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        del summary["notes"]
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "missing fields: notes"):
            target.validate_bundle(bundle_root)

    def test_non_signoff_soak_result_fails_in_signoff_mode(self) -> None:
        bundle_root = self.copy_fixture_bundle()
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "pq-mempool-soak-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["passed"] = 9
        summary["failed"] = 1
        summary["pass"] = False
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "pq_mempool_soak: signoff requires"):
            target.validate_bundle(bundle_root, signoff=True)


if __name__ == "__main__":
    unittest.main()
