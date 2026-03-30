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


LATEST_FIXTURE_BUNDLE = REPO_ROOT / "docs" / "artifacts" / "ops-slo" / "2026-03-30"
HISTORICAL_FIXTURE_BUNDLE = REPO_ROOT / "docs" / "artifacts" / "ops-slo" / "2026-03-23"


class ValidateOpsSLOEvidenceTest(unittest.TestCase):
    def copy_fixture_bundle(self, source_bundle: Path) -> Path:
        tmpdir = Path(tempfile.mkdtemp(prefix="ops-slo-bundle-"))
        bundle_root = tmpdir / source_bundle.name
        shutil.copytree(source_bundle, bundle_root)
        return bundle_root

    def test_latest_fixture_bundle_passes_signoff(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        target.validate_bundle(bundle_root, signoff=True)

    def test_historical_fixture_bundle_passes_generic_validation(self) -> None:
        bundle_root = self.copy_fixture_bundle(HISTORICAL_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        target.validate_bundle(bundle_root)

    def test_missing_summary_file_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        (bundle_root / "mempool-pq-stress-summary.json").unlink()

        with self.assertRaisesRegex(target.ValidationError, "mempool-pq-stress-summary.json: missing file"):
            target.validate_bundle(bundle_root)

    def test_malformed_json_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        (bundle_root / "feature-pq-reorg-summary.json").write_text("{bad json\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "feature-pq-reorg-summary.json: malformed JSON"):
            target.validate_bundle(bundle_root)

    def test_wrong_scenario_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "mempool-pq-limits-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["scenario"] = "wrong_scenario"
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "mempool-pq-limits-summary.json: unexpected scenario"):
            target.validate_bundle(bundle_root)

    def test_missing_base_required_field_fails(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "mempool-pq-stress-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        del summary["notes"]
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "missing fields: notes"):
            target.validate_bundle(bundle_root)

    def test_missing_stress_threshold_field_fails_in_signoff_mode(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "mempool-pq-stress-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        del summary["saturation_target"]
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "mempool_pq_stress: signoff requires field saturation_target"):
            target.validate_bundle(bundle_root, signoff=True)

    def test_wrong_stress_threshold_value_fails_in_signoff_mode(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "mempool-pq-stress-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["rbf_replacements"] = 4
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "mempool_pq_stress: signoff requires rbf_replacements == 5"):
            target.validate_bundle(bundle_root, signoff=True)

    def test_wrong_reorg_threshold_value_fails_in_signoff_mode(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
        self.addCleanup(shutil.rmtree, bundle_root.parent)
        summary_path = bundle_root / "feature-pq-reorg-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["competing_branch_blocks"] = 3
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

        with self.assertRaisesRegex(target.ValidationError, "feature_pq_reorg: signoff requires competing_branch_blocks == 2"):
            target.validate_bundle(bundle_root, signoff=True)

    def test_non_signoff_soak_result_fails_in_signoff_mode(self) -> None:
        bundle_root = self.copy_fixture_bundle(LATEST_FIXTURE_BUNDLE)
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
