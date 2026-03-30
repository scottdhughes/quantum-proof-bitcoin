#!/usr/bin/env python3
"""Validate checked-in or freshly captured PQBTC ops/SLO evidence bundles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


SPEC_ID = "OPS-SLO-v1"
CAPTURE_SCRIPT = "contrib/soak/capture_ops_slo_evidence.sh"
REQUIRED_ARTIFACTS = [
    "README.md",
    "mempool-pq-limits-summary.json",
    "mempool-pq-stress-summary.json",
    "feature-pq-reorg-summary.json",
    "pq-mempool-soak-summary.json",
    "pq-mempool-soak-results.tsv",
]
SUMMARY_REQUIRED_FIELDS = [
    "scenario",
    "pass",
    "duration_s",
    "mempool_before_restart",
    "mempool_after_restart",
    "reorg_result",
    "crash_assert_hang",
    "notes",
]
SOAK_REQUIRED_FIELDS = SUMMARY_REQUIRED_FIELDS + [
    "runs",
    "passed",
    "failed",
    "jobs",
    "test",
    "results_tsv",
]
SUMMARY_SCENARIOS = {
    "mempool-pq-limits-summary.json": "mempool_pq_limits",
    "mempool-pq-stress-summary.json": "mempool_pq_stress",
    "feature-pq-reorg-summary.json": "feature_pq_reorg",
}
SOAK_SUMMARY = "pq-mempool-soak-summary.json"
SOAK_SCENARIO = "pq_mempool_soak"


class ValidationError(ValueError):
    """Raised when an evidence bundle does not satisfy the frozen contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path.name}: malformed JSON: {exc.msg}") from exc


def _validate_manifest(bundle_root: Path) -> dict[str, object]:
    manifest_path = bundle_root / "manifest.json"
    _require(manifest_path.is_file(), "manifest.json: missing file")
    manifest = _load_json(manifest_path)
    _require(isinstance(manifest, dict), "manifest.json: top-level object required")
    expected_keys = {"spec_id", "stamp", "capture_script", "soak_runs", "artifacts"}
    _require(set(manifest.keys()) == expected_keys, "manifest.json: unexpected schema")
    _require(manifest["spec_id"] == SPEC_ID, "manifest.json: unexpected spec_id")
    _require(manifest["stamp"] == bundle_root.name, "manifest.json: stamp must match bundle directory name")
    _require(manifest["capture_script"] == CAPTURE_SCRIPT, "manifest.json: unexpected capture_script")
    _require(isinstance(manifest["soak_runs"], int), "manifest.json: soak_runs must be an integer")
    _require(isinstance(manifest["artifacts"], list), "manifest.json: artifacts must be a list")
    _require(sorted(manifest["artifacts"]) == sorted(REQUIRED_ARTIFACTS), "manifest.json: artifacts list drifted")
    return manifest


def _validate_readme(bundle_root: Path) -> None:
    readme_path = bundle_root / "README.md"
    _require(readme_path.is_file(), "README.md: missing file")
    readme = readme_path.read_text(encoding="utf-8")
    required_fragments = [
        f"# PQBTC Ops/SLO Evidence ({bundle_root.name})",
        f"- Spec: `{SPEC_ID}`",
        f"- Capture script: `{CAPTURE_SCRIPT}`",
        "- Validator: `contrib/soak/validate_ops_slo_evidence.py --signoff <bundle-root>`",
        f"- Raw logs: `build/ops-slo/{bundle_root.name}`",
        "## Artifacts",
        "## Optional Supplemental Artifacts",
    ]
    for artifact in REQUIRED_ARTIFACTS:
        required_fragments.append(f"- `{artifact}`")
    required_fragments.append("- `soak-summaries/`")
    for fragment in required_fragments:
        _require(fragment in readme, f"README.md: missing required text: {fragment}")


def _validate_summary_fields(path: Path, expected_scenario: str, required_fields: list[str]) -> dict[str, object]:
    summary = _load_json(path)
    _require(isinstance(summary, dict), f"{path.name}: top-level object required")
    missing = [field for field in required_fields if field not in summary]
    _require(not missing, f"{path.name}: missing fields: {', '.join(missing)}")
    _require(summary["scenario"] == expected_scenario, f"{path.name}: unexpected scenario")
    return summary


def validate_bundle(bundle_root: Path, *, signoff: bool = False) -> None:
    bundle_root = bundle_root.resolve()
    _require(bundle_root.is_dir(), f"{bundle_root}: bundle directory not found")

    manifest = _validate_manifest(bundle_root)
    _validate_readme(bundle_root)

    for artifact in REQUIRED_ARTIFACTS:
        _require((bundle_root / artifact).is_file(), f"{artifact}: missing file")

    summaries = []
    for filename, scenario in SUMMARY_SCENARIOS.items():
        summary = _validate_summary_fields(bundle_root / filename, scenario, SUMMARY_REQUIRED_FIELDS)
        summaries.append(summary)

    soak_summary = _validate_summary_fields(bundle_root / SOAK_SUMMARY, SOAK_SCENARIO, SOAK_REQUIRED_FIELDS)
    _require(isinstance(soak_summary["runs"], int), f"{SOAK_SUMMARY}: runs must be an integer")
    _require(isinstance(soak_summary["passed"], int), f"{SOAK_SUMMARY}: passed must be an integer")
    _require(isinstance(soak_summary["failed"], int), f"{SOAK_SUMMARY}: failed must be an integer")
    _require(isinstance(soak_summary["jobs"], int), f"{SOAK_SUMMARY}: jobs must be an integer")
    _require(isinstance(soak_summary["test"], str) and soak_summary["test"], f"{SOAK_SUMMARY}: test must be a non-empty string")
    _require(isinstance(soak_summary["results_tsv"], str) and soak_summary["results_tsv"], f"{SOAK_SUMMARY}: results_tsv must be a non-empty string")
    _require(soak_summary["runs"] == manifest["soak_runs"], f"{SOAK_SUMMARY}: runs must match manifest soak_runs")
    _require(soak_summary["passed"] + soak_summary["failed"] == soak_summary["runs"], f"{SOAK_SUMMARY}: passed + failed must equal runs")
    _require((soak_summary["failed"] == 0) == (soak_summary["pass"] is True), f"{SOAK_SUMMARY}: pass must match failed count")

    if signoff:
        _require(manifest["soak_runs"] == 10, "manifest.json: signoff requires soak_runs == 10")
        for summary in summaries:
            _require(summary["pass"] is True, f"{summary['scenario']}: signoff requires pass=true")
            _require(summary["crash_assert_hang"] is False, f"{summary['scenario']}: signoff requires crash_assert_hang=false")
        _require(soak_summary["pass"] is True, f"{SOAK_SCENARIO}: signoff requires pass=true")
        _require(soak_summary["crash_assert_hang"] is False, f"{SOAK_SCENARIO}: signoff requires crash_assert_hang=false")
        _require(soak_summary["runs"] == 10, f"{SOAK_SCENARIO}: signoff requires runs == 10")
        _require(soak_summary["passed"] == 10, f"{SOAK_SCENARIO}: signoff requires passed == 10")
        _require(soak_summary["failed"] == 0, f"{SOAK_SCENARIO}: signoff requires failed == 0")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_root", help="Path to docs/artifacts/ops-slo/<stamp>")
    parser.add_argument("--signoff", action="store_true", help="Enforce frozen sign-off thresholds")
    args = parser.parse_args()

    try:
        validate_bundle(Path(args.bundle_root), signoff=args.signoff)
    except ValidationError as exc:
        print(f"OPS/SLO validation failed: {exc}")
        return 1

    print(f"OPS/SLO evidence bundle validated: {Path(args.bundle_root).resolve()}")
    if args.signoff:
        print("Sign-off thresholds satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
