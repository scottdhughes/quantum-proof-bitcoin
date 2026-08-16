"""Regression tests for the consensus-disabled SHRINCS candidate contract."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "contrib" / "shrincs" / "check_manifest.py"
MANIFEST_PATH = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"

SPEC = importlib.util.spec_from_file_location("shrincs_check_manifest", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ShrincsCandidateManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
            cls.manifest = json.load(handle)

    def assert_invalid(self, data: dict, expected: str) -> None:
        with self.assertRaisesRegex(CHECKER.ManifestError, expected):
            CHECKER.validate_manifest(data)

    def test_committed_manifest_is_valid(self) -> None:
        CHECKER.validate_manifest(copy.deepcopy(self.manifest))

    def test_consensus_activation_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["consensus_enabled"] = True
        self.assert_invalid(data, "consensus must remain disabled")

    def test_algorithm_allocation_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["consensus_contract"]["algorithm_id"] = 2
        self.assert_invalid(data, "algorithm_id must remain unset")

    def test_release_hold_removal_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["release_hold"] = False
        self.assert_invalid(data, "release hold must remain enabled")

    def test_upstream_pin_drift_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["upstream"]["draft_specification"]["commit"] = "0" * 40
        self.assert_invalid(data, "draft_specification.commit drifted")

    def test_incompatible_oracle_cannot_be_silently_promoted(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["upstream"]["research_cpp"]["compatibility_with_pinned_draft"] = "COMPATIBLE"
        self.assert_invalid(data, "research_cpp.compatibility_with_pinned_draft drifted")

    def test_signature_profile_drift_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["observed_profiles"]["draft_specification"]["stateless_signature_bytes"] = 5775
        self.assert_invalid(data, "stateless signature size drifted")

    def test_historical_profile_cannot_be_selected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["observed_profiles"]["historical_paper_profile"]["selected_for_pqbtc"] = True
        self.assert_invalid(data, "historical 324-byte profile must not be selected")

    def test_state_safety_control_cannot_be_disabled(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["wallet_state_contract"]["reserve_before_sign"] = False
        self.assert_invalid(data, "reserve_before_sign must remain enabled")

    def test_gate_cannot_be_closed_in_foundation_tranche(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["required_gates"]["exact_profile_frozen"] = True
        self.assert_invalid(data, "exact_profile_frozen cannot be marked complete")


if __name__ == "__main__":
    unittest.main()
