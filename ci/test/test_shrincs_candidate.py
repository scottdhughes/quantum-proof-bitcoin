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

    def test_libshrincs_pin_drift_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["upstream"]["libshrincs_wotsc"]["commit"] = "0" * 40
        self.assert_invalid(data, "libshrincs_wotsc.commit drifted")

    def test_incompatible_oracle_cannot_be_silently_promoted(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["upstream"]["research_cpp"]["compatibility_with_pinned_draft"] = "COMPATIBLE"
        self.assert_invalid(data, "research_cpp.compatibility_with_pinned_draft drifted")

    def test_component_cannot_be_silently_promoted_to_full_verifier(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["wotsc"]["qualifies_as_full_shrincs_verifier"] = True
        self.assert_invalid(data, "component_evidence.wotsc drifted")

    def test_component_proof_reproduction_cannot_be_claimed(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["wotsc"]["formal_proofs_reproduced_by_pqbtc"] = True
        self.assert_invalid(data, "component_evidence.wotsc drifted")

    def test_stateful_prototype_cannot_be_promoted_to_full_verifier(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateful_fxmss"]["qualifies_as_full_shrincs_verifier"] = True
        self.assert_invalid(data, "component_evidence.stateful_fxmss drifted")

    def test_stateful_prototype_cannot_be_marked_consensus_ready(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateful_fxmss"]["consensus_ready"] = True
        self.assert_invalid(data, "component_evidence.stateful_fxmss drifted")

    def test_stateful_mutation_count_drift_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateful_fxmss"]["signature_bit_mutations_rejected"] -= 1
        self.assert_invalid(data, "component_evidence.stateful_fxmss drifted")

    def test_stateful_vectors_cannot_be_uncommitted(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateful_fxmss"]["vectors_committed"] = False
        self.assert_invalid(data, "component_evidence.stateful_fxmss drifted")

    def test_stateless_prototype_cannot_be_promoted_to_full_verifier(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateless_hypertree"]["qualifies_as_full_shrincs_verifier"] = True
        self.assert_invalid(data, "component_evidence.stateless_hypertree drifted")

    def test_stateless_prototype_cannot_be_marked_consensus_ready(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateless_hypertree"]["consensus_ready"] = True
        self.assert_invalid(data, "component_evidence.stateless_hypertree drifted")

    def test_stateless_mutation_count_drift_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateless_hypertree"]["signature_bit_mutations_rejected"] -= 1
        self.assert_invalid(data, "component_evidence.stateless_hypertree drifted")

    def test_stateless_vectors_cannot_be_uncommitted(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["stateless_hypertree"]["vectors_committed"] = False
        self.assert_invalid(data, "component_evidence.stateless_hypertree drifted")

    def test_full_profile_cannot_be_marked_consensus_ready(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["full_profile"]["consensus_ready"] = True
        self.assert_invalid(data, "component_evidence.full_profile drifted")

    def test_full_profile_cannot_be_marked_production_ready(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["full_profile"]["production_backend_ready"] = True
        self.assert_invalid(data, "component_evidence.full_profile drifted")

    def test_full_profile_cannot_claim_independently_generated_kats(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["full_profile"]["committed_kats_independently_generated"] = True
        self.assert_invalid(data, "component_evidence.full_profile drifted")

    def test_full_profile_invalid_lengths_must_remain_zero_work(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["full_profile"]["invalid_signature_lengths_zero_hash_work"] = False
        self.assert_invalid(data, "component_evidence.full_profile drifted")

    def test_full_profile_artifact_digest_drift_is_rejected(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["component_evidence"]["full_profile"]["artifact_sha256"] = "0" * 64
        self.assert_invalid(data, "component_evidence.full_profile drifted")

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

    def test_full_differential_gate_cannot_be_closed(self) -> None:
        data = copy.deepcopy(self.manifest)
        data["required_gates"]["differential_verifiers"] = True
        self.assert_invalid(data, "differential_verifiers cannot be marked complete")


if __name__ == "__main__":
    unittest.main()
