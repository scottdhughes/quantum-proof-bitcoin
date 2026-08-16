"""Validate the consensus-disabled PQBTC SHRINCS candidate manifest."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPO_ROOT / "contrib" / "shrincs" / "manifest.json"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_UPSTREAM = {
    "parameter_model": (
        "BlockstreamResearch/SPHINCS-Parameters",
        "d64a217595597d5fe165ba6d236af83e6737da31",
        "PARAMETER_ONLY",
    ),
    "draft_specification": (
        "SHRINCS/shrincs-bip",
        "acc6bda51dc3b94848d118967247ad0f3cd7a80e",
        "AUTHORITATIVE_DRAFT",
    ),
    "libshrincs_wotsc": (
        "remix7531/libshrincs",
        "53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5",
        "COMPATIBLE_COMPONENT",
    ),
    "research_cpp": (
        "BlockstreamResearch/shrincs-cpp",
        "7643d9530c568f8671b21b9502e51bd9722b2e8d",
        "INCOMPATIBLE",
    ),
    "simplicity_verifier": (
        "BlockstreamResearch/shrincs-simplicity-verifier",
        "d13165d3d21bac73e8794eede21f0f1527f3b837",
        "INCOMPATIBLE",
    ),
}

REQUIRED_STATE_CONTROLS = (
    "reserve_before_sign",
    "burn_on_attempt",
    "no_state_rollback_after_reorg_or_rejection",
    "rbf_requires_fresh_state",
    "reject_uncoordinated_cloned_signers",
    "static_backup_restore_uses_recovery_path",
    "self_verify_before_release",
    "state_corruption_fails_closed",
)

EXPECTED_WOTSC = {
    "compiled_c_matches_committed_kats": True,
    "current_draft_matches_committed_kats": True,
    "formal_proofs_reproduced_by_pqbtc": False,
    "kat_case_count": 8,
    "qualifies_as_full_shrincs_verifier": False,
    "scope": "stateful WOTS+C leaf only",
    "status": "COMPATIBLE_COMPONENT_ORACLE",
    "wots_public_key_bytes": 16,
    "wots_signature_bytes": 514,
}

EXPECTED_STATEFUL = {
    "balanced_and_unbalanced_vectors": True,
    "consensus_ready": False,
    "independent_c_verifier": True,
    "kat_case_count": 7,
    "public_key_bit_mutations_rejected": 2688,
    "qualifies_as_full_shrincs_verifier": False,
    "scope": "complete current-draft stateful verification path only",
    "signature_bit_mutations_rejected": 32688,
    "status": "INDEPENDENT_DIFFERENTIAL_PROTOTYPE",
    "structural_negatives_rejected": 42,
    "uses_qualified_libshrincs_wotsc": True,
    "valid_signatures_verified": 7,
    "vectors_committed": True,
    "vectors_retained_as_ci_artifact": True,
}

EXPECTED_STATELESS = {
    "consensus_ready": False,
    "deterministic_and_fixed_randomizer_vectors": True,
    "independent_c_verifier": True,
    "kat_case_count": 2,
    "public_key_bit_mutations_rejected": 384,
    "qualifies_as_full_shrincs_verifier": False,
    "scope": "complete current-draft stateless recovery verification path only",
    "signature_bit_mutations_rejected": 46304,
    "status": "INDEPENDENT_DIFFERENTIAL_PROTOTYPE",
    "structural_negatives_rejected": 12,
    "uses_pinned_libshrincs_sha256": True,
    "valid_signatures_verified": 2,
    "vectors_committed": True,
    "vectors_retained_as_ci_artifact": True,
}

EXPECTED_FULL_PROFILE = {
    "artifact_bytes": 39752,
    "artifact_id": 9270280450,
    "artifact_sha256": "1e72d00da47decf374424a6460856b25d97ce9a435d3b68e35e6d35a55277722",
    "canonical_early_rejections": 62,
    "canonical_hashed_rejections": 194,
    "canonical_random_rejections": 256,
    "canonical_stateful_lengths": 255,
    "canonical_stateless_lengths": 1,
    "committed_kat_vectors": 9,
    "committed_kats_independently_generated": False,
    "committed_kats_regenerate_byte_for_byte": True,
    "consensus_ready": False,
    "independent_c_verifier": True,
    "invalid_public_key_lengths_tested": 64,
    "invalid_signature_lengths_tested": 5745,
    "invalid_signature_lengths_zero_hash_work": True,
    "mode_and_binding_cases_rejected": 10,
    "no_cross_algorithm_fallback": True,
    "production_backend_ready": False,
    "public_key_bytes": 48,
    "sanitizer_replay_passed": True,
    "scope": "strict combined current-draft verifier envelope",
    "sha256_work": {
        "stateful_calls_maximum": 248,
        "stateful_calls_minimum": 245,
        "stateful_compressions_maximum": 505,
        "stateful_compressions_minimum": 498,
        "stateless_calls_maximum": 1558,
        "stateless_calls_minimum": 1528,
        "stateless_compressions_maximum": 3164,
        "stateless_compressions_minimum": 3103,
    },
    "signature_lengths_tested": 6001,
    "stateful_kat_json_sha256": "059549af4c74f6bd1898fc93add185ec0bffe08063b00cbff5b1eb4080ebc041",
    "stateless_kat_json_sha256": "67356b917284198f5a89bfbe727391dcde5e0f06c9f6799b0edd31197968eaae",
    "status": "STRICT_FULL_PROFILE_PROTOTYPE",
    "valid_signatures_verified": 9,
    "vectors_committed": True,
}


class ManifestError(ValueError):
    """Raised when the candidate manifest violates a frozen safety invariant."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def _require_string_list(value: object, message: str, minimum: int = 2) -> None:
    _require(
        isinstance(value, list)
        and len(value) >= minimum
        and all(isinstance(item, str) and item for item in value),
        message,
    )


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    _require(isinstance(data, dict), "manifest root must be an object")
    return data


def validate_upstream(data: dict[str, Any]) -> None:
    upstream = data.get("upstream")
    _require(isinstance(upstream, dict), "upstream must be an object")
    _require(set(upstream) == set(EXPECTED_UPSTREAM), "upstream artifact set drifted")

    for name, (repository, commit, compatibility) in EXPECTED_UPSTREAM.items():
        item = upstream.get(name)
        _require(isinstance(item, dict), f"upstream.{name} must be an object")
        _require(item.get("repository") == repository, f"upstream.{name}.repository drifted")
        _require(item.get("commit") == commit, f"upstream.{name}.commit drifted")
        _require(
            bool(SHA1_RE.fullmatch(str(item.get("commit", "")))),
            f"upstream.{name}.commit is not a 40-byte hex SHA",
        )
        _require(
            item.get("compatibility_with_pinned_draft") == compatibility,
            f"upstream.{name}.compatibility_with_pinned_draft drifted",
        )
        if compatibility == "INCOMPATIBLE":
            _require_string_list(
                item.get("compatibility_reasons"),
                f"upstream.{name}.compatibility_reasons must retain concrete evidence",
            )
        elif compatibility == "COMPATIBLE_COMPONENT":
            _require_string_list(
                item.get("compatible_scope"),
                f"upstream.{name}.compatible_scope must remain explicit",
                minimum=3,
            )
            _require_string_list(
                item.get("limitations"),
                f"upstream.{name}.limitations must remain explicit",
                minimum=3,
            )
            _require(
                item.get("kat_source_commit")
                == "4795244c4208f5de69dc386f6e6a451b7aa0c4e2",
                f"upstream.{name}.kat_source_commit drifted",
            )


def validate_components(data: dict[str, Any]) -> None:
    components = data.get("component_evidence")
    _require(isinstance(components, dict), "component_evidence must be an object")
    _require(
        set(components) == {"wotsc", "stateful_fxmss", "stateless_hypertree", "full_profile"},
        "component_evidence set drifted",
    )
    _require(components.get("wotsc") == EXPECTED_WOTSC, "component_evidence.wotsc drifted")
    _require(
        components.get("stateful_fxmss") == EXPECTED_STATEFUL,
        "component_evidence.stateful_fxmss drifted",
    )
    _require(
        components.get("stateless_hypertree") == EXPECTED_STATELESS,
        "component_evidence.stateless_hypertree drifted",
    )
    _require(
        components.get("full_profile") == EXPECTED_FULL_PROFILE,
        "component_evidence.full_profile drifted",
    )
    _require(
        bool(SHA256_RE.fullmatch(EXPECTED_FULL_PROFILE["artifact_sha256"])),
        "full-profile artifact digest is malformed",
    )


def validate_observed_profiles(data: dict[str, Any]) -> None:
    observed = data.get("observed_profiles")
    _require(isinstance(observed, dict), "observed_profiles must be an object")

    draft = observed.get("draft_specification")
    _require(isinstance(draft, dict), "draft_specification profile missing")
    _require(draft.get("public_key_bytes") == 48, "draft public-key size drifted")
    _require(
        draft.get("stateful_signature_bytes") == {"minimum": 554, "maximum": 4618},
        "draft stateful signature range drifted",
    )
    _require(draft.get("stateless_signature_bytes") == 5776, "draft stateless signature size drifted")
    _require(draft.get("security_proof_complete") is False, "security proof cannot be marked complete")
    _require(draft.get("normative_status") == "DRAFT", "draft normative status drifted")

    explorer = observed.get("parameter_explorer")
    _require(isinstance(explorer, dict), "parameter_explorer profile missing")
    _require(
        explorer.get("stateless_tuple_h_d_k_a_w") == [45, 5, 10, 13, 16],
        "pinned stateless tuple drifted",
    )
    _require(explorer.get("stateful_ots") == "WOTS+C", "stateful OTS family drifted")
    _require(explorer.get("stateful_winternitz_w") == 64, "stateful Winternitz parameter drifted")

    historical = observed.get("historical_paper_profile")
    _require(isinstance(historical, dict), "historical profile missing")
    _require(
        historical.get("selected_for_pqbtc") is False,
        "historical 324-byte profile must not be selected",
    )
    _require(historical.get("status") == "HISTORICAL_ONLY", "historical profile status drifted")


def validate_consensus_and_state(data: dict[str, Any]) -> None:
    consensus = data.get("consensus_contract")
    _require(isinstance(consensus, dict), "consensus_contract must be an object")
    _require(consensus.get("enabled") is False, "consensus contract must remain disabled")
    for field in (
        "algorithm_id",
        "opcode",
        "witness_version",
        "tapscript_leaf_version",
        "domain_separation",
    ):
        _require(consensus.get(field) is None, f"consensus_contract.{field} must remain unset")
    for field in ("accepted_public_key_sizes", "accepted_signature_sizes", "sighash_modes"):
        _require(consensus.get(field) == [], f"consensus_contract.{field} must remain empty")

    state = data.get("wallet_state_contract")
    _require(isinstance(state, dict), "wallet_state_contract must be an object")
    _require(set(state) == set(REQUIRED_STATE_CONTROLS), "wallet state-control set drifted")
    for control in REQUIRED_STATE_CONTROLS:
        _require(state.get(control) is True, f"wallet state control {control} must remain enabled")

    gates = data.get("required_gates")
    _require(isinstance(gates, dict) and gates, "required_gates must be a non-empty object")
    for name, value in gates.items():
        _require(
            value is False,
            f"gate {name} cannot be marked complete in the full-profile tranche",
        )


def validate_manifest(data: dict[str, Any]) -> None:
    _require(data.get("schema_version") == 1, "schema_version must remain 1")
    _require(data.get("candidate_id") == "pqbtc-shrincs-v0", "candidate_id drifted")
    _require(data.get("status") == "RESEARCH_CANDIDATE", "candidate status must remain RESEARCH_CANDIDATE")
    _require(data.get("consensus_enabled") is False, "SHRINCS consensus must remain disabled")
    _require(data.get("production_backend") == "NONE", "production backend must remain NONE")
    _require(data.get("release_hold") is True, "production release hold must remain enabled")
    validate_upstream(data)
    validate_components(data)
    validate_observed_profiles(data)
    validate_consensus_and_state(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    data = load_manifest(args.manifest)
    validate_manifest(data)
    result = {
        "candidate_id": data["candidate_id"],
        "status": data["status"],
        "consensus_enabled": data["consensus_enabled"],
        "production_backend": data["production_backend"],
        "release_hold": data["release_hold"],
        "upstream_pins": len(data["upstream"]),
        "compatible_components": sum(
            item["compatibility_with_pinned_draft"] == "COMPATIBLE_COMPONENT"
            for item in data["upstream"].values()
        ),
        "independent_stateful_prototypes": int(
            data["component_evidence"]["stateful_fxmss"]["status"]
            == "INDEPENDENT_DIFFERENTIAL_PROTOTYPE"
        ),
        "independent_stateless_prototypes": int(
            data["component_evidence"]["stateless_hypertree"]["status"]
            == "INDEPENDENT_DIFFERENTIAL_PROTOTYPE"
        ),
        "strict_full_profile_prototypes": int(
            data["component_evidence"]["full_profile"]["status"]
            == "STRICT_FULL_PROFILE_PROTOTYPE"
        ),
        "incompatible_oracles": sum(
            item["compatibility_with_pinned_draft"] == "INCOMPATIBLE"
            for item in data["upstream"].values()
        ),
        "state_controls": len(data["wallet_state_contract"]),
        "result": "PASS",
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "SHRINCS candidate manifest: PASS "
            f"(pins={result['upstream_pins']}, "
            f"compatible_components={result['compatible_components']}, "
            f"strict_full_profiles={result['strict_full_profile_prototypes']}, "
            f"state_controls={result['state_controls']}, "
            "consensus=disabled, backend=NONE, release_hold=true)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
