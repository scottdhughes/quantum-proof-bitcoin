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

EXPECTED_UPSTREAM = {
    "parameter_model": (
        "BlockstreamResearch/SPHINCS-Parameters",
        "d64a217595597d5fe165ba6d236af83e6737da31",
    ),
    "draft_specification": (
        "SHRINCS/shrincs-bip",
        "acc6bda51dc3b94848d118967247ad0f3cd7a80e",
    ),
    "libshrincs_wotsc": (
        "remix7531/libshrincs",
        "53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5",
    ),
    "research_cpp": (
        "BlockstreamResearch/shrincs-cpp",
        "7643d9530c568f8671b21b9502e51bd9722b2e8d",
    ),
    "simplicity_verifier": (
        "BlockstreamResearch/shrincs-simplicity-verifier",
        "d13165d3d21bac73e8794eede21f0f1527f3b837",
    ),
}

EXPECTED_COMPATIBILITY = {
    "parameter_model": "PARAMETER_ONLY",
    "draft_specification": "AUTHORITATIVE_DRAFT",
    "libshrincs_wotsc": "COMPATIBLE_COMPONENT",
    "research_cpp": "INCOMPATIBLE",
    "simplicity_verifier": "INCOMPATIBLE",
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


def validate_manifest(data: dict[str, Any]) -> None:
    _require(data.get("schema_version") == 1, "schema_version must remain 1")
    _require(data.get("candidate_id") == "pqbtc-shrincs-v0", "candidate_id drifted")
    _require(
        data.get("status") == "RESEARCH_CANDIDATE",
        "candidate status must remain RESEARCH_CANDIDATE",
    )
    _require(data.get("consensus_enabled") is False, "SHRINCS consensus must remain disabled")
    _require(data.get("production_backend") == "NONE", "production backend must remain NONE")
    _require(data.get("release_hold") is True, "production release hold must remain enabled")

    upstream = data.get("upstream")
    _require(isinstance(upstream, dict), "upstream must be an object")
    _require(set(upstream) == set(EXPECTED_UPSTREAM), "upstream artifact set drifted")
    for name, (repository, commit) in EXPECTED_UPSTREAM.items():
        item = upstream.get(name)
        _require(isinstance(item, dict), f"upstream.{name} must be an object")
        _require(item.get("repository") == repository, f"upstream.{name}.repository drifted")
        _require(item.get("commit") == commit, f"upstream.{name}.commit drifted")
        _require(
            bool(SHA1_RE.fullmatch(str(item.get("commit", "")))),
            f"upstream.{name}.commit is not a 40-byte hex SHA",
        )
        _require(
            item.get("compatibility_with_pinned_draft") == EXPECTED_COMPATIBILITY[name],
            f"upstream.{name}.compatibility_with_pinned_draft drifted",
        )
        if EXPECTED_COMPATIBILITY[name] == "INCOMPATIBLE":
            _require_string_list(
                item.get("compatibility_reasons"),
                f"upstream.{name}.compatibility_reasons must retain concrete evidence",
            )
        elif EXPECTED_COMPATIBILITY[name] == "COMPATIBLE_COMPONENT":
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
            kat_source = str(item.get("kat_source_commit", ""))
            _require(
                bool(SHA1_RE.fullmatch(kat_source)),
                f"upstream.{name}.kat_source_commit is invalid",
            )
            _require(
                kat_source == "4795244c4208f5de69dc386f6e6a451b7aa0c4e2",
                f"upstream.{name}.kat_source_commit drifted",
            )

    components = data.get("component_evidence")
    _require(
        isinstance(components, dict)
        and set(components) == {"wotsc", "stateful_fxmss", "stateless_hypertree"},
        "component_evidence set drifted",
    )

    wotsc = components.get("wotsc")
    _require(isinstance(wotsc, dict), "component_evidence.wotsc must be an object")
    expected_wotsc = {
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
    _require(wotsc == expected_wotsc, "component_evidence.wotsc drifted")

    stateful_fxmss = components.get("stateful_fxmss")
    _require(
        isinstance(stateful_fxmss, dict),
        "component_evidence.stateful_fxmss must be an object",
    )
    expected_stateful_fxmss = {
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
        "vectors_committed": False,
        "vectors_retained_as_ci_artifact": True,
    }
    _require(
        stateful_fxmss == expected_stateful_fxmss,
        "component_evidence.stateful_fxmss drifted",
    )

    stateless_hypertree = components.get("stateless_hypertree")
    _require(
        isinstance(stateless_hypertree, dict),
        "component_evidence.stateless_hypertree must be an object",
    )
    expected_stateless_hypertree = {
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
        "vectors_committed": False,
        "vectors_retained_as_ci_artifact": True,
    }
    _require(
        stateless_hypertree == expected_stateless_hypertree,
        "component_evidence.stateless_hypertree drifted",
    )

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
    _require(
        draft.get("stateful_verify_sha256_compressions") == {"minimum": 255, "maximum": 509},
        "draft stateful verifier cost drifted",
    )
    _require(
        draft.get("stateless_verify_sha256_compressions") == {"minimum": 462, "maximum": 2637},
        "draft stateless verifier cost drifted",
    )
    _require(
        draft.get("security_proof_complete") is False,
        "security proof may not be marked complete without a separate reviewed update",
    )
    _require(draft.get("normative_status") == "DRAFT", "draft normative status drifted")

    explorer = observed.get("parameter_explorer")
    _require(isinstance(explorer, dict), "parameter_explorer profile missing")
    _require(
        explorer.get("stateless_tuple_h_d_k_a_w") == [45, 5, 10, 13, 16],
        "pinned stateless tuple drifted",
    )
    _require(
        explorer.get("stateless_signature_bytes") == 5776,
        "parameter explorer stateless size drifted",
    )
    _require(explorer.get("stateful_ots") == "WOTS+C", "stateful OTS family drifted")
    _require(
        explorer.get("stateful_winternitz_w") == 64,
        "stateful Winternitz parameter drifted",
    )
    _require(
        explorer.get("stateful_families") == ["BXMSS", "UXMSS"],
        "stateful family set drifted",
    )
    _require(
        explorer.get("normative_status") == "RESEARCH_TOOL",
        "parameter explorer must remain non-normative",
    )

    historical = observed.get("historical_paper_profile")
    _require(isinstance(historical, dict), "historical profile missing")
    _require(
        historical.get("compact_signature_bytes_headline") == 324,
        "historical 324-byte record drifted",
    )
    _require(
        historical.get("selected_for_pqbtc") is False,
        "historical 324-byte profile must not be selected",
    )
    _require(
        historical.get("status") == "HISTORICAL_ONLY",
        "historical profile status drifted",
    )

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
    for field in (
        "accepted_public_key_sizes",
        "accepted_signature_sizes",
        "sighash_modes",
    ):
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
            f"gate {name} cannot be marked complete in the stateless verifier tranche",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Path to a SHRINCS candidate manifest",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable success record",
    )
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
            f"independent_stateful_prototypes={result['independent_stateful_prototypes']}, "
            f"independent_stateless_prototypes={result['independent_stateless_prototypes']}, "
            f"incompatible_oracles={result['incompatible_oracles']}, "
            f"state_controls={result['state_controls']}, "
            "consensus=disabled, backend=NONE, release_hold=true)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
