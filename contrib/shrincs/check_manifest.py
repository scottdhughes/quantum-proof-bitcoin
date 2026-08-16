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
    "research_cpp": (
        "BlockstreamResearch/shrincs-cpp",
        "7643d9530c568f8671b21b9502e51bd9722b2e8d",
    ),
    "simplicity_verifier": (
        "BlockstreamResearch/shrincs-simplicity-verifier",
        "d13165d3d21bac73e8794eede21f0f1527f3b837",
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


class ManifestError(ValueError):
    """Raised when the candidate manifest violates a frozen safety invariant."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    _require(isinstance(data, dict), "manifest root must be an object")
    return data


def validate_manifest(data: dict[str, Any]) -> None:
    _require(data.get("schema_version") == 1, "schema_version must remain 1")
    _require(data.get("candidate_id") == "pqbtc-shrincs-v0", "candidate_id drifted")
    _require(data.get("status") == "RESEARCH_CANDIDATE", "candidate status must remain RESEARCH_CANDIDATE")
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
        _require(bool(SHA1_RE.fullmatch(str(item.get("commit", "")))), f"upstream.{name}.commit is not a 40-byte hex SHA")

    observed = data.get("observed_profiles")
    _require(isinstance(observed, dict), "observed_profiles must be an object")

    draft = observed.get("draft_specification")
    _require(isinstance(draft, dict), "draft_specification profile missing")
    _require(draft.get("public_key_bytes") == 48, "draft public-key size drifted")
    _require(draft.get("stateful_signature_bytes") == {"minimum": 554, "maximum": 4618}, "draft stateful signature range drifted")
    _require(draft.get("stateless_signature_bytes") == 5776, "draft stateless signature size drifted")
    _require(draft.get("stateful_verify_sha256_compressions") == {"minimum": 255, "maximum": 509}, "draft stateful verifier cost drifted")
    _require(draft.get("stateless_verify_sha256_compressions") == {"minimum": 462, "maximum": 2637}, "draft stateless verifier cost drifted")
    _require(draft.get("security_proof_complete") is False, "security proof may not be marked complete without a separate reviewed update")
    _require(draft.get("normative_status") == "DRAFT", "draft normative status drifted")

    explorer = observed.get("parameter_explorer")
    _require(isinstance(explorer, dict), "parameter_explorer profile missing")
    _require(explorer.get("stateless_tuple_h_d_k_a_w") == [45, 5, 10, 13, 16], "pinned stateless tuple drifted")
    _require(explorer.get("stateless_signature_bytes") == 5776, "parameter explorer stateless size drifted")
    _require(explorer.get("stateful_ots") == "WOTS+C", "stateful OTS family drifted")
    _require(explorer.get("stateful_winternitz_w") == 64, "stateful Winternitz parameter drifted")
    _require(explorer.get("stateful_families") == ["BXMSS", "UXMSS"], "stateful family set drifted")
    _require(explorer.get("normative_status") == "RESEARCH_TOOL", "parameter explorer must remain non-normative")

    historical = observed.get("historical_paper_profile")
    _require(isinstance(historical, dict), "historical profile missing")
    _require(historical.get("compact_signature_bytes_headline") == 324, "historical 324-byte record drifted")
    _require(historical.get("selected_for_pqbtc") is False, "historical 324-byte profile must not be selected")
    _require(historical.get("status") == "HISTORICAL_ONLY", "historical profile status drifted")

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
        _require(value is False, f"gate {name} cannot be marked complete in the foundation tranche")


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
        "state_controls": len(data["wallet_state_contract"]),
        "result": "PASS",
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "SHRINCS candidate manifest: PASS "
            f"(pins={result['upstream_pins']}, "
            f"state_controls={result['state_controls']}, "
            "consensus=disabled, backend=NONE, release_hold=true)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
