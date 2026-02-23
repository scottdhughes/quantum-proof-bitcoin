# Policy Limits for PQBTC v1

## Status: FROZEN
## Spec-ID: POLICY-LIMITS-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: NO

## Policy Objectives
- Relay and mine valid PQ transactions safely under higher witness sizes.
- Keep DoS resistance explicit and measurable.

## v1 Policy Baselines
- Default mining max weight tracks consensus max weight.
- Standard witness stack item bounds must permit 4480-byte PQ signatures.
- Standard templates are restricted to P2WSH (+NULL_DATA carrier) for v1 relay/mining policy.
- `MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 10000`.
- `MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 10000` (taproot disabled in v1 but limit remains explicit).

## Change Control
Policy parameter changes require test updates and a changelog entry in this file.
