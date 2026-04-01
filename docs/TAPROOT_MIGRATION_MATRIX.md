# Taproot Replacement Migration and Compatibility Matrix

## Status: FROZEN
## Spec-ID: TAPROOT-MIGRATION-MATRIX-v1
## Frozen-By: issue-23-matrix-20260401
## Consensus-Relevant: NO

## Purpose

Freeze the first migration and compatibility matrix for the explicit-replacement
Taproot path.

This document is the canonical future-facing authority for how PQBTC classifies
Taproot-facing migration coverage across the already-frozen dormant and pre-active
states. It does not define active replacement semantics and does not change runtime
behavior.

## Current Inputs

This matrix builds on already-frozen inputs:

1. `TAPROOT_POSTURE.md` freezes future Taproot posture as explicit replacement.
2. `TAPROOT_ACTIVATION.md` freezes BIP9/versionbits as the activation family.
3. The current repo state is `DEPLOYMENT_DEFINED_NOT_SIGNALING` with concrete but
   far-future dormant `taproot_replacement` deployment values.
4. No dormant Taproot-facing surface is approved merely because code or reporting exists.

## Normative Bucket Definitions

- `legacy_only`: inherited Taproot behavior that is not a PQBTC replacement target.
- `replacement_migration`: directly relevant to the frozen PQBTC replacement path.
- `deferred`: Taproot-facing surface exists, but replacement semantics are not yet
  specific enough to test directly.

These bucket meanings are inventory metadata only. They do not change CI gating,
required status contexts, or runtime behavior.

## Compatibility Classes

This matrix freezes three compatibility outcome classes:

- `same-consensus / reporting-only divergence`
- `same-consensus / pre-active deployment divergence`
- `future-active compatibility reserved`

The matrix is directional. Each row is evaluated as `local state -> observed/compared state`.

## Frozen Directed Migration Matrix

| Local state | Observed/compared state | Compatibility class | Allowed interpretation | Coverage expectation |
|---|---|---|---|---|
| `DORMANT_BASELINE` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `same-consensus / reporting-only divergence` | One side exposes a concrete dormant deployment/reporting surface while the other reflects the historical shipped v1 baseline. No approved replacement semantics exist on either side. | Deployment/reporting assertions only. |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `DORMANT_BASELINE` | `same-consensus / reporting-only divergence` | Same consensus posture despite missing deployment reporting on the historical side. No approved replacement semantics exist on either side. | Deployment/reporting assertions only. |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `SIGNALING` | `same-consensus / pre-active deployment divergence` | BIP9 deployment status differs, but runtime semantics remain unchanged and no replacement behavior is active. | Regtest-only deployment-status coverage. |
| `SIGNALING` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `same-consensus / pre-active deployment divergence` | Same as above from the opposite observation direction. | Regtest-only deployment-status coverage. |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `LOCKED_IN_PRE_ACTIVE` | `same-consensus / pre-active deployment divergence` | Lock-in visibility differs, but no replacement semantics are active yet. | Regtest-only deployment-status coverage. |
| `LOCKED_IN_PRE_ACTIVE` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `same-consensus / pre-active deployment divergence` | Same as above from the opposite observation direction. | Regtest-only deployment-status coverage. |
| `DORMANT_BASELINE` | `SIGNALING` | `same-consensus / pre-active deployment divergence` | Historical baseline and regtest signaling may disagree on deployment status only. No approved replacement semantics exist. | Regtest-only deployment-status coverage. |
| `SIGNALING` | `DORMANT_BASELINE` | `same-consensus / pre-active deployment divergence` | Same as above from the opposite observation direction. | Regtest-only deployment-status coverage. |
| `DORMANT_BASELINE` | `LOCKED_IN_PRE_ACTIVE` | `same-consensus / pre-active deployment divergence` | Historical baseline and regtest lock-in may disagree on deployment status only. No approved replacement semantics exist. | Regtest-only deployment-status coverage. |
| `LOCKED_IN_PRE_ACTIVE` | `DORMANT_BASELINE` | `same-consensus / pre-active deployment divergence` | Same as above from the opposite observation direction. | Regtest-only deployment-status coverage. |
| `*` | `ACTIVE_REPLACEMENT` | `future-active compatibility reserved` | Any pairing involving future active replacement is reserved for later implementation work. This document does not define active replacement semantics. | Bucket and inventory now; implementation later. |
| `ACTIVE_REPLACEMENT` | `*` | `future-active compatibility reserved` | Any pairing involving future active replacement is reserved for later implementation work. This document does not define active replacement semantics. | Bucket and inventory now; implementation later. |

## Coverage Guardrails

1. Public-network defaults remain concrete but far-future dormant.
2. `SIGNALING` and `LOCKED_IN_PRE_ACTIVE` are currently exercisable only through
   regtest `-vbparams` override machinery.
3. No wallet, RPC, descriptor, PSBT, address, or witness-v1 behavior becomes
   approved merely because deployment reporting exists.
4. This matrix freezes what is comparable today; it does not speculate about
   active replacement semantics beyond reserving them for later work.

## Implemented Pre-Active Runtime Evidence

The opening slice of `#23` froze this matrix and its suite classification. The
current runtime slice adds evidence for the currently exercisable pre-active rows
without changing the matrix meaning:

1. `feature_taproot_replacement_deployment.py` remains the single-node proof of
   concrete dormant replacement deployment reporting and regtest BIP9 override
   transitions.
2. `feature_taproot_replacement_compat.py` adds cross-node runtime evidence for
   `DEPLOYMENT_DEFINED_NOT_SIGNALING <-> SIGNALING` and
   `DEPLOYMENT_DEFINED_NOT_SIGNALING <-> LOCKED_IN_PRE_ACTIVE` on the same
   accepted chain, with `active = false` on both nodes.
3. Any row involving `ACTIVE_REPLACEMENT` remains explicitly deferred.

## Frozen Suite Classification

| Suite | Current `policy_class` | `taproot_matrix_bucket` | Rationale |
|---|---|---|---|
| `feature_taproot.py` | `legacy_only` | `legacy_only` | Explicit inherited BIP341/BIP342 functional coverage; not a PQBTC replacement target as-is. |
| `wallet_taproot.py` | `legacy_only` | `legacy_only` | Explicit inherited Taproot wallet coverage; not a PQBTC replacement target as-is. |
| `feature_taproot_replacement_deployment.py` | `pq_backlog` | `replacement_migration` | Directly exercises the frozen dormant replacement deployment/reporting path and regtest pre-active BIP9 transitions. |
| `feature_taproot_replacement_compat.py` | `pq_backlog` | `replacement_migration` | Adds cross-node evidence that defined, started, and locked_in pre-active states can diverge in reporting while remaining on the same accepted chain. |
| `rpc_createmultisig.py` | `dual_profile` | `deferred` | Contains Taproot-adjacent bech32m coverage, but replacement-specific semantics are not yet defined. |
| `rpc_psbt.py` | `dual_profile` | `deferred` | Contains Taproot-facing PSBT surfaces, but replacement-specific semantics are not yet defined. |
| `wallet_address_types.py` | `dual_profile` | `deferred` | Contains bech32m/Taproot-facing address branches, but replacement-specific semantics are not yet defined. |
| `wallet_createwalletdescriptor.py` | `pq_backlog` | `deferred` | Contains `tr(...)` descriptor creation paths, but replacement descriptor semantics are not yet defined. |
| `wallet_miniscript.py` | `dual_profile` | `deferred` | Contains Taproot-facing descriptor/miniscript surfaces, but replacement semantics are not yet defined. |
| `wallet_miniscript_decaying_multisig_descriptor_psbt.py` | `dual_profile` | `deferred` | Touches descriptor/PSBT surfaces that may intersect future replacement compatibility, but not yet specifically enough to test. |

## Explicit Non-Goals

This slice does **not** define:

- active replacement witness-v1 semantics
- migration behavior between active replacement and dormant nodes
- CI reclassification of Taproot suites into PQ-required gates
- wallet, RPC, descriptor, PSBT, address, or consensus implementation changes

## Downstream Boundary

The opening slice of `#23` froze the directional matrix and suite classification.
This runtime slice implements the currently exercisable pre-active evidence only.

Remaining `#23` work after this slice is the active-replacement compatibility and
the deferred Taproot-facing migration suites implied by this matrix.
