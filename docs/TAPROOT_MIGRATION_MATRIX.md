# Taproot Replacement Migration and Compatibility Matrix

## Status: FROZEN
## Spec-ID: TAPROOT-MIGRATION-MATRIX-v1
## Frozen-By: issue-23-matrix-20260401
## Consensus-Relevant: NO

## Purpose

Freeze the first migration and compatibility matrix for the explicit-replacement
Taproot path.

This document is the canonical future-facing authority for how PQBTC classifies
Taproot-facing migration coverage across the already-frozen dormant, pre-active,
and narrowly-owned active states. It now defines exactly one positive
PQ-native active replacement seam, and keeps all remaining active semantics
reserved.

## Current Inputs

This matrix builds on already-frozen inputs:

1. `TAPROOT_POSTURE.md` freezes future Taproot posture as explicit replacement.
2. `TAPROOT_ACTIVATION.md` freezes BIP9/versionbits as the activation family.
3. The current repo state is `DEPLOYMENT_DEFINED_NOT_SIGNALING` with concrete but
   far-future dormant `taproot_replacement` deployment values.
4. No dormant Taproot-facing surface is approved merely because code or reporting exists.
5. Any positive active seam must be written down here before code or tests rely on it.

## Normative Bucket Definitions

- `legacy_only`: inherited Taproot behavior that is not a PQBTC replacement target.
- `replacement_migration`: directly relevant to the frozen PQBTC replacement path.
- `deferred`: Taproot-facing surface exists, but replacement semantics are not yet
  specific enough to test directly.

These bucket meanings are inventory metadata only. They do not change CI gating,
required status contexts, or runtime behavior.

## Compatibility Classes

This matrix freezes four compatibility outcome classes:

- `same-consensus / reporting-only divergence`
- `same-consensus / pre-active deployment divergence`
- `active-semantic divergence / inherited-taproot rejected`
- `active-semantic divergence / pq-native replacement accepted`
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
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `ACTIVE_REPLACEMENT` | `same-consensus / reporting-only divergence` | Versionbits/deployment reporting may diverge while the nodes remain on the same accepted chain, provided only plain blocks are exercised. This is not evidence of replacement witness-v1 semantics. | Plain-block same-chain reporting assertions only. |
| `ACTIVE_REPLACEMENT` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `same-consensus / reporting-only divergence` | Same as above from the opposite observation direction. This is not evidence of replacement witness-v1 semantics. | Plain-block same-chain reporting assertions only. |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `ACTIVE_REPLACEMENT` | `active-semantic divergence / inherited-taproot rejected` | For the inherited witness-v1 Taproot negative-control fixture, the defined node may accept a block that the active node rejects. This is negative-control active evidence only: it proves inherited Taproot semantics are not the replacement path and does not define any positive PQ-native active seam. | Cross-node block-validation negative-control fixture only. |
| `ACTIVE_REPLACEMENT` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `active-semantic divergence / inherited-taproot rejected` | Same as above from the opposite observation direction. The active node rejects inherited Taproot witness-v1 semantics while the defined node still accepts the negative-control fixture. | Cross-node block-validation negative-control fixture only. |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `ACTIVE_REPLACEMENT` | `active-semantic divergence / pq-native replacement accepted` | For the first positive PQ-native seam, the defined node rejects a raw witness-v1 / 32-byte / non-P2SH replacement block that the active node accepts. This seam is block-validation-only: `SHA256(revealed_script) == program`, the revealed script is the exact PQ single-sig script `<33-byte pk_script> OP_CHECKSIG`, and execution reuses the existing PQ witness-script engine with fixed `SIGHASH_ALL`. It does not define generic witness-v1, keypath, tree, tapscript, annex, mempool, relay, policy, wallet, descriptor, RPC, address, or PSBT semantics. | Cross-node raw block positive fixture only. |
| `ACTIVE_REPLACEMENT` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` | `active-semantic divergence / pq-native replacement accepted` | Same as above from the opposite observation direction. The active node accepts the first positive PQ-native replacement fixture while the defined node rejects it under inherited witness-v1 handling. | Cross-node raw block positive fixture only. |
| `*` | `ACTIVE_REPLACEMENT` | `future-active compatibility reserved` | Any remaining pairing involving future active replacement beyond the explicit plain-block reporting rows, inherited-Taproot negative-control rows, and the single positive replacement-script-hash row is reserved for later implementation work. | Bucket and inventory now; implementation later. |
| `ACTIVE_REPLACEMENT` | `*` | `future-active compatibility reserved` | Any remaining pairing involving future active replacement beyond the explicit plain-block reporting rows, inherited-Taproot negative-control rows, and the single positive replacement-script-hash row is reserved for later implementation work. | Bucket and inventory now; implementation later. |

## Coverage Guardrails

1. Public-network defaults remain concrete but far-future dormant.
2. `SIGNALING` and `LOCKED_IN_PRE_ACTIVE` are currently exercisable only through
   regtest `-vbparams` override machinery.
3. No wallet, RPC, descriptor, PSBT, address, or witness-v1 behavior becomes
   approved merely because deployment reporting exists.
4. This matrix freezes what is comparable today; it does not speculate about
   active replacement semantics beyond the explicit negative-control row and
   the single positive replacement-script-hash row.
5. Runtime evidence for `ACTIVE_REPLACEMENT` in the current repo is limited to:
   - plain-block same-chain reporting compatibility
   - inherited Taproot negative-control rejection
   - one block-validation-only PQ-native witness-v1 replacement script-hash seam
6. No mempool, relay, or policy behavior is defined by this matrix.
7. No wallet, RPC, descriptor, address, or PSBT meaning is defined by this matrix.

## Implemented Runtime Evidence

The opening slice of `#23` froze this matrix and its suite classification. The
current runtime slices add evidence for the currently exercisable reporting rows
without changing the matrix meaning:

1. `feature_taproot_replacement_deployment.py` remains the single-node proof of
   concrete dormant replacement deployment reporting and regtest BIP9 override
   transitions through the exact active boundary.
2. `feature_taproot_replacement_compat.py` adds cross-node runtime evidence for
   `DEPLOYMENT_DEFINED_NOT_SIGNALING <-> SIGNALING` and
   `DEPLOYMENT_DEFINED_NOT_SIGNALING <-> LOCKED_IN_PRE_ACTIVE` on the same
   accepted chain, with `active = false` on both nodes.
3. `feature_taproot_replacement_active_boundary.py` adds cross-node runtime
   evidence for `DEPLOYMENT_DEFINED_NOT_SIGNALING <-> ACTIVE_REPLACEMENT` on the
   same accepted chain using plain blocks only.
4. `feature_taproot_replacement_active_semantic_guard.py` adds the first true
   active-semantic evidence as a negative control: a default
   `DEPLOYMENT_DEFINED_NOT_SIGNALING` node accepts a valid inherited witness-v1
   Taproot keypath spend at block-validation level, while an
   `ACTIVE_REPLACEMENT` node rejects the same block once the explicit guard is active.
5. `feature_taproot_replacement_active_positive_seam.py` adds the first positive
   PQ-native active seam as a raw block fixture only: an
   `ACTIVE_REPLACEMENT` node accepts a witness-v1 / 32-byte / non-P2SH
   replacement-script-hash spend when `SHA256(revealed_script) == program` and
   the revealed script is the exact PQ single-sig script
   `<33-byte pk_script> OP_CHECKSIG`, while a
   `DEPLOYMENT_DEFINED_NOT_SIGNALING` node rejects the same block.
6. No mempool, relay, or policy acceptance is implied by the current runtime evidence.

## Explicit-Replacement Semantic Guard

The current repo now owns one explicit active-semantic boundary:
`ACTIVE_REPLACEMENT` rejects inherited witness-v1 Taproot keypath spending
semantics in block validation.

This is **negative-control active evidence only**. It proves inherited Taproot
witness-v1 semantics are **not** the PQBTC replacement path. It does **not**
define any positive PQ-native active witness-v1, address, wallet, descriptor,
RPC, or PSBT seam.

## First Positive Active Seam

The current repo now owns one explicit positive active-semantic boundary:
`ACTIVE_REPLACEMENT` accepts exactly one PQ-native witness-v1 replacement seam.

This is a **single block-validation seam only**:

- witness version `1`
- 32-byte witness program
- non-P2SH
- witness stack `[pq_signature, revealed_script]`
- `SHA256(revealed_script) == program`
- `revealed_script` is exactly `<33-byte pk_script> OP_CHECKSIG`
- execution reuses the existing PQ witness-script engine through
  `SigVersion::WITNESS_V0`
- fixed `SIGHASH_ALL` only

It does **not** define generic witness-v1 semantics, keypath, tree/tapscript,
annex, mempool, relay, policy, wallet, descriptor, address, RPC, or PSBT behavior.

## Frozen Suite Classification

| Suite | Current `policy_class` | `taproot_matrix_bucket` | Rationale |
|---|---|---|---|
| `feature_taproot.py` | `legacy_only` | `legacy_only` | Explicit inherited BIP341/BIP342 functional coverage; not a PQBTC replacement target as-is. |
| `wallet_taproot.py` | `legacy_only` | `legacy_only` | Explicit inherited Taproot wallet coverage; not a PQBTC replacement target as-is. |
| `feature_taproot_replacement_deployment.py` | `pq_backlog` | `replacement_migration` | Directly exercises the frozen dormant replacement deployment/reporting path and regtest pre-active BIP9 transitions. |
| `feature_taproot_replacement_compat.py` | `pq_backlog` | `replacement_migration` | Adds cross-node evidence that defined, started, and locked_in pre-active states can diverge in reporting while remaining on the same accepted chain. |
| `feature_taproot_replacement_active_boundary.py` | `pq_backlog` | `replacement_migration` | Adds cross-node evidence that defined and active reporting can diverge on the same accepted chain using plain blocks only, without defining active semantics. |
| `feature_taproot_replacement_active_semantic_guard.py` | `pq_backlog` | `replacement_migration` | Adds the first active-semantic negative-control seam: inherited Taproot witness-v1 keypath spends remain acceptable on the defined side and are explicitly rejected on the active side. |
| `feature_taproot_replacement_active_positive_seam.py` | `pq_backlog` | `replacement_migration` | Adds the first positive active-semantic seam: a raw witness-v1 replacement-script-hash block is accepted on the active side and rejected on the defined side. |
| `rpc_createmultisig.py` | `dual_profile` | `deferred` | Contains Taproot-adjacent bech32m coverage, but replacement-specific semantics are not yet defined. |
| `rpc_psbt.py` | `pq_required` | `deferred` | Required for the restored pre-taproot PSBT decode/finalize contract, while Taproot-facing replacement semantics remain undefined. |
| `wallet_address_types.py` | `pq_required` | `deferred` | Required for restored inherited address-type smoke coverage, inherited mixed-address `sendmany`, and PQ-only inherited-address RPC rejection boundaries, while replacement-specific semantics remain undefined. |
| `wallet_createwalletdescriptor.py` | `pq_backlog` | `deferred` | Contains `tr(...)` descriptor creation paths, but replacement descriptor semantics are not yet defined. |
| `wallet_miniscript.py` | `pq_required` | `deferred` | Required for the restored wallet-side miniscript funding/signing/finalization contract, while TapMiniscript replacement meaning remains undefined. |
| `wallet_miniscript_decaying_multisig_descriptor_psbt.py` | `pq_required` | `deferred` | Required for the decaying miniscript multisig funding/signing/finalization contract, while future replacement-path meaning remains separate. |

## Explicit Non-Goals

This slice does **not** define:

- broad migration behavior between active replacement and dormant nodes beyond the explicit negative-control fixture
- broad migration behavior between active replacement and dormant nodes beyond the explicit negative-control fixture and single positive replacement-script-hash fixture
- CI reclassification of Taproot suites into PQ-required gates
- generic witness-v1, keypath, tree/tapscript, annex, mempool, relay, policy, wallet, RPC, descriptor, PSBT, or address semantics

## Downstream Boundary

The opening slice of `#23` froze the directional matrix and suite classification.
The current runtime slices implement the currently exercisable reporting rows
plus the inherited-Taproot negative-control guard only.

Remaining `#23` work after this slice is the first true active-semantic
positive PQ-native compatibility tranche and the deferred Taproot-facing
migration suites implied by this matrix.
