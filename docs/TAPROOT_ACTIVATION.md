# Taproot Replacement Activation and Rollback

## Status: FROZEN
## Spec-ID: TAPROOT-ACTIVATION-v1
## Frozen-By: issue-22-activation-20260331
## Consensus-Relevant: YES

## Purpose

Freeze the activation/deployment model and the concrete dormant deployment
values for the explicit-replacement Taproot path before migration tests or
replacement semantics are implemented.

This document is the canonical future-facing authority for replacement activation,
deployment parameter shape, and rollback/abort semantics on PQBTC. It does not
change current runtime behavior.

## Historical v1 Baseline

The shipped v1 baseline was `DORMANT_BASELINE`:

1. `DEPLOYMENT_TAPROOT` was `NEVER_ACTIVE` on PQBTC deployment tracks.
2. Pre-taproot `OP_CHECKSIG` and `OP_CHECKMULTISIG` remain PQ-only.
3. Pre-taproot sighash remains fixed `SIGHASH_ALL`.
4. No dormant Taproot-facing surface is approved for use merely because code exists.

## Current Repo Deployment State

The live repo now remains operationally dormant, but it is no longer
unconfigured:

1. `Consensus::DEPLOYMENT_TAPROOT` is wired with concrete far-future BIP9 values.
2. The operator-facing deployment/reporting name is `taproot_replacement`.
3. The current operator-visible phase is `DEPLOYMENT_DEFINED_NOT_SIGNALING`.
4. No dormant Taproot-facing surface is approved for use merely because code exists.

The future active path, if ever deployed, is a PQ-native replacement path. It is
not inherited BIP341/BIP342 Taproot semantics switched on as-is.

## Mechanism Family Decision

### Chosen Mechanism Family

PQBTC freezes the future replacement activation family as **BIP9/versionbits**.

This choice freezes the deployment/reporting model already present in the repo,
including:

- `Consensus::BIP9Deployment` in `src/consensus/params.h`
- `DEPLOYMENT_TAPROOT` deployment slots in `src/kernel/chainparams.cpp`
- deployment reporting via `deploymentinfo.cpp` and `getdeploymentinfo`
- versionbits threshold state reporting in `versionbits.cpp`

### Rejected Alternative

The rejected alternative is a mechanism-agnostic or later-defined activation family.

### Why a Mechanism-Agnostic Model Was Rejected

The repo already exposes a concrete deployment family in consensus params, chainparams,
and RPC reporting. Leaving the mechanism family unresolved here would keep the main
`#22` design question open and force downstream migration work to reason about an
unknown activation substrate.

Freezing BIP9/versionbits now is the narrowest decision-complete move because it
resolves the family choice without prematurely choosing concrete network values.

## Two-Layer Activation Model

This document uses two layers:

- **Operator/governance phases**: planning and release-facing states used to describe
  whether the replacement path is dormant, deployable, signaling, active, or aborted.
- **Code-facing BIP9 states**: `defined`, `started`, `locked_in`, `active`, and
  `failed`, as exposed by the existing versionbits deployment model.

The crosswalk below is descriptive only. It is not an identity claim that every
operator phase is a distinct code state.

| Operator/governance phase | Meaning | Code-facing BIP9 state relationship |
|---|---|---|
| `DORMANT_BASELINE` | Historical shipped v1 posture with Taproot disabled and no approved replacement behavior | No active deployment instance is in use; `DEPLOYMENT_TAPROOT` is `NEVER_ACTIVE` |
| `SPEC_FROZEN_NOT_DEPLOYING` | Posture and activation model are frozen in docs, but no live deployment instance is configured for signaling | No deployment attempt is active yet |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | A concrete future-dated BIP9 deployment instance exists in code/config terms, but the start condition is not yet met | `defined` |
| `SIGNALING` | A deployment attempt is collecting BIP9 signaling and has not yet locked in | `started` |
| `LOCKED_IN_PRE_ACTIVE` | Threshold rules are satisfied, but replacement behavior is not active yet | `locked_in` |
| `ACTIVE_REPLACEMENT` | The PQ-native replacement path is active according to the frozen deployment rules | `active` |
| `ABORTED_PRE_ACTIVATION` | Operator/governance outcome for an abandoned pre-activation attempt | For a started deployment instance, the terminal code-facing state is `failed`; for withdrawal before signaling, the repo returns to a non-deploying posture |

## Phase Semantics

### `DORMANT_BASELINE`
- This is the historical shipped v1 state.
- `DEPLOYMENT_TAPROOT` is `NEVER_ACTIVE`.
- Witness-v1 code and Taproot-facing wallet/RPC/descriptor/PSBT surfaces are dormant inventory only.
- No operator should treat existing dormant surfaces as approved for use.

### `SPEC_FROZEN_NOT_DEPLOYING`
- The replacement posture and activation model are frozen in docs.
- No deployment instance is configured for signaling.
- This phase is documentation/governance only and does not imply a live deployment object.

### `DEPLOYMENT_DEFINED_NOT_SIGNALING`
- This is the current repo state after concrete deployment values are wired.
- A future BIP9 deployment instance may exist, but start conditions are not yet met.
- The operator-facing deployment/reporting name is `taproot_replacement`.
- Replacement behavior remains dormant.
- Wallet, RPC, PSBT, descriptor, address, and witness-v1 behavior remain unchanged.

### `SIGNALING`
- BIP9 signaling has started.
- The replacement path is still not active.
- No surface behavior changes are approved in this phase.
- This phase exists to collect signaling only.

### `LOCKED_IN_PRE_ACTIVE`
- BIP9 threshold conditions are satisfied.
- Replacement behavior is still not active until the activation delay/height rule is reached.
- No ordinary rollback is defined in this phase.

### `ACTIVE_REPLACEMENT`
- The PQ-native replacement path becomes active.
- Only at this phase may downstream implementation tranches activate replacement-specific
  witness-v1/address/wallet/descriptor/PSBT/RPC behavior.
- This tranche does not define those active semantics; it only defines when such semantics
  become eligible for later implementation.

### `ABORTED_PRE_ACTIVATION`
- This is an operator/governance outcome, not a standalone BIP9 state.
- During signaling, the code-facing terminal state for an abandoned or expired deployment
  attempt is `failed`.
- Before signaling starts, withdrawal returns the repo to a dormant/non-deploying posture
  without requiring a `failed` steady-state interpretation.

## Deployment-Parameter Schema

The mechanism family is frozen as BIP9/versionbits. Any later code tranche must fill in
this parameter schema explicitly.

| Field | Meaning | Frozen in this tranche |
|---|---|---|
| Deployment mechanism family | Activation/reporting family used for the replacement path | BIP9/versionbits |
| Deployment identifier / reporting surface | Human-readable deployment name exposed through deployment reporting | Field required; concrete name/value not chosen here |
| Signaling bit | Versionbits bit used for miner signaling | Field required; concrete value not chosen here |
| Start condition | Condition that moves a deployment instance from non-signaling into `started` | Field required; concrete value not chosen here |
| Timeout / expiry condition | Condition after which an unsuccessful deployment attempt terminates | Field required; concrete value not chosen here |
| Threshold rule | Confirmation/signaling threshold required for lock-in | Field required; concrete value not chosen here |
| Period window | Retarget/signaling window used for threshold evaluation | Field required; concrete value not chosen here |
| Minimum activation delay / height | Delay between lock-in and active enforcement | Field required; concrete value not chosen here |
| Network-specific override surface | Where per-network values may differ | Field required; concrete values not chosen here |
| Operator-visible status names | Release/operator-facing names for deployment status reporting | Frozen by this document |
| Release-gating prerequisites | Preconditions for even permitting a deployment attempt | Field required; concrete checklist may be extended later |

### Frozen Operator-Visible Status Vocabulary

The operator-facing vocabulary is:

- `DORMANT_BASELINE`
- `SPEC_FROZEN_NOT_DEPLOYING`
- `DEPLOYMENT_DEFINED_NOT_SIGNALING`
- `SIGNALING`
- `LOCKED_IN_PRE_ACTIVE`
- `ACTIVE_REPLACEMENT`
- `ABORTED_PRE_ACTIVATION`

The code-facing BIP9 reporting vocabulary remains:

- `defined`
- `started`
- `locked_in`
- `active`
- `failed`

Future implementation and release docs must preserve this two-layer distinction.

## Frozen Concrete Deployment Values

The repo now freezes these concrete dormant defaults:

| Network | Deployment name | Bit | Start time | Timeout | Min activation height | Threshold | Period |
|---|---|---|---|---|---|---|---|
| `main` | `taproot_replacement` | 2 | `4102444800` (`2100-01-01T00:00:00Z`) | `4133980800` (`2101-01-01T00:00:00Z`) | 0 | 1815 | 2016 |
| `testnet` | `taproot_replacement` | 2 | `4102444800` (`2100-01-01T00:00:00Z`) | `4133980800` (`2101-01-01T00:00:00Z`) | 0 | 1512 | 2016 |
| `testnet4` | `taproot_replacement` | 2 | `4102444800` (`2100-01-01T00:00:00Z`) | `4133980800` (`2101-01-01T00:00:00Z`) | 0 | 1512 | 2016 |
| `signet` | `taproot_replacement` | 2 | `4102444800` (`2100-01-01T00:00:00Z`) | `4133980800` (`2101-01-01T00:00:00Z`) | 0 | 1815 | 2016 |
| `regtest` | `taproot_replacement` | 2 | `4102444800` (`2100-01-01T00:00:00Z`) | `4133980800` (`2101-01-01T00:00:00Z`) | 0 | 108 | 144 |

These values are intentionally far-future dormant defaults. They make the
replacement deployment concrete and operator-visible without starting a near-term
signaling commitment on public networks.

## Rollback and Abort Envelope

Rollback and abort are defined conservatively by phase.

| Phase | Ordinary withdrawal / rollback rule | Outcome |
|---|---|---|
| `DORMANT_BASELINE` | Ordinary planning withdrawal is allowed | Remains dormant |
| `SPEC_FROZEN_NOT_DEPLOYING` | Ordinary planning withdrawal is allowed | Returns to dormant/non-deploying posture |
| `DEPLOYMENT_DEFINED_NOT_SIGNALING` | Ordinary withdrawal is allowed before signaling begins | Returns to dormant/non-deploying posture |
| `SIGNALING` | Abort is allowed before lock-in | Operator outcome is `ABORTED_PRE_ACTIVATION`; code-facing deployment attempt terminates as `failed` |
| `LOCKED_IN_PRE_ACTIVE` | **No ordinary rollback is defined** | Any retreat requires a separate exceptional recovery decision outside this tranche |
| `ACTIVE_REPLACEMENT` | **No routine rollback is defined** | Post-activation retreat is outside this tranche |

The `failed` BIP9 state is meaningful only as a pre-activation abort/expiry outcome for a
started deployment instance. It is not a post-activation rollback concept.

## Phase-by-Surface Activation Matrix

| Surface | `DORMANT_BASELINE` / `SPEC_FROZEN_NOT_DEPLOYING` | `DEPLOYMENT_DEFINED_NOT_SIGNALING` / `SIGNALING` / `LOCKED_IN_PRE_ACTIVE` | `ACTIVE_REPLACEMENT` | Downstream owner |
|---|---|---|---|---|
| Deployment state / `getdeploymentinfo` posture | Current repo exposes a concrete far-future dormant `taproot_replacement` deployment; no replacement semantics are active | Deployment reporting may reflect BIP9 lifecycle, but no replacement semantics are active | Eligible for later implementation under the replacement rules | `#22` |
| Witness-v1 output acceptance | Dormant inventory only | Unchanged; no approved activation during pre-active phases | Eligible only after replacement activation rules are implemented | `#22` |
| Address encoding and reporting | Dormant inventory only | Unchanged; existing code is not approval for use | Eligible only after replacement-specific address/output rules are implemented | `#22` |
| Wallet capability surfaces such as `taprootEnabled()` | Dormant inventory only | Unchanged; no approved wallet activation during pre-active phases | Eligible only after replacement-specific wallet behavior is defined | `#22` then `#23` |
| Descriptor `tr(...)` | Legacy-only inventory surface | Unchanged; not approved for use during pre-active phases | Migration classification is now frozen in `TAPROOT_MIGRATION_MATRIX.md`; replacement semantics remain deferred | `#23` |
| PSBT Taproot fields | Legacy-only inventory surface | Unchanged; not approved for replacement use during pre-active phases | Migration classification is now frozen in `TAPROOT_MIGRATION_MATRIX.md`; replacement semantics remain deferred | `#23` |
| RPC create/decode/reporting surfaces | Dormant or legacy-only inventory surfaces | Unchanged; reporting does not imply approved replacement semantics | Migration classification is now frozen in `TAPROOT_MIGRATION_MATRIX.md`; replacement-specific behavior remains deferred | `#22` then `#23` |
| Functional Taproot suites | Legacy-only coverage | Unchanged | Migration relevance is now frozen in `TAPROOT_MIGRATION_MATRIX.md`; implementation remains deferred | `#23` |
| CI classification posture | Inherited Taproot suites remain `legacy_only`; replacement deployment reporting remains `pq_backlog` | Unchanged | `policy_class` remains frozen while `taproot_matrix_bucket` carries migration metadata only | `#23` |

## Release-Gating Baseline

This tranche freezes that a future deployment attempt must not be moved beyond
the current dormant defined state until all of the following exist in a later follow-up:

- frozen posture doc (`TAPROOT_POSTURE.md`)
- frozen activation/rollback doc (this document)
- operator/release guidance for interpreting deployment status
- frozen migration/compatibility matrix in `TAPROOT_MIGRATION_MATRIX.md`
- replacement-specific semantics and activation behavior for the affected surfaces

This tranche does not define the full checklist contents beyond those baseline categories.

## Explicit Non-Goals

This document does **not** define:

- the replacement-path witness-v1 script/address semantics themselves
- migration or compatibility behavior implementation across pre/post-activation nodes; the frozen matrix lives in `TAPROOT_MIGRATION_MATRIX.md`
- CI reclassification or conversion of Taproot-specific suites
- routine rollback after lock-in or after activation

## Downstream Issue Boundaries

- `#22`: freeze activation/deployment mechanism family, state machine, parameter schema,
  and rollback envelope for the explicit-replacement path
- `#23`: freeze the migration matrix and implement migration/compatibility behavior spanning pre/post-activation states
