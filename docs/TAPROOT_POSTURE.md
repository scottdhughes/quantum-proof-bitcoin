# Taproot Posture Beyond v1

## Status: FROZEN
## Spec-ID: TAPROOT-POSTURE-v1
## Frozen-By: issue-21-posture-20260330
## Consensus-Relevant: YES

## Purpose

Freeze the post-v1 Taproot posture decision before activation, deployment, rollback,
or migration mechanics are specified.

This document is the canonical future-facing authority for Taproot posture on PQBTC.
It does not change current runtime behavior.

## Current v1 Baseline

The live v1 baseline remains:

1. Taproot deployment is `NEVER_ACTIVE` on PQBTC deployment tracks.
2. Pre-taproot `OP_CHECKSIG` and `OP_CHECKMULTISIG` are PQ-only semantics.
3. Pre-taproot sighash is fixed to `SIGHASH_ALL`.

These baseline facts are frozen in:

- `CONSENSUS_SURFACE.md`
- `CONSENSUS_DIFFS.md`
- `SCRIPT_SEMANTICS.md`
- `SIGHASH.md`
- `RELEASE_V1_RC1.md`
- `RUNBOOK_V1_RC1.md`

## Decision Record

### Chosen Posture

PQBTC future Taproot posture is **explicit replacement**.

The future witness-v1+ path, if activated later, must be specified as a PQ-native
replacement design. PQBTC will not define its future posture by simply turning on the
currently dormant inherited Bitcoin Taproot stack.

### Rejected Alternative

The rejected alternative is **coexistence**.

### Why Coexistence Was Rejected

Coexistence was not chosen because it would preserve or reintroduce an unresolved dual
semantic surface across:

- consensus deployment and witness-v1 validation
- address encoding and `bech32m` output handling
- descriptor and wallet output-type behavior
- PSBT and RPC Taproot reporting fields
- functional test and CI classification boundaries

The live repo is already frozen around a PQ-only pre-taproot consensus posture and still
treats Taproot-specific suites as non-PQ-gated legacy coverage. Freezing coexistence now
would force downstream activation and migration work to carry an open-ended mixed semantic
model that the current implementation and docs do not define.

## Normative Future Posture

1. Inherited Bitcoin Taproot/BIP341/BIP342 semantics are **not** the future activation
   target as-is on PQBTC.
2. Any future witness-v1+ replacement path must be specified as a PQ-native design.
3. Existing Taproot-related code and tests in the repo are implementation surfaces to
   classify, not proof of planned activation semantics.
4. No current dormant Taproot surface becomes active merely because it exists in the codebase.

## Surface Boundary Matrix

| Surface | Current v1 state | Explicit-replacement posture | Expected treatment | Downstream owner |
|---|---|---|---|---|
| Deployment state in `src/kernel/chainparams.cpp` | `DEPLOYMENT_TAPROOT` is `NEVER_ACTIVE` on PQBTC tracks | Current deployment settings are baseline only, not the future activation design | Retained dormant until a replacement activation spec exists | `#22` |
| Script semantics | Pre-taproot `CHECKSIG` / `CHECKMULTISIG` are PQ-only | Future witness-v1+ semantics must be defined as a new PQ-native replacement, not inherited Taproot semantics | Superseded later by replacement-specific script rules | `#21` then `#22` |
| Sighash posture | Pre-taproot paths are fixed to `SIGHASH_ALL` | This doc does not define any witness-v1+ replacement sighash rules | Downstream-defined only | `#21` then `#22` |
| Witness-v1 / Taproot address encoding in `src/key_io.cpp` | Bech32m/Taproot encoding and decoding code exists | Existing witness-v1 address code is not a commitment to activate inherited Taproot semantics | Retained dormant until a replacement address/output spec exists | `#21` then `#22` |
| Wallet Taproot capability surfaces such as `taprootEnabled()` | Interfaces and output-type plumbing exist | Existing wallet surfaces are inherited implementation artifacts, not approved future posture | Retained dormant and out of current sign-off scope | `#22` and `#23` |
| Descriptor `tr(...)` posture | Descriptor/test surfaces for Taproot exist in inherited wallet code and tests | `tr(...)` is not part of the approved future PQBTC posture as-is | Legacy-only until a replacement descriptor decision exists | `#21` then `#23` |
| PSBT Taproot fields | Taproot PSBT fields still exist in inherited code and tests | Existing PSBT Taproot field support is not approved future interoperability behavior | Retained dormant and classified as legacy-only for now | `#23` |
| RPC reporting and creation surfaces | RPC decode/create/reporting surfaces still expose Taproot-related fields and address types | Existing RPC exposure is not an approval of future activated semantics | Retained dormant; future replacement behavior must be specified explicitly | `#22` and `#23` |
| Functional Taproot suites | Taproot-specific functional tests remain in the repo | These tests are inventory surfaces, not future activation commitments | Retained as legacy-only coverage until migration decisions exist | `#23` |
| CI classification posture | `CI_COMPLETENESS.md` classifies Taproot-specific tests as `legacy_only` | This tranche does not reclassify them | Legacy-only remains frozen for now | `#23` |

## Explicit Non-Goals

This document does **not** define:

- activation state machine or deployment parameters
- rollback or abort rules for a future replacement path
- migration or compatibility matrix across pre/post-activation states
- CI reclassification or conversion of Taproot-specific suites
- runtime code changes, removals, or enablement

## Downstream Issue Boundaries

- `#21`: freeze posture choice and surface boundary map
- `#22`: define activation/deployment mechanism and rollback rules for the chosen posture
- `#23`: define cross-version migration and compatibility validation for the chosen posture
