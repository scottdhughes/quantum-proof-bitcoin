# PQBTC CI Completeness Inventory

## Status: TRACKED
## Spec-ID: CI-COMPLETENESS-v1
## Frozen-By: issue-15-foundation-20260327
## Consensus-Relevant: NO

## Purpose

Freeze the first post-wallet, post-multi-algorithm CI completeness contract:

1. the required PQ-first functional gate list has a single checked-in source of truth
2. the full functional corpus is classified against the current PQ-first posture
3. workflow and gate ownership is explicit

This tranche does not migrate legacy suites to PQ semantics and does not optimize runtime or matrix size.

## Canonical Inputs

- PQ gate list: `ci/test/pq_functional_tests.txt`
- Exhaustive functional inventory: `ci/test/functional_suite_inventory.json`
- Inventory validator: `ci/test/check_ci_inventory.py`

## Policy Classes

| Class | Meaning |
|---|---|
| `pq_required` | Current required PQ-first functional gates. |
| `pq_backlog` | Candidate suites for later explicit PQ migration or PQ gating decisions. |
| `dual_profile` | Retained under the current non-gating dual-profile contract. |
| `legacy_only` | Explicit legacy/retired behavior that is not on the PQ migration path. |

## Current Inventory Summary

The current functional corpus has `271` tracked test files, classified as:

| Class | Count |
|---|---|
| `pq_required` | `9` |
| `pq_backlog` | `106` |
| `dual_profile` | `147` |
| `legacy_only` | `9` |

Current required PQ-first gates:

1. `feature_pq_block_limits.py`
2. `feature_pq_reorg.py`
3. `feature_pqsig_basic.py`
4. `feature_pqsig_multisig.py`
5. `mempool_pq_limits.py`
6. `mempool_pq_stress.py`
7. `wallet_pq_active_ranged.py`
8. `wallet_pq_backup_recovery.py`
9. `wallet_pq_psbt.py`

The previous wallet-confidence gap is closed in this tranche by promoting the
existing PQ wallet suites into the required gate and adding PQ-native wallet and
PSBT unit coverage to the default `test_pqbtc` profile. The remaining key
backlog families are:

1. mempool and mining policy suites not yet given explicit PQ gating treatment
2. chainstate and validation-facing feature tests that still need a later PQ migration decision
3. broader dual-profile and legacy-only coverage that still needs durable ownership and migration boundaries

Explicit legacy-only coverage in this tranche includes:

1. Taproot-specific tests
2. SegWit/pre-SegWit transition tests
3. legacy message-signing flows

Inherited Taproot-specific suites remain `legacy_only` in the current CI contract,
while `feature_taproot_replacement_deployment.py` and
`feature_taproot_replacement_compat.py` and
`feature_taproot_replacement_active_boundary.py` and
`feature_taproot_replacement_active_positive_seam.py` and
`feature_taproot_replacement_active_semantic_guard.py` remain `pq_backlog` as
replacement-path deployment, pre-active compatibility, active-boundary
reporting, first-positive active-semantic, and negative-control
active-semantic coverage. Their future status is governed by
`TAPROOT_POSTURE.md` and `TAPROOT_MIGRATION_MATRIX.md`.
`policy_class` remains the CI gating/ownership surface, while
`taproot_matrix_bucket` is migration-matrix metadata only and does not change
required CI behavior in this tranche.

## Ownership

Until a separate ownership model or `CODEOWNERS` file exists, all current workflow and gate ownership is assigned to `@scottdhughes`.

## Deferred Work

Still deferred after this tranche:

1. converting `pq_backlog` suites into required PQ gates or documenting permanent dual-profile boundaries for them
2. promoting high-value chainstate and validation suites from `pq_backlog` once the current wallet-confidence tranche is stable
