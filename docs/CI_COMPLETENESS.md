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

The current functional corpus has `266` tracked test files, classified as:

| Class | Count |
|---|---|
| `pq_required` | `6` |
| `pq_backlog` | `104` |
| `dual_profile` | `147` |
| `legacy_only` | `9` |

Current required PQ-first gates:

1. `feature_pq_block_limits.py`
2. `feature_pq_reorg.py`
3. `feature_pqsig_basic.py`
4. `feature_pqsig_multisig.py`
5. `mempool_pq_limits.py`
6. `mempool_pq_stress.py`

Key backlog families in this tranche:

1. wallet functional coverage outside the current PQ-specific tests
2. mempool and mining policy suites not yet given explicit PQ gating treatment
3. chainstate and validation-facing feature tests that still need a later PQ migration decision

Explicit legacy-only coverage in this tranche includes:

1. Taproot-specific tests
2. SegWit/pre-SegWit transition tests
3. legacy message-signing flows

## Ownership

Until a separate ownership model or `CODEOWNERS` file exists, all current workflow and gate ownership is assigned to `@scottdhughes`.

## Deferred Work

Still deferred after this tranche:

1. converting `pq_backlog` suites into required PQ gates or documenting permanent dual-profile boundaries for them
