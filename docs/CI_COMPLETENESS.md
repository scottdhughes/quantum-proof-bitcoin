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

The current functional corpus has `276` tracked test files, classified as:

| Class | Count |
|---|---|
| `pq_required` | `40` |
| `pq_backlog` | `85` |
| `dual_profile` | `142` |
| `legacy_only` | `9` |

Current required PQ-first gates:

1. `feature_pq_block_limits.py`
2. `feature_pq_reorg.py`
3. `feature_pqsig_basic.py`
4. `feature_pqsig_multisig.py`
5. `feature_taproot_replacement_deployment.py`
6. `feature_taproot_replacement_compat.py`
7. `feature_taproot_replacement_active_boundary.py`
8. `feature_taproot_replacement_active_semantic_guard.py`
9. `feature_taproot_replacement_active_positive_seam.py`
10. `mempool_pq_limits.py`
11. `mempool_pq_stress.py`
12. `wallet_pq_active_ranged.py`
13. `wallet_pq_backup_recovery.py`
14. `wallet_pq_create_tx.py`
15. `wallet_pq_descriptors.py`
16. `wallet_pq_psbt.py`
17. `wallet_pq_send.py`
18. `wallet_pq_sendall.py`
19. `wallet_pq_sendmany.py`
20. `wallet_pq_signrawtransaction.py`
21. `feature_assumeutxo.py`
22. `feature_assumevalid.py`
23. `feature_block.py`
24. `rpc_psbt.py`
25. `wallet_address_types.py`
26. `wallet_assumeutxo.py`
27. `wallet_backup.py`
28. `wallet_fast_rescan.py`
29. `wallet_fundrawtransaction.py`
30. `wallet_miniscript.py`
31. `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
32. `wallet_multisig_descriptor_psbt.py`
33. `wallet_reindex.py`
34. `wallet_reorgsrestore.py`
35. `wallet_rescan_unconfirmed.py`
36. `wallet_resendwallettransactions.py`
37. `wallet_send.py`
38. `wallet_sendall.py`
39. `wallet_sendmany.py`
40. `wallet_transactiontime_rescan.py`

The previous wallet-confidence gap is closed in this tranche by promoting the
existing PQ wallet suites into the required gate and adding PQ-native wallet,
fixed watch-only descriptor, direct create-tx, `send`, `sendall`, `sendmany`,
direct raw-signing, and PSBT unit coverage to the default `test_pqbtc`
profile. The restored inherited pre-taproot PSBT RPC surface and the
watch-only multisig descriptor PSBT finalization flow are now also part of the
required gate, so the canonical PQ path covers both the proprietary PQ
partial-signature path and the legacy multisig/classical finalize path. The
broader inherited miniscript descriptor funding/signing/finalization surface,
including the decaying multisig locktime contract, is now also part of the
required gate. The inherited address-type confidence gap is now also part of
the required gate: `wallet_address_types.py` covers inherited address-shape
smoke behavior, descriptor bech32m smoke behavior, inherited mixed-address
`sendmany`, PQ-only inherited-address RPC rejections, and invalid address-type
precedence. The inherited raw transaction funding surface is now also part of
the required gate: `wallet_fundrawtransaction.py` covers default and preset
input selection, fee/change handling, address/change-type handling, watch-only
and external-input funding, transaction-size limits, duplicate outputs,
unsafe-input controls, and input confirmation controls under the current
legacy-compatible PQC profile. The validation-side confidence gap is now also
closed by promoting `feature_assumevalid.py` into the required gate, so the
canonical PQ path covers the live assumevalid signature-skipping boundary in
addition to the owned assumeutxo activation and wallet background-sync slices.
The inherited wallet send-path confidence gap is now also part of the required
gate: `wallet_send.py`, `wallet_sendall.py`, and `wallet_sendmany.py` cover the
restored legacy-compatible destination send, sweep, PSBT/no-broadcast,
fee/change/input-selection, watch-only, confirmation-control, anti-fee-sniping,
and subtract-fee-from-output validation surfaces that currently pass under the
PQC profile.
The inherited wallet rebroadcast confidence gap is now also part of the
required gate: `wallet_resendwallettransactions.py` covers delayed wallet
transaction rebroadcast, scheduler-triggered resubmission, peer inventory
announcement, and parent-before-child rebroadcast for unconfirmed transaction
chains evicted from the mempool under the current PQC profile.
The inherited wallet reindex confidence gap is now also part of the required
gate: `wallet_reindex.py` covers watch-only descriptor birthtime adjustment,
explicit rescan detection for a previously missed transaction, `-reindex`
restart completion, confirmed transaction survival after reindex, and
descriptor wallet birthtime convergence to the transaction time under the
current PQC profile.
The inherited wallet fast-rescan confidence gap is now also part of the
required gate: `wallet_fast_rescan.py` covers block-filter fast rescan and
slow full-block rescan parity for descriptor wallets across backup restore and
non-active descriptor import paths, including ranged descriptor top-ups and a
fixed non-ranged descriptor under the current PQC profile.
The inherited wallet unconfirmed-rescan confidence gap is now also part of the
required gate: `wallet_rescan_unconfirmed.py` covers descriptor import rescans
of mempool transactions after a mocked reorg, watched parent-address ownership,
re-entered parent detection, and unconfirmed child sweep detection through
input ordering under the current PQC profile.
The inherited wallet reorg-restore confidence gap is now also part of the
required gate: `wallet_reorgsrestore.py` covers wallet transaction status
restoration across longer-chain reloads, conflicted transaction recovery,
startup abandonment of orphaned coinbase transactions and descendants, and
unclean-shutdown reorg recovery without duplicate-disconnect crashes under the
current PQC profile.
The inherited wallet transaction-time rescan confidence gap is now also part
of the required gate: `wallet_transactiontime_rescan.py` covers watch-only
descriptor transaction time preservation across original detection and full
restoration rescans, idle `abortrescan`, invalid `rescanblockchain` parameter
rejection, and locked encrypted wallet rescan rejection under the current PQC
profile.
The inherited wallet backup/restore confidence gap is now also part of the
required gate: `wallet_backup.py` covers `backupwallet`/`restorewallet`
balance preservation after transaction churn, invalid and missing backup-file
rejection, destination-path safety, backup-to-source failure, unnamed restore,
and pruned-node restore behavior under the current PQC profile.
The replacement-path confidence gap is closed in this tranche by promoting the
full deterministic Taproot replacement functional stack into the required PQ
gate.
The assumeutxo confidence gap is closed in this tranche by promoting the live
snapshot-activation surface and the adjacent wallet-side background-sync
surface into the canonical required gate. The assumevalid confidence gap is
closed in this tranche by promoting the fixed invalid-signature burial-depth
validation slice into the same required PQ path. The full-block confidence gap
is narrowed in this tranche by promoting the bounded invalid-branch, transport,
and resurrection `feature_block.py` surface into the same required PQ path.
The remaining key backlog families are:

1. mempool and mining policy suites not yet given explicit PQ gating treatment
2. additional chainstate and validation-facing feature tests that still need a later PQ migration decision
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
`feature_taproot_replacement_active_semantic_guard.py` are now `pq_required` as
replacement-path deployment, pre-active compatibility, active-boundary
reporting, first-positive active-semantic, and negative-control
active-semantic coverage. Their current required-gate status is governed by
`TAPROOT_POSTURE.md` and `TAPROOT_MIGRATION_MATRIX.md`.
`policy_class` remains the CI gating/ownership surface, while
`taproot_matrix_bucket` is migration-matrix metadata only and does not change
required CI behavior in this tranche.

## Ownership

Until a separate ownership model or `CODEOWNERS` file exists, all current workflow and gate ownership is assigned to `@scottdhughes`.

## Deferred Work

Still deferred after this tranche:

1. converting additional `pq_backlog` suites into required PQ gates or documenting permanent dual-profile boundaries for them
2. promoting high-value chainstate and validation suites from `pq_backlog` once the current wallet-confidence tranche is stable
