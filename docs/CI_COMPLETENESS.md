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
| `pq_required` | `91` |
| `pq_backlog` | `34` |
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
24. `feature_blocksdir.py`
25. `feature_blocksxor.py`
26. `feature_coinstatsindex.py`
27. `feature_fastprune.py`
28. `feature_index_prune.py`
29. `feature_loadblock.py`
30. `feature_reindex.py`
31. `feature_reindex_init.py`
32. `feature_reindex_readonly.py`
33. `feature_remove_pruned_files_on_startup.py`
34. `feature_utxo_set_hash.py`
35. `rpc_psbt.py`
36. `wallet_abandonconflict.py`
37. `wallet_address_types.py`
38. `wallet_assumeutxo.py`
39. `wallet_avoid_mixing_output_types.py`
40. `wallet_avoidreuse.py`
41. `wallet_backup.py`
42. `wallet_balance.py`
43. `wallet_basic.py`
44. `wallet_blank.py`
45. `wallet_bumpfee.py`
46. `wallet_change_address.py`
47. `wallet_coinbase_category.py`
48. `wallet_conflicts.py`
49. `wallet_create_tx.py`
50. `wallet_createwallet.py`
51. `wallet_createwalletdescriptor.py`
52. `wallet_crosschain.py`
53. `wallet_descriptor.py`
54. `wallet_disable.py`
55. `wallet_encryption.py`
56. `wallet_fallbackfee.py`
57. `wallet_fast_rescan.py`
58. `wallet_fundrawtransaction.py`
59. `wallet_gethdkeys.py`
60. `wallet_groups.py`
61. `wallet_hd.py`
62. `wallet_importdescriptors.py`
63. `wallet_importprunedfunds.py`
64. `wallet_keypool.py`
65. `wallet_keypool_topup.py`
66. `wallet_labels.py`
67. `wallet_listdescriptors.py`
68. `wallet_listreceivedby.py`
69. `wallet_listsinceblock.py`
70. `wallet_listtransactions.py`
71. `wallet_miniscript.py`
72. `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
73. `wallet_multisig_descriptor_psbt.py`
74. `wallet_multiwallet.py`
75. `wallet_orphanedreward.py`
76. `wallet_reindex.py`
77. `wallet_reorgsrestore.py`
78. `wallet_rescan_unconfirmed.py`
79. `wallet_resendwallettransactions.py`
80. `wallet_send.py`
81. `wallet_sendall.py`
82. `wallet_sendmany.py`
83. `wallet_signrawtransactionwithwallet.py`
84. `wallet_simulaterawtx.py`
85. `wallet_spend_unconfirmed.py`
86. `wallet_startup.py`
87. `wallet_timelock.py`
88. `wallet_transactiontime_rescan.py`
89. `wallet_txn_clone.py`
90. `wallet_txn_doublespend.py`
91. `wallet_v3_txs.py`

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
The inherited wallet creation and blank-wallet confidence gap is now also part
of the required gate: `wallet_blank.py` preserves blank descriptor-wallet flags
across descriptor import and encryption, while `wallet_createwallet.py` covers
invalid option combinations, disabled-private-key and blank-wallet creation,
descriptor import behavior, encryption, empty-passphrase warnings,
`avoid_reuse`, legacy-wallet rejection, and wallet version logging under the
current PQC profile.
The inherited wallet descriptor-creation and cross-chain wallet-file
confidence gap is now also part of the required gate:
`wallet_createwalletdescriptor.py` and `wallet_crosschain.py` cover xpub-based
descriptor creation, bech32/bech32m descriptor manager creation, PQ-only
active-manager rejection, and cross-genesis wallet load/restore rejection under
the current PQC profile.
The inherited multiwallet lifecycle confidence gap is now also part of the
required gate: `wallet_multiwallet.py` covers wallet directory scanning, wallet
path validation and symlink rejection, dynamic load/unload and creation,
per-wallet balance and fee isolation, concurrent load rejection, multiwallet
backup/restore, and exclusive database locking under the current PQC profile.
The inherited wallet key-management and descriptor-maintenance confidence gap
is now also part of the required gate: `wallet_descriptor.py`,
`wallet_disable.py`, `wallet_encryption.py`, `wallet_gethdkeys.py`,
`wallet_hd.py`, `wallet_keypool.py`, `wallet_keypool_topup.py`, and
`wallet_listdescriptors.py` cover descriptor wallet maintenance, no-wallet
runtime behavior, wallet encryption, HD key reporting, HD backup/restore,
keypool refill/exhaustion, restored keypool top-up, and descriptor listing
under the current PQC profile.
The inherited wallet accounting, labels, and transaction-listing confidence
gap is now also part of the required gate: `wallet_balance.py`,
`wallet_coinbase_category.py`, `wallet_labels.py`, `wallet_listreceivedby.py`,
`wallet_listsinceblock.py`, and `wallet_listtransactions.py` cover balance
accounting, coinbase category reporting, label RPCs, received-by accounting,
since-block listing, and transaction listing/gettransaction behavior under the
current PQC profile.
The inherited wallet coin-selection and spend-policy confidence gap is now
also part of the required gate: `wallet_avoid_mixing_output_types.py`,
`wallet_avoidreuse.py`, `wallet_change_address.py`, `wallet_fallbackfee.py`,
`wallet_groups.py`, and `wallet_spend_unconfirmed.py` cover output-type
grouping, avoid-reuse coin selection, change-address selection, fallback-fee
RBF creation, grouped UTXO selection, avoid-partial-spends behavior, and
unconfirmed-input spend policy under the current PQC profile.
The inherited wallet bumpfee and transaction-conflict confidence gap is now
also part of the required gate: `wallet_abandonconflict.py`,
`wallet_bumpfee.py`, `wallet_conflicts.py`, `wallet_txn_clone.py`, and
`wallet_txn_doublespend.py` cover abandoned/conflicted transaction handling,
fee bumping and PSBT fee bumping, wallet conflict tracking, cloned/malleated
transaction accounting, and double-spend transaction accounting under the
current PQC profile.
The inherited wallet transaction-construction, simulation, and broad basic
behavior confidence gap is now also part of the required gate:
`wallet_basic.py`, `wallet_create_tx.py`, and `wallet_simulaterawtx.py` cover
basic wallet balance and UTXO visibility, lockunspent persistence and
validation, inherited transaction creation, anti-fee-sniping locktime
behavior, transaction-size and mempool-chain rejection, current wallet
transaction version behavior, raw transaction balance simulation, watch-only
descriptor visibility, duplicate-spend rejection, missing-input rejection,
chained simulated transactions, and mined-input rejection under the current
PQC profile.
The inherited wallet raw-signing and descriptor-import confidence gap is now
also part of the required gate: `wallet_signrawtransactionwithwallet.py` and
`wallet_importdescriptors.py` cover locked encrypted wallet rejection, invalid
sighash validation, script verification error reporting, fully signed
transaction no-op behavior, CSV/CLTV witness signing, descriptor import
validation, duplicate imports and label updates, multisig and ranged descriptor
imports, private-key-enabled wallet constraints, and descriptor persistence
under the current PQC profile.
The inherited remaining wallet transaction-breadth confidence gap is now also
part of the required gate: `wallet_importprunedfunds.py`,
`wallet_timelock.py`, `wallet_orphanedreward.py`, and `wallet_v3_txs.py` cover
imported pruned-fund proof handling, timelocked-send accounting stability,
orphaned block reward abandonment and reload behavior, and v3/TRUC wallet
transaction handling under the current PQC profile.
The inherited wallet startup confidence gap is now also part of the required
gate: `wallet_startup.py` covers default wallet auto-load, persisted
`load_on_startup` wallet creation flags, `unloadwallet` startup-list removal,
and `loadwallet` startup-list addition under the current PQC profile.
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
The block storage and prune-lifecycle confidence gap is now also part of the
required gate: `feature_blocksdir.py`, `feature_blocksxor.py`,
`feature_fastprune.py`, `feature_remove_pruned_files_on_startup.py`, and
`feature_index_prune.py` cover external block storage, XORed blk/rev handling,
large-block admission under `-fastprune`, pruned-file cleanup on startup, and
blockfilter/coinstats index behavior under prune.
The bootstrap/import confidence gap is now also part of the required gate:
`feature_loadblock.py` covers linearized `bootstrap.dat` production from live
PQBTC regtest block files and `-loadblock` import convergence on a disconnected
peer.
The txoutset-hash confidence gap is now also part of the required gate:
`feature_utxo_set_hash.py` covers the bounded raw `OP_TRUE` chainstate
sequence, manual MuHash equality, and fixed PQBTC `hash_serialized_3` /
`muhash` constants.
The txoutset/index confidence gap is now also part of the required gate:
`feature_coinstatsindex.py` covers direct-mined raw `OP_TRUE` txoutset deltas,
indexed-vs-non-indexed `gettxoutsetinfo()` parity, verbose block accounting,
restart, reindex, reindex-chainstate, reorg, and stale-index recovery on the
bounded PQBTC dataset.
The restart/reindex confidence gap is now also part of the required gate:
`feature_reindex.py` covers repeated `-reindex` and `-reindex-chainstate`
recovery, out-of-order blockfile recovery, expected debug markers, and
interrupted blockfilter reindex resume without wiping the existing LevelDB.
The init-time block-index recovery confidence gap is now also part of the
required gate: `feature_reindex_init.py` covers missing `blocks/index` startup
failure, explicit `-reindex` / `-reindex-chainstate` recovery guidance, the
noninteractive reindex-acceptance path, and return to height `200`.
The read-only blockstore reindex confidence gap is now also part of the
required gate: `feature_reindex_readonly.py` covers `-fastprune` blockfile
rollover, read-only and host-level immutable treatment of the first blk file
when supported, successful `-reindex -fastprune` restart, the expected
`Reindexing finished` marker, preserved chain height, and cleanup permission
restoration.
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
