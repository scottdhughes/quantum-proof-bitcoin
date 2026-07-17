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
| `pq_required` | `121` |
| `pq_backlog` | `0` |
| `dual_profile` | `141` |
| `legacy_only` | `14` |

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
12. `mempool_accept.py`
13. `mempool_accept_wtxid.py`
14. `mempool_datacarrier.py`
15. `mempool_dust.py`
16. `mempool_ephemeral_dust.py`
17. `mempool_expiry.py`
18. `mempool_limit.py`
19. `mempool_package_limits.py`
20. `mempool_package_onemore.py`
21. `mempool_package_rbf.py`
22. `mempool_packages.py`
23. `mempool_persist.py`
24. `mempool_reorg.py`
25. `mempool_resurrect.py`
26. `mempool_sigoplimit.py`
27. `mempool_spend_coinbase.py`
28. `mempool_truc.py`
29. `mempool_unbroadcast.py`
30. `mempool_updatefromblock.py`
31. `mining_basic.py`
32. `mining_getblocktemplate_longpoll.py`
33. `mining_mainnet.py`
34. `mining_prioritisetransaction.py`
35. `mining_template_verification.py`
36. `wallet_pq_active_ranged.py`
37. `wallet_pq_backup_recovery.py`
38. `wallet_pq_create_tx.py`
39. `wallet_pq_descriptors.py`
40. `wallet_pq_psbt.py`
41. `wallet_pq_send.py`
42. `wallet_pq_sendall.py`
43. `wallet_pq_sendmany.py`
44. `wallet_pq_signrawtransaction.py`
45. `feature_assumeutxo.py`
46. `feature_assumevalid.py`
47. `feature_bip68_sequence.py`
48. `feature_block.py`
49. `feature_blocksdir.py`
50. `feature_blocksxor.py`
51. `feature_cltv.py`
52. `feature_coinstatsindex.py`
53. `feature_config_args.py`
54. `feature_csv_activation.py`
55. `feature_fastprune.py`
56. `feature_index_prune.py`
57. `feature_loadblock.py`
58. `feature_pruning.py`
59. `feature_reindex.py`
60. `feature_reindex_init.py`
61. `feature_reindex_readonly.py`
62. `feature_remove_pruned_files_on_startup.py`
63. `feature_utxo_set_hash.py`
64. `feature_versionbits_warning.py`
65. `rpc_psbt.py`
66. `wallet_abandonconflict.py`
67. `wallet_address_types.py`
68. `wallet_assumeutxo.py`
69. `wallet_avoid_mixing_output_types.py`
70. `wallet_avoidreuse.py`
71. `wallet_backup.py`
72. `wallet_balance.py`
73. `wallet_basic.py`
74. `wallet_blank.py`
75. `wallet_bumpfee.py`
76. `wallet_change_address.py`
77. `wallet_coinbase_category.py`
78. `wallet_conflicts.py`
79. `wallet_create_tx.py`
80. `wallet_createwallet.py`
81. `wallet_createwalletdescriptor.py`
82. `wallet_crosschain.py`
83. `wallet_descriptor.py`
84. `wallet_disable.py`
85. `wallet_encryption.py`
86. `wallet_fallbackfee.py`
87. `wallet_fast_rescan.py`
88. `wallet_fundrawtransaction.py`
89. `wallet_gethdkeys.py`
90. `wallet_groups.py`
91. `wallet_hd.py`
92. `wallet_importdescriptors.py`
93. `wallet_importprunedfunds.py`
94. `wallet_keypool.py`
95. `wallet_keypool_topup.py`
96. `wallet_labels.py`
97. `wallet_listdescriptors.py`
98. `wallet_listreceivedby.py`
99. `wallet_listsinceblock.py`
100. `wallet_listtransactions.py`
101. `wallet_miniscript.py`
102. `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
103. `wallet_multisig_descriptor_psbt.py`
104. `wallet_multiwallet.py`
105. `wallet_orphanedreward.py`
106. `wallet_reindex.py`
107. `wallet_reorgsrestore.py`
108. `wallet_rescan_unconfirmed.py`
109. `wallet_resendwallettransactions.py`
110. `wallet_send.py`
111. `wallet_sendall.py`
112. `wallet_sendmany.py`
113. `wallet_signrawtransactionwithwallet.py`
114. `wallet_simulaterawtx.py`
115. `wallet_spend_unconfirmed.py`
116. `wallet_startup.py`
117. `wallet_timelock.py`
118. `wallet_transactiontime_rescan.py`
119. `wallet_txn_clone.py`
120. `wallet_txn_doublespend.py`
121. `wallet_v3_txs.py`

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
The unknown-versionbits warning confidence gap is now also part of the
required gate: `feature_versionbits_warning.py` covers warning-free behavior
below the unknown-bit threshold, active unknown-rules warnings through mining
and network info, and `alertnotify` output once the unknown versionbit
activates on regtest.
The BIP68 sequence-lock confidence gap is now also part of the required gate:
`feature_bip68_sequence.py` covers sequence-lock disable-flag behavior,
`non-BIP68-final` rejection and acceptance across confirmed and unconfirmed
inputs, pre-CSV-activation block acceptance for BIP68-invalid spends, mempool
cleanup after reorg, suite-local CSV activation, and version-2 relay
standardness.
The CLTV confidence gap is now also part of the required gate:
`feature_cltv.py` covers buried BIP65 deployment metadata, pre-activation
acceptance of CLTV-invalid transactions in blocks, post-activation block
version enforcement, exact mempool and block rejection reasons for CLTV
failures, and valid CLTV spend acceptance.
The CSV activation confidence gap is now also part of the required gate:
`feature_csv_activation.py` covers suite-local activation for BIP68, BIP112,
and BIP113; pre-activation acceptance; post-activation rejection and acceptance
across relative locktime, CHECKSEQUENCEVERIFY, and MedianTimePast nLockTime
cases; and exact block rejection reasons.
The broad pruning confidence gap is now also part of the required gate:
`feature_pruning.py` covers automatic and manual pruning over large block
files, stale-block and deep-reorg retention, redownload of previously pruned
block data, invalid prune option handling, `scanblocks` errors over pruned
data, pruneheight accounting when undo data is absent, and wallet load/rescan
boundaries where wallet support is compiled.
The inherited raw transaction mempool-acceptance confidence gap is now also
part of the required gate: `mempool_accept.py` covers `testmempoolaccept`
argument validation, already-known and missing-input handling, standardness and
resource-envelope reject reasons, fee and replacement checks, relative
locktime policy, anchor behavior, and confirmed bare-multisig policy under the
current legacy-compatible PQC profile.
The inherited wtxid-aware mempool-acceptance confidence gap is now also part
of the required gate: `mempool_accept_wtxid.py` covers same-`txid` /
different-`wtxid` child transactions, exact already-in-mempool reporting,
same-nonwitness-data rejection, no replacement by an alternate witness, and
canonical mempool `wtxid` rebroadcast under the current legacy-compatible PQC
profile.
The inherited datacarrier policy confidence gap is now also part of the
required gate: `mempool_datacarrier.py` covers default uncapped OP_RETURN
relay, disabled datacarrier relay, custom `-datacarriersize` acceptance and
rejection boundaries, empty and zero-byte OP_RETURN payload handling, and
`getmempoolinfo` datacarrier-size reporting under the current
legacy-compatible PQC profile.
The inherited dust relay policy confidence gap is now also part of the
required gate: `mempool_dust.py` covers `-dustrelayfee=0` small-output
acceptance, exact dust-threshold acceptance, one-satoshi-below-threshold
`dust` rejection, OP_RETURN zero-threshold behavior, and multiple configured
dust relay fee rates under the current legacy-compatible PQC profile.
The inherited ephemeral-dust package policy confidence gap is now also part
of the required gate: `mempool_ephemeral_dust.py` covers TRUC 1P1C
ephemeral-dust package acceptance, zero-fee dust parent rules, sponsor
cycling, restart behavior, fee-having and multidust rejection, missing
ephemeral spends, reorg restoration, and disabled-minrelay batched sweep
behavior under the current legacy-compatible PQC profile.
The inherited mempool expiry policy confidence gap is now also part of the
required gate: `mempool_expiry.py` covers default and custom mempool expiry
windows, parent and child eviction, independent transaction survival,
prioritisation persistence after expiry, and mocktime-driven expiry checks
under the current legacy-compatible PQC profile.
The inherited mempool size, eviction, and package-limit policy confidence gap
is now also part of the required gate: `mempool_limit.py` covers full-mempool
minimum-fee rejection, CPFP package admission below the mempool minimum, peer
broadcast fee-filter behavior, immediate low-feerate package eviction,
`-maxmempool` floor init rejection, mid-package eviction, mid-package
replacement, and RBF carveout limit rejection under the current
legacy-compatible PQC profile.
The inherited package ancestor/descendant limit confidence gap is now also
part of the required gate: `mempool_package_limits.py` covers combined
in-mempool and in-package chain limits, ancestor and descendant count limits,
bushy package ancestor accounting, ancestor-size and descendant-size limits,
stable `package-mempool-limits` rejection, and acceptance after clearing the
conflicting mempool state under the current legacy-compatible PQC profile.
The inherited one-more-descendant carveout confidence gap is now also part of
the required gate: `mempool_package_onemore.py` covers full ancestor-chain
construction, ancestor and descendant limit rejection, oversized descendant
rejection, package rejection diagnostics, direct-child carveout acceptance,
independent chain admission, and single-conflict RBF replacement of the
carveout chain under the current legacy-compatible PQC profile.
The inherited package RBF confidence gap is now also part of the required
gate: `mempool_package_rbf.py` covers 1-parent-1-child package replacement,
singleton conflict replacement, additional-fee and incremental-relay-fee
requirements, replacement-candidate caps, package and conflict-cluster shape
rejection, feerate diagram rejection, TRUC zero-fee-parent package RBF, and
mempool-ancestor conflict rejection under the current legacy-compatible PQC
profile.
The inherited mempool package tracking confidence gap is now also part of the
required gate: `mempool_packages.py` covers default and custom
ancestor/descendant chain limits, verbose ancestor and descendant accounting,
`gettxspendingprevout` consistency, `prioritisetransaction` fee-delta
accounting, cross-node custom limit propagation, and reorg disconnect handling
under the current legacy-compatible PQC profile.
The inherited mempool persistence confidence gap is now also part of the
required gate: `mempool_persist.py` covers default `mempool.dat` reload,
`-persistmempool=0` dump/load suppression, `savemempool` and `importmempool`
RPC behavior, priority-delta and unbroadcast-set persistence, wallet
watch-only accounting after reload where wallet support is compiled,
cross-node `mempool.dat` import, import union behavior, and disk-write failure
handling under the current legacy-compatible PQC profile.
The inherited mempool reorg confidence gap is now also part of the required
gate: `mempool_reorg.py` covers coinbase-spend mempool removal when reorgs
make coinbase spends immature, timelock non-final rejection and later
acceptance, disconnected block transactions returning to the mempool, invalid
descendant removal after deeper invalidation, and relay/request behavior for
transactions from recently disconnected blocks under the current
legacy-compatible PQC profile.
The inherited mempool resurrection confidence gap is now also part of the
required gate: `mempool_resurrect.py` covers disconnected parent and
descendant transactions returning to the mempool with zero confirmations after
a two-block reorg, then being mined again under the current legacy-compatible
PQC profile.
The inherited mempool sigop resource-envelope confidence gap is now also part
of the required gate: `mempool_sigoplimit.py` covers `-bytespersigop` adjusted
vsize accounting, ancestor and descendant size accounting with adjusted vsize,
package-limit rejection for sigop-heavy bare multisig packages, and legacy
sigops standardness boundaries under the current legacy-compatible PQC
profile.
The inherited mempool coinbase-spend maturity confidence gap is now also part
of the required gate: `mempool_spend_coinbase.py` covers near-mature coinbase
spend admission, adjacent premature coinbase-spend rejection with
`bad-txns-premature-spend-of-coinbase`, mined confirmation of the mature
spend, and later admission of the formerly premature spend after height
advances under the current legacy-compatible PQC profile.
The inherited TRUC/v3 mempool policy confidence gap is now also part of the
required gate: `mempool_truc.py` covers v3 transaction size and child-size
limits, TRUC inheritance and replacement checks, reorg restoration behavior,
sibling eviction, package ancestor handling, `testmempoolaccept` inheritance
diagnostics, and minrelay package combinations under the current
legacy-compatible PQC profile.
The inherited mempool unbroadcast delivery confidence gap is now also part of
the required gate: `mempool_unbroadcast.py` covers unbroadcast count and
per-entry reporting, mempool.dat persistence across restart, rebroadcast after
reconnect and scheduler advance, removal from the unbroadcast set after peer
delivery, suppression of repeat broadcast to later peers, no re-addition for
already-known transactions, and cleanup before confirmation under the current
legacy-compatible PQC profile.
The inherited mempool update-from-block reorg-accounting confidence gap is now
also part of the required gate: `mempool_updatefromblock.py` covers descendant
and ancestor count/size reconstruction for a 100-transaction tournament graph
re-added from disconnected blocks, disconnect-pool trimming at the
`MAX_DISCONNECTED_TX_POOL_BYTES` boundary with coupled child removal, and
too-long-chain handling when non-standardly mined chains return to the mempool
under normal chain limits in the current legacy-compatible PQC profile.
The inherited mining RPC and block-template confidence gap is now also part of
the required gate: `mining_basic.py` covers `getmininginfo`, witness
commitment construction, versionbits and `-blockversion`, `submitblock` and
`submitheader` validation, fee and sigop ordering in block templates,
`-blockmintxfee` filtering, BIP94 timewarp protection, pruned-block
`submitblock`, `-blockmaxweight` and `-blockreservedweight` boundaries, and
generated coinbase height-locktime behavior under the current
legacy-compatible PQC profile.
The inherited getblocktemplate longpoll confidence gap is now also part of the
required gate: `mining_getblocktemplate_longpoll.py` covers stable longpollid
values when nothing changes, longpoll wait behavior on a separate RPC
connection, wakeup after another node generates a block, wakeup after the local
node generates a block, and wakeup after a new mempool transaction enters under
the current legacy-compatible PQC profile.
The inherited alternate-mainnet difficulty-adjustment mining confidence gap is
now also part of the required gate: `mining_mainnet.py` covers deterministic
alternate-mainnet block data, first-period block acceptance at difficulty 1,
current and next retarget reporting in `getmininginfo`, acceptance of the first
second-period block at difficulty 4, and historical difficulty, bits, and target
reporting in `getblock` under the current legacy-compatible PQC profile.
The inherited mining prioritise-transaction confidence gap is now also part of
the required gate: `mining_prioritisetransaction.py` covers RPC argument
validation for `prioritisetransaction` and `getprioritisedtransactions`,
fee-delta accounting and persistence around replacement and restart boundaries,
diamond-shaped package modified-fee accounting, prioritised and deprioritised
mining selection, relay-fee override admission for a free transaction, and
`getblocktemplate` refresh after prioritisation changes under the current
legacy-compatible PQC profile.
The inherited getblocktemplate proposal-verification confidence gap is now also
part of the required gate: `mining_template_verification.py` covers
proposal-mode validation for valid and malformed blocks, invalid-template
reject reasons, difficulty, merkle-root, timestamp, and best-prevblk
boundaries, transaction-bearing proposal checks without UTXO mutation,
overspend and double-spend rejection, and concurrent proposal validation under
the current legacy-compatible PQC profile.
The risk-reviewed PQBTC configuration-namespace confidence gap is now also
part of the required gate: `feature_config_args.py` covers `pqbtc.conf`
discovery and diagnostics, explicit and ignored configuration-file handling,
`includeconf`, and datadir/config precedence. This bounded gate does not claim
platform default datadir names or broader binary, GUI, service, user-agent, or
network identity coverage; those remain separate risk decisions.
The inherited `feature_coinstatsindex_compatibility.py` suite is now
`legacy_only`: it hard-codes Bitcoin Core v28.2 migration behavior, but this
repository has no PQBTC v28.2 release lineage or authentic compatible binaries.
The available PQBTC v1 tags identify as v30.2 and cannot supply the old index
format the suite is intended to exercise. This classification records the
boundary without promoting a skipped test or fabricating release provenance.
The inherited `feature_unsupported_utxo_db.py` suite is also now `legacy_only`:
it creates a Bitcoin Core v0.14.3 chainstate database and checks current-node
rejection and reindex behavior, but this repository has no PQBTC v0.14.3
release lineage and Track A does not support migration from an old Bitcoin Core
datadir. The mechanics remain useful reference coverage without becoming a
required PQBTC previous-release gate.
The inherited `mempool_compatibility.py` suite is now `legacy_only` as well. It
moves `mempool.dat` in both directions between Bitcoin Core v0.20.1 and the
current node to enforce an upstream serialization upgrade/downgrade contract.
PQBTC has no v0.20.1 release lineage and does not support that cross-product
migration path, so the mechanics remain reference coverage rather than a
required PQBTC gate.
The inherited `wallet_backwards_compatibility.py` suite is now `legacy_only`.
It loads wallets in both directions between the current node and Bitcoin Core
v0.20.1 through v25.0, covering legacy BDB wallets, descriptor-version
boundaries, transaction and keypool preservation, and legacy-to-descriptor
migration behavior. PQBTC never shipped that release lineage and does not
support those cross-product wallet upgrade and downgrade paths, so the suite
remains inherited reference coverage rather than a required PQBTC gate.
The inherited `wallet_migration.py` suite is now `legacy_only`. It creates
legacy BDB wallets with Bitcoin Core v28.2 and verifies current-node conversion
to SQLite descriptor wallets, including watch-only and solvables partitioning,
wallet-data preservation, backup creation, and failure rollback. PQBTC has no
v28.2 release lineage and does not support migration from an upstream Bitcoin
Core wallet, so this remains reference coverage rather than a required PQBTC
gate. No suites remain in `pq_backlog`; see
[PREVIOUS_RELEASE_ASSET_BOUNDARY.md](PREVIOUS_RELEASE_ASSET_BOUNDARY.md) for
the completed provenance boundary.

Explicit legacy-only coverage in this tranche includes:

1. Taproot-specific tests
2. SegWit/pre-SegWit transition tests
3. legacy message-signing flows
4. inherited Bitcoin Core v28.2 coinstats-index migration coverage
5. inherited Bitcoin Core v0.14.3 chainstate-database migration coverage
6. inherited Bitcoin Core v0.20.1 `mempool.dat` migration coverage
7. inherited Bitcoin Core v0.20.1 through v25.0 wallet upgrade and downgrade coverage
8. inherited Bitcoin Core v28.2 legacy BDB-to-descriptor wallet migration coverage

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

1. selecting any future promotion candidate from `dual_profile` through a
   separate risk-based posture decision rather than extending this completed
   backlog mechanically
2. defining explicit entry criteria for any new `pq_backlog` suite so the
   zero-backlog inventory remains a meaningful reviewed baseline
