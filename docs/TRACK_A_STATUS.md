# PQBTC Track A Status

## Status: ACTIVE
## Spec-ID: TRACK-A-STATUS-v1
## Updated: 2026-04-14
## Current Phase: Phase 1 - Wallet And Block Surface Expansion

## Purpose

Operational status for the ninety-day Track A plan.

This file is the working handoff for Aineko. When no more specific repo task is
active, use this file to choose the next safe step for `quantum-proof-bitcoin`.

## Current Objective

Keep the non-signing decaying miniscript descriptor/PSBT carveout in
`wallet_miniscript_decaying_multisig_descriptor_psbt.py` frozen, keep the
current `feature_block.py` invalid-branch/transport/mempool tranche frozen,
freeze the new `wallet_miniscript.py`, `rpc_createmultisig.py`,
`wallet_multisig_descriptor_psbt.py`, `feature_blocksdir.py`,
`feature_blocksxor.py`, `feature_fastprune.py`, and
`feature_remove_pruned_files_on_startup.py`, `feature_index_prune.py`, and
`feature_pq_block_limits.py`, `feature_pq_reorg.py`, and
`mempool_pq_limits.py`, and `mempool_pq_stress.py` boundaries, freeze the new
`feature_pqsig_basic.py`, `feature_pqsig_multisig.py`,
`feature_loadblock.py`, `wallet_miniscript.py`, and
`feature_utxo_set_hash.py`, `feature_coinstatsindex.py`, and
`feature_reindex.py`, `feature_reindex_init.py`, and
`feature_reindex_readonly.py`, and `feature_assumevalid.py` boundaries, and
promote `feature_assumeutxo.py` and `wallet_assumeutxo.py` into the canonical
`pq_required` gate, then return the next owned follow-on to
`feature_coinstatsindex_compatibility.py`, with broader inherited miniscript
funding/finalization rehab as the local wallet alternate.

## Current Working Thesis

- `quantum-proof-bitcoin` stays on Track A: native post-quantum Bitcoin.
- Track A assumes PQBTC launches as a new chain at block 0, not as an in-place
  continuation of inherited Bitcoin chain history.
- Blockstream's Liquid/Simplicity work is a benchmark and adjacent migration
  reference, not a reason to reset the repo.
- The best progress in this window is one owned product-facing migration slice,
  not broad speculative redesign.

## Current Follow-On Candidates

Preferred next owned tranche:

1. `feature_coinstatsindex_compatibility.py`
   - Why next: the core assumeutxo activation surface and the adjacent
     wallet-side background-sync surface are now frozen, so the remaining
     nearby chainstate/index follow-on is cross-version coinstats
     compatibility.

Alternate rebalance:

2. broader inherited miniscript funding/finalization rehab
   - Why alternate: if local wallet adjacency is still the priority, this
     remains the next wallet-side surface to reopen.

Wallet alternate:

3. broader inherited classical multisig PSBT/finalization rehab
   - Why alternate: if wallet compatibility scope widens beyond miniscript
     funding, this remains the larger deferred wallet tranche.

Still deferred:

4. `feature_assumevalid.py` gate promotion
5. TapMiniscript activation or replacement semantics

## Current Queue

1. This slice freezes `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
   as:
   - inherited xpub-backed decaying miniscript descriptor import as reference
     context only
   - one explicit inherited coordinator `sendtoaddress(...)` rejection boundary
   - PQ-safe raw funding into the watch-only miniscript receive script under
     the functional harness
   - non-signing watch-only PSBT creation/decode across the decaying locktime
     loop
   - one explicit inherited classical signer
     `walletprocesspsbt(finalize=false)` encoding-failure negative control
   Minimum validation only:
   - `python3 test/functional/wallet_miniscript_decaying_multisig_descriptor_psbt.py`
   - `python3 test/functional/wallet_pq_descriptors.py`
   Stays deferred:
   - inherited classical miniscript signer rehabilitation
   - broad inherited multisig broadcast/finalization rehabilitation
   - policy-level claims beyond the current functional harness carveout
2. `feature_block.py` now owns:
   - exact push-only MAX_SCRIPT_SIZE boundary construction under PQBTC limits
   - PQ legacy-signature helpers for the block-spend paths this suite covers
   - same-work side branches as header-only announcements that do not move the
     active tip by themselves
   - explicit full ancestor-chain delivery only when those side branches are
     later exercised
   - explicit invalid longer-fork and invalid-descendant branch assertions with
     tip preservation instead of disconnect-only expectations
   - transport-size oversized-block expectations where PQBTC now fails before
     inherited parser-level checks
   - resurrection checks grounded on the live mempool baseline plus the
     `tx78`/`tx79` delta
   Minimum validation target:
   - `python3 test/functional/feature_block.py`
   Still deferred inside this suite:
   - promotion into `pq_required`
   - broader CI ownership decisions for chainstate-facing backlog beyond this
     fixed functional contract
3. `wallet_miniscript.py` now owns:
   - inherited miniscript sanity rejection coverage for insane and
     unsatisfiable descriptors
   - one static public-key `wsh(...)` miniscript import plus address
     derivation as the only positive in-file miniscript surface
   - one explicit raw-funding `scriptpubkey` negative control under the
     default policy path for inherited classical miniscript outputs
   - one direct coinbase-funded watch-only miniscript UTXO
   - one incomplete non-signing PSBT-backed send-preparation boundary using the
     tracked miniscript UTXO without change
   - explicit incomplete `walletprocesspsbt(finalize=false)` and
     `finalizepsbt` boundaries for that watch-only miniscript PSBT
   - one wallet-local xprv-backed `wsh(pk(.../*))` miniscript import as the
     only positive in-file signer-backed miniscript surface
   - one explicit inherited `sendtoaddress(...)` `Signing transaction failed`
     negative control for funding that signer-backed miniscript address
   - one direct coinbase-funded signer-backed miniscript UTXO with
     `spendable=true` and `has_private_keys=true`
   - one explicit PSBT update/signing seam for that signer-backed miniscript:
     `walletprocesspsbt(sign=false, finalize=false)` fills witness data
     without signatures, and `walletprocesspsbt(finalize=false)` adds exactly
     one classical-looking `partial_sig`
   - explicit node-side decode/finalize failures for that signed miniscript
     PSBT under the current PQ-only signature-encoding rule
   - explicit ranged xpub/tprv invalid-key negative controls, including one
     TapMiniscript xpub import boundary
   Minimum validation target:
   - `python3 test/functional/wallet_miniscript.py`
   Still deferred inside this suite:
   - broader inherited miniscript funding/finalization rehabilitation beyond
     the current one-signer boundary
   - TapMiniscript activation or replacement semantics
   - promotion into `pq_required`
4. `rpc_createmultisig.py` now owns:
   - inherited `createmultisig` descriptor/address output construction for
     `legacy` / `p2sh-segwit` / `bech32`
   - address expectations grounded on `deriveaddresses(descriptor)` under the
     current PQBTC network identity instead of inherited `bcrt...` prefixes
   - explicit 16-of-20 creation coverage as an output-shape surface
   - explicit `bech32m` rejection, mixed-key fallback warnings, sortedmulti
     equivalence over sorted keys, and multisig redeemScript encoding checks
   - one representative inherited classical funding `scriptpubkey` negative
     control
   Minimum validation target:
   - `python3 test/functional/rpc_createmultisig.py`
   Still deferred inside this suite:
   - broad `signrawtransactionwithkey` / `combinerawtransaction` rehab
   - inherited classical multisig broadcast compatibility
   - replacement-path `bech32m` semantics
   - promotion into `pq_required`
5. `wallet_multisig_descriptor_psbt.py` now owns:
   - inherited xpub-backed watch-only `wsh(sortedmulti(...))` descriptor import
     as reference context
   - cross-participant receive/change address agreement for the imported
     watch-only multisig
   - one explicit inherited coordinator `sendtoaddress(...)` rejection
     boundary
   - direct coinbase funding into the multisig receive address to create one
     real watch-only UTXO without reopening inherited send-path behavior
   - watch-only
     `walletcreatefundedpsbt -> decodepsbt -> walletprocesspsbt(finalize=false)`
     coverage for that watch-only UTXO
   - one real inherited signer `walletprocesspsbt(finalize=false)` seam that
     returns an incomplete PSBT carrying exactly one classical-looking raw
     `partial_sig` entry
   - explicit node-side `decodepsbt`, subsequent signer processing, and
     `finalizepsbt` encoding-failure boundaries for that signed PSBT under the
     current PQ-only signature rules
   Minimum validation target:
   - `python3 test/functional/wallet_multisig_descriptor_psbt.py`
   Still deferred inside this suite:
   - broad inherited classical multisig signing/finalization rehabilitation
   - promotion into `pq_required`
6. `feature_blocksdir.py` now owns:
   - missing `-blocksdir` init failure when the external path does not exist
   - successful external blk/rev storage under the chosen blocksdir with the
     local chain path retaining the block index
   - explicit no-fallback contract: the node datadir does not recreate a local
     `blocks/` directory while the external blocksdir is active
   - restart persistence with the same external blocksdir
   Minimum validation target:
   - `python3 test/functional/feature_blocksdir.py`
   Still deferred inside this suite:
   - block-file mutation/corruption handling
   - XORed block-file handling
   - promotion into `pq_required`
7. `feature_blocksxor.py` now owns:
   - non-wallet block-file seeding via deterministic mining under
     `-blocksxor=1 -fastprune=1`
   - explicit multi-file blk/rev creation before any XOR assertions
   - manual un-XOR rewrite of mined blk/rev files using the stored random XOR
     key
   - restart rejection when `-blocksxor=0` is requested while that random key
     still exists
   - successful `-blocksxor=0` restart after deleting the stored key, followed
     by `verifychain(checklevel=2, nblocks=0)` integrity validation
   - null XOR key recreation after the successful un-XOR restart path
   Minimum validation target:
   - `python3 test/functional/feature_blocksxor.py`
   Still deferred inside this suite:
   - broader block-file corruption handling
   - prune/reindex lifecycle coverage
   - promotion into `pq_required`
8. `feature_fastprune.py` now owns:
   - startup under `-fastprune`
   - one large witness-annex block assembled through the non-signing
     `MiniWalletMode.ADDRESS_OP_TRUE` path
   - direct `generateblock(...)` acceptance for that large block without crash
     or hang
   - explicit chain-height advancement from the initialized 200-block harness
     to 201
   Minimum validation target:
   - `python3 test/functional/feature_fastprune.py`
   Still deferred inside this suite:
   - prune lifecycle and file-deletion handling
   - restart and reindex behavior
   - prune-plus-index interaction
   - promotion into `pq_required`
9. `feature_remove_pruned_files_on_startup.py` now owns:
   - mining enough blocks under `-fastprune -prune=1` to create multiple
     blk/rev files before pruning
   - explicit prune-triggered blk/rev deletion expectations on platforms where
     open file descriptors do not block removal
   - explicit Windows delayed-delete expectations while blk/rev descriptors
     remain open
   - cleanup completion on restart after those file descriptors are closed
   - `-reindex` recreation of a fresh `blk00000.dat` / `rev00000.dat`
     baseline after wiping the previous pruned file set
   Minimum validation target:
   - `python3 test/functional/feature_remove_pruned_files_on_startup.py`
   Still deferred inside this suite:
   - prune-plus-index interaction
   - broader index recovery and prune-lock semantics
   - promotion into `pq_required`
10. `feature_index_prune.py` now owns:
   - linear RPC block sync under prune for blockfilter/coinstats index nodes
   - index accessibility at tip before and after pruning begins
   - continued queryability for pruned block heights while the index state
     still covers them
   - explicit RPC errors after restarting without indices
   - restart continuity when pruning exactly up to the indices' best block
   - expected init failures when pruning moves past the indices' best block
   - recovery after restarting with `-reindex`
   - explicit prune-lock movement in the reorg path
   Minimum validation target:
   - `python3 test/functional/feature_index_prune.py`
   Still deferred inside this suite:
   - promotion into `pq_required`
   - broader bootstrap/loadblock import behavior
11. `feature_pq_block_limits.py` now owns:
   - exact `getblocktemplate` block weight limit reporting at `16_000_000`
   - exact-ceiling `-blockmaxweight=16000000` restart acceptance
   - explicit startup rejection for `-blockmaxweight=16000001`
   - post-restart mining continuity after returning to the allowed ceiling
   - required PQ-first gate protection for this launch-profile surface
   Minimum validation target:
   - `python3 test/functional/feature_pq_block_limits.py`
   Still deferred inside this suite:
   - broader mining policy and template-construction behavior
   - mempool packing or fee-driven block assembly behavior
12. `feature_pq_reorg.py` now owns:
   - wallet-funded PQ output creation followed by one PQ-signed spend on the
     first branch
   - acceptance into mempool, mining on the first branch, and explicit mempool
     removal after that block
   - competing longer branch construction on the disconnected peer
   - node restart before reconnect without losing later reorg reconciliation
   - mempool reinsertion of the previously mined PQ spend after the competing
     branch wins
   - rebroadcast tolerance for "already in mempool" / "already known" states
  - re-mining of the spend on the final winning branch with both nodes
     converging on the same final tip
   - successful `PQBTCSLORecorder` completion for the reorg scenario
   Minimum validation target:
   - `python3 test/functional/feature_pq_reorg.py`
   Still deferred inside this suite:
   - broader multi-transaction reorg conflict matrices
   - large-witness mempool churn and restart-persistence boundaries
   - storage/import bootstrap behavior
13. `mempool_pq_limits.py` now owns:
   - exact-size PQ signature acceptance and short/long PQ signature rejection
   - `10_000` byte witness-item acceptance and `10_001` byte witness-item
     rejection
   - stable oversized-witness reject reason across repeated admission attempts
     and restart
   - large-witness RBF replacement across increasing fee steps
   - restart persistence for a batch of large-witness mempool transactions until
     mining clears them
   - successful `PQBTCSLORecorder` completion with the reject reason recorded
   - required PQ-first gate protection for this mempool boundary
   Minimum validation target:
   - `python3 test/functional/mempool_pq_limits.py`
   Still deferred inside this suite:
   - broader two-node relay stress behavior
   - reorg reconciliation behavior
   - storage/import bootstrap behavior
14. `mempool_pq_stress.py` now owns:
   - witness-heavy RBF replacement propagation across both nodes
   - relay of a broader independent witness-heavy spend batch across both nodes
   - restart persistence on the receiving node after reconnect and sync
   - mempool clearing on both nodes when the stress block is mined
   - mempool restoration on invalidate and clearing again on reconsider
   - successful `PQBTCSLORecorder` completion for the stress scenario
   - required PQ-first gate protection for this relay/mempool stress boundary
   Minimum validation target:
   - `python3 test/functional/mempool_pq_stress.py`
   Still deferred inside this suite:
   - broader multi-peer partition behavior
   - signature-validity edge cases
   - storage/import bootstrap behavior
15. `feature_pqsig_basic.py` now owns:
   - wallet-helper funding of a PQ `OP_CHECKSIG` P2WSH witness output under the
     functional harness
   - one valid PQ witness acceptance path through `testmempoolaccept`
   - one truncated-signature rejection boundary at mempool admission
   - one tampered-but-correct-length signature rejection boundary at mempool
     admission
   - broadcast and confirmation of the accepted spend
   - required PQ-first gate protection for this minimal signing boundary
   Minimum validation target:
   - `python3 test/functional/feature_pqsig_basic.py`
   Still deferred inside this suite:
   - multisignature PQ witness behavior
   - wallet-owned PSBT or descriptor signing semantics
   - relay, restart, and reorg behavior
16. `feature_pqsig_multisig.py` now owns:
   - wallet-helper funding of a PQ `OP_CHECKMULTISIG` P2WSH witness output under
     the functional harness
   - one valid 2-of-2 PQ multisignature witness acceptance path through
     `testmempoolaccept`
   - one tampered multisignature witness rejection boundary at mempool
     admission
   - broadcast and confirmation of the accepted multisignature spend
   - required PQ-first gate protection for this minimal multisignature boundary
   Minimum validation target:
   - `python3 test/functional/feature_pqsig_multisig.py`
   Still deferred inside this suite:
   - threshold variants beyond the current 2-of-2 witness shape
   - wallet-owned PSBT, descriptor, or RPC multisignature semantics
   - relay, restart, reorg, and block-import behavior
17. `feature_loadblock.py` now owns:
   - source-node generation of `100` post-genesis blocks while the peer remains
     disconnected
   - linearization config built from the live source-node RPC credentials,
     blockdir, genesis hash, and current regtest message-start bytes
   - successful `linearize-hashes.py` and `linearize-data.py` production of one
     `bootstrap.dat`
   - restart of the unsynced peer with `-loadblock=<bootstrap.dat>`
   - blocking completion of import up to height `100`
   - convergence on the same best block hash as the source node after import
   Minimum validation target:
   - `python3 test/functional/feature_loadblock.py`
   Still deferred inside this suite:
   - pruning-plus-bootstrap interaction
   - index rebuild or reindex interaction
   - malformed or interrupted bootstrap import recovery
18. `feature_utxo_set_hash.py` now owns:
   - one deterministic raw `OP_TRUE` MiniWallet funding path in place of the
     inherited Taproot-shaped MiniWallet self-transfer path
   - direct inclusion of that raw `OP_TRUE` self-transfer by `generateblock(...)`
   - manual MuHash accumulation that still matches
     `gettxoutsetinfo("muhash")`
   - fixed PQBTC `hash_serialized_3` and `muhash` constants for this exact
     chainstate sequence
   - explicit deferral of the inherited default MiniWallet send path after its
     reproduced `scriptpubkey (-26)` failure
   Minimum validation target:
   - `python3 test/functional/feature_utxo_set_hash.py`
   Still deferred inside this suite:
   - adjacent coinstats-index coverage
   - promotion into `pq_required`
19. `feature_coinstatsindex.py` now owns:
   - one raw `OP_TRUE` MiniWallet funding path in place of the inherited
     default MiniWallet mempool self-transfer path
   - one direct-mined raw self-transfer that establishes the first owned
     txoutset delta before the index/non-index comparison
   - one direct-mined parent/child pair that covers a spendable raw output plus
     one explicit `OP_RETURN` unspendable output
   - stable indexed historical height/hash queries and verbose `block_info`
     accounting across that bounded dataset
   - restart, `-reindex`, `-reindex-chainstate`, reorg, and stale-index
     recovery behavior on the same dataset
   - explicit deferral of the inherited default MiniWallet mempool path after
     its reproduced `scriptpubkey (-26)` failure
   Minimum validation target:
   - `python3 test/functional/feature_coinstatsindex.py`
   Still deferred inside this suite:
   - previous-release coinstats index compatibility
   - promotion into `pq_required`
20. `feature_reindex.py` now owns:
   - repeated restart-time `-reindex` recovery to the same three-block height
   - repeated restart-time `-reindex-chainstate` recovery to the same
     three-block height
   - out-of-order blk file recovery after manually swapping the first
     post-genesis blocks on disk
   - expected out-of-order block debug markers during that restart
   - recovery of the full `12`-block chain after the out-of-order blockfile
     pass
   - interrupted `-blockfilterindex -reindex` restart followed by a clean
     later startup that reopens, rather than wipes, the existing blockfilter
     LevelDB
   Minimum validation target:
   - `python3 test/functional/feature_reindex.py`
   Still deferred inside this suite:
   - init-time block-index failure recovery
   - immutable/read-only blockstore restart behavior
   - promotion into `pq_required`
21. `feature_reindex_init.py` now owns:
   - explicit removal of the on-disk `blocks/index` directory before startup
   - the exact init-time block-database failure message that instructs the
     operator to restart with `-reindex` or `-reindex-chainstate`
   - the current noninteractive reindex-acceptance recovery path
   - successful recovery back to height `200` after that init failure
   Minimum validation target:
   - `python3 test/functional/feature_reindex_init.py`
   Still deferred inside this suite:
   - broader restart-time reindex behavior
   - immutable/read-only blockstore restart behavior
   - promotion into `pq_required`
22. `feature_reindex_readonly.py` now owns:
   - forced creation of a second blk file under `-fastprune`
   - explicit read-only plus host-level immutable treatment of the first blk
     file when the local platform supports it
   - successful restart under `-reindex -fastprune` with the immutable/read-only
     blockstore
   - explicit `Reindexing finished` log confirmation
   - restoration of file mutability and permissions for cleanup
   Minimum validation target:
   - `python3 test/functional/feature_reindex_readonly.py`
   Still deferred inside this suite:
   - generic reindex behavior outside the immutable/read-only blockstore case
   - promotion into `pq_required`
23. `feature_assumevalid.py` now owns:
   - one handcrafted invalid-signature spend buried just over two weeks deep
   - rejection of that bad block at height `102` on the non-assumevalid node
   - acceptance of the full `2202`-block chain on the deeply buried
     assumevalid-enabled node
   - expected debug markers for disabling and re-enabling signature validation
   - rejection of the same bad block on the shallow assumevalid-enabled node
     when it is not buried deeply enough
   Minimum validation target:
   - `python3 test/functional/feature_assumevalid.py`
   Still deferred inside this suite:
   - assumeutxo snapshot loading and activation behavior
   - promotion into `pq_required`
24. `feature_assumeutxo.py` now owns:
   - regtest assumeutxo metadata anchors at heights `110`, `200`, and `299`
     for the live PQBTC harness
   - snapshot activation across the current prune/index node profiles
   - invalid snapshot-file, metadata, and chainstate rejection behavior under
     the current PQBTC snapshot contents
   - one dedicated clean-node non-empty-mempool rejection using PQ-safe raw
     `P2WSH` funding instead of inherited wallet signing
   - one explicit snapshot-only inherited MiniWallet spend negative control
     rejected with `scriptpubkey (-26)`
   - restart, `-reindex`, `-reindex-chainstate`, and assumeutxo-node IBD sync
     behavior under the same fixed snapshot dataset
   Minimum validation target:
   - `python3 test/functional/feature_assumeutxo.py`
   Still deferred inside this suite:
   - wallet behavior during assumeutxo background sync
   - inherited MiniWallet mempool acceptance rehabilitation
25. `wallet_assumeutxo.py` now owns:
   - a wallet-side assumeutxo background-sync contract on top of the current
     regtest assumeutxo anchors
   - direct-mined pre-snapshot and post-snapshot MiniWallet funding that keeps
     the chain aligned with the current assumeutxo snapshot metadata
   - restoration of a snapshot-height backup during background sync
   - rejection of a pre-snapshot backup during background sync with the current
     bounded wallet-loading error
   - descriptor import and `rescanblockchain` failure while historical blocks
     remain unavailable during background sync
   - eventual restore/import success and final owned balances of `34` and
     `340` after background validation completes
   Minimum validation target:
   - `python3 test/functional/wallet_assumeutxo.py`
   Still deferred inside this suite:
   - broad inherited MiniWallet mempool acceptance
26. Recommended next PR after this tranche:
   - preferred: `feature_coinstatsindex_compatibility.py`
   - alternate: broader inherited miniscript funding/finalization rehab
   - broader wallet alternate: broader inherited classical multisig
     PSBT/finalization rehab
   Why next:
   - `feature_coinstatsindex_compatibility.py` is the remaining nearby
     chainstate/index follow-on now that both assumeutxo slices are frozen
   - broader inherited wallet rehab remains useful, but it is no longer the
     adjacency-first next step unless local assets for compatibility coverage
     are unavailable
19. Use `FEATURE_BLOCK_POSTURE.md` as the fixed note for the current
   `feature_block.py` contract.
20. Use `PSBT_REPLACEMENT_TRANCHE.md` as the current owned miniscript/PSBT
   carveout note.
21. Use `PQ_DESCRIPTOR_WATCHONLY_CONTRACT.md` as the fixed public descriptor
   contract.
22. Use `CREATEMULTISIG_POSTURE.md` as the fixed note for the current
   `rpc_createmultisig.py` contract.
23. Use `FEATURE_BLOCKSDIR_POSTURE.md` as the fixed note for the current
   `feature_blocksdir.py` contract.
24. Use `FEATURE_BLOCKSXOR_POSTURE.md` as the fixed note for the current
   `feature_blocksxor.py` contract.
25. Use `FEATURE_FASTPRUNE_POSTURE.md` as the fixed note for the current
   `feature_fastprune.py` contract.
26. Use `FEATURE_REMOVE_PRUNED_FILES_ON_STARTUP_POSTURE.md` as the fixed note
   for the current `feature_remove_pruned_files_on_startup.py` contract.
27. Use `FEATURE_INDEX_PRUNE_POSTURE.md` as the fixed note for the current
   `feature_index_prune.py` contract.
28. Use `FEATURE_PQ_BLOCK_LIMITS_POSTURE.md` as the fixed note for the current
   `feature_pq_block_limits.py` contract.
29. Use `FEATURE_PQ_REORG_POSTURE.md` as the fixed note for the current
   `feature_pq_reorg.py` contract.
30. Use `MEMPOOL_PQ_LIMITS_POSTURE.md` as the fixed note for the current
   `mempool_pq_limits.py` contract.
31. Use `MEMPOOL_PQ_STRESS_POSTURE.md` as the fixed note for the current
   `mempool_pq_stress.py` contract.
32. Use `FEATURE_PQSIG_BASIC_POSTURE.md` as the fixed note for the current
   `feature_pqsig_basic.py` contract.
33. Use `FEATURE_PQSIG_MULTISIG_POSTURE.md` as the fixed note for the current
   `feature_pqsig_multisig.py` contract.
34. Use `FEATURE_LOADBLOCK_POSTURE.md` as the fixed note for the current
   `feature_loadblock.py` contract.
35. Use `WALLET_MINISCRIPT_POSTURE.md` as the fixed note for the current
   `wallet_miniscript.py` contract.
36. Use `FEATURE_UTXO_SET_HASH_POSTURE.md` as the fixed note for the current
   `feature_utxo_set_hash.py` contract.
37. Use `FEATURE_COINSTATSINDEX_POSTURE.md` as the fixed note for the current
   `feature_coinstatsindex.py` contract.
38. Use `FEATURE_REINDEX_POSTURE.md` as the fixed note for the current
   `feature_reindex.py` contract.
39. Use `FEATURE_REINDEX_INIT_POSTURE.md` as the fixed note for the current
   `feature_reindex_init.py` contract.
40. Use `FEATURE_REINDEX_READONLY_POSTURE.md` as the fixed note for the current
   `feature_reindex_readonly.py` contract.
41. Use `FEATURE_ASSUMEVALID_POSTURE.md` as the fixed note for the current
   `feature_assumevalid.py` contract.
42. Use `FEATURE_ASSUMEUTXO_POSTURE.md` as the fixed note for the current
   `feature_assumeutxo.py` contract.
43. Use `WALLET_ASSUMEUTXO_POSTURE.md` as the fixed note for the current
   `wallet_assumeutxo.py` contract.
29. Treat inherited `getnewaddress` / `getrawchangeaddress` as unsupported on
   PQ-only active-manager wallets; the owned PQ address UX remains
   `getnewpqaddress` / `getrawpqchangeaddress`.
30. Treat `createwalletdescriptor` as an inherited xpub builder, not a PQ-native
   wallet-manager creation path under the all-PQ Track A stance.
31. Use `GENESIS_AND_NETWORK_POSTURE.md` as the launch-level interpretation for
   a fresh block-0 chain with its own network identity.
32. Keep the owned `rpc_psbt.py` subset and the non-signing decaying miniscript
   carveout separate from inherited classical PSBT rehabilitation.
33. Use `PQ_WALLET_MANAGER_SETUP.md` as the current setup-path contract for
   active PQ receive/change managers.
34. Use `CREATEWALLETDESCRIPTOR_POSTURE.md` to keep inherited descriptor
    creation separate from the PQ-native creation path.
35. Use `TEST_COST_POSTURE.md` to choose the cheapest defensible validation tier
    for each tranche before running tests.
36. Re-run and inspect the current required PQ-first functional gate strategy at
    a targeted level.
37. Reproduce the current `OPS_SLO` evidence flow only when the work has
    actually reached milestone-evidence scope.

## Autonomous Scope

Aineko may do these without asking:

- read code, tests, and docs in this repo
- tighten or add strategy/status docs
- rank backlog items and propose tranche scope
- run low-cost targeted tests and validation commands
- update this file with decisions, results, and blockers

Aineko must ask before:

- consensus-rule changes
- broad signature-stack changes or cryptographic-family pivots
- destructive actions
- long expensive build/test campaigns
- public claims, releases, or external messaging
- changing the Track A thesis itself

## Phase 1 Deliverables

- first tranche named
- tranche semantics written down
- backlog ranking tightened
- current gate health summarized
- ops evidence path sanity-checked

## Reference Pack

- `TRACK_A_NATIVE_PQ_BITCOIN.md`
- `TRACK_A_90_DAY_ROADMAP.md`
- `SHRINCS_DECISION_TRACK.md`
- `PQSIG_PROFILE_COMPARISON.md`
- `GENESIS_AND_NETWORK_POSTURE.md`
- `RESEARCH_INDEX.md`
- `PSBT_REPLACEMENT_TRANCHE.md`
- `PQ_DESCRIPTOR_WATCHONLY_CONTRACT.md`
- `PQ_WALLET_MANAGER_SETUP.md`
- `PQ_ADDRESS_RPC_POSTURE.md`
- `CREATEWALLETDESCRIPTOR_POSTURE.md`
- `FEATURE_BLOCKSXOR_POSTURE.md`
- `FEATURE_FASTPRUNE_POSTURE.md`
- `FEATURE_REMOVE_PRUNED_FILES_ON_STARTUP_POSTURE.md`
- `FEATURE_INDEX_PRUNE_POSTURE.md`
- `FEATURE_PQ_BLOCK_LIMITS_POSTURE.md`
- `FEATURE_PQ_REORG_POSTURE.md`
- `MEMPOOL_PQ_LIMITS_POSTURE.md`
- `MEMPOOL_PQ_STRESS_POSTURE.md`
- `TEST_COST_POSTURE.md`
- `POST_RC_EPICS.md`
- `CI_COMPLETENESS.md`
- `TAPROOT_MIGRATION_MATRIX.md`
- `OPS_SLO.md`

## Decision Log

- 2026-04-06: Track A confirmed as the repo anchor. No Liquid/Simplicity reset.
- 2026-04-13: `SHRINCS_DECISION_TRACK.md` added to keep SHRINCS-family
  evaluation explicit but separate: the repo can study or benchmark a future
  profile in parallel, but the active Track A execution baseline remains
  `PQSig rc2` until a dedicated go / no-go decision says otherwise.
- 2026-04-13: `PQSIG_PROFILE_COMPARISON.md` added as the first concrete
  decision memo: the active launch recommendation remains `PQSig rc2`, a
  SHRINCS-style profile is the main pre-launch comparison target, and
  SHRIMPS-style work stays a later compact-signature lane until wallet,
  recovery, and implementation costs are made concrete.
- 2026-04-06: Launch posture clarified: PQBTC is intended as a fresh chain
  starting at block 0, not as a retrofit onto inherited Bitcoin history.
- 2026-04-06: `GENESIS_AND_NETWORK_POSTURE.md` added to freeze the practical
  launch interpretation of that thesis: new history, new network identity, no
  assumed Bitcoin UTXO inheritance, and no obligation to preserve broad
  classical wallet compatibility by default.
- 2026-04-06: Initial ninety-day roadmap added.
- 2026-04-06: First owned tranche chosen: `rpc_psbt.py` / PQ-native PSBT semantics.
- 2026-04-06: `PSBT_REPLACEMENT_TRANCHE.md` added as the tranche semantics note.
- 2026-04-06: Follow-on queue tightened: `wallet_pq_descriptors.py` ahead of `wallet_createwalletdescriptor.py`, with address/miniscript surfaces later.
- 2026-04-06: Targeted confidence pass: `pqsig_script_tests` passed, `wallet_pq_psbt.py` passed, `rpc_psbt.py` failed at `finalizepsbt` with `Signature is not a valid encoding`.
- 2026-04-06: Root cause narrowed: `src/script/interpreter.cpp` currently makes
  `CheckSignatureEncoding()` PQ-only for all pre-taproot paths, so classical
  PSBT `partial_sigs` created for `pkh(...)` inputs decode-fail even when the
  wallet signs them correctly.
- 2026-04-06: Track A stance confirmed as all-PQ. Restoring inherited
  classical PSBT decode/finalize compatibility is not current owned work.
- 2026-04-06: Fixed watch-only `pq(...)` descriptor contract confirmed with
  both unit and functional coverage; `wallet_createwalletdescriptor.py` is now
  the next descriptor-facing follow-on.
- 2026-04-06: `wallet_createwalletdescriptor.py` verified green, but confirmed
  as inherited xpub-to-`wpkh/tr` descriptor creation rather than a PQ-native
  creation path.
- 2026-04-06: Recommended direction: keep PQ wallet-manager creation on the
  dedicated `pqpriv(...)` path for now instead of overloading the inherited
  `createwalletdescriptor` RPC early.
- 2026-04-06: Active `pqpriv(...)` manager coverage now explicitly rejects both
  inherited `bech32` and `bech32m` `createwalletdescriptor` paths as HD-xpub
  creation flows, including after backup/restore.
- 2026-04-06: `createwalletdescriptor` now returns a PQ-specific error on
  PQ-only wallets instead of the generic HD-key ambiguity message.
- 2026-04-06: Dedicated `createpqwalletmanagers` RPC landed for PQ-native
  receive/change setup on descriptor wallets with no active managers.
- 2026-04-06: `wallet_pq_active_ranged.py` now covers the dedicated setup RPC
  directly.
- 2026-04-06: `wallet_pq_psbt.py` now runs the main PQ-native PSBT path through
  `createpqwalletmanagers`, while retaining one lower-level `importdescriptors`
  check so raw `pqpriv(...)` setup stays exercised.
- 2026-04-08: `wallet_pq_psbt.py` now also covers `fundrawtransaction` on a
  PQ-only wallet, freezing the current expectation that automatic change stays
  on the active internal `pqpriv(...)` manager rather than re-entering
  inherited change-address semantics.
- 2026-04-08: `wallet_pq_psbt.py` now also covers automatic-input
  `walletcreatefundedpsbt` on a PQ-only wallet, freezing the current
  expectation that the PSBT funding path keeps automatic change on the active
  internal `pqpriv(...)` manager and emits one PQ proprietary partial-signature
  field per funded PQ input.
- 2026-04-08: The same PQ-owned `walletcreatefundedpsbt` tranche now covers the
  `changePosition` and `subtractFeeFromOutputs` option edges, with automatic PQ
  change still staying on the active internal `pqpriv(...)` manager.
- 2026-04-08: `wallet_pq_create_tx.py` now owns the narrow PQ-only direct
  wallet create-tx posture: inherited anti-fee-sniping stays in force on
  `sendtoaddress`, old tips keep `locktime = 0`, recent tips keep
  `0 < locktime <= height`, and the current wallet tx version stays `2`.
- 2026-04-08: `wallet_pq_send.py` now owns the narrow PQ-only `send` RPC
  posture: default recent-tip anti-fee-sniping stays in force, an explicit
  `locktime = 0` override disables it, and the current wallet tx version stays
  `2`.
- 2026-04-08: `wallet_pq_sendall.py` now owns the narrow PQ-only `sendall`
  RPC posture: default recent-tip anti-fee-sniping stays in force, an explicit
  `locktime = 0` override disables it, and the current wallet tx version stays
  `2`.
- 2026-04-08: `wallet_pq_sendmany.py` now owns the narrow PQ-only `sendmany`
  RPC posture: default anti-fee-sniping stays in force, the current wallet tx
  version stays `2`, and one multi-recipient `subtractfeefrom` edge is now
  owned in the required PQ gate.
- 2026-04-08: `wallet_pq_descriptors.py` now owns the fixed watch-only
  `pq(...)` descriptor boundary strongly enough for the required PQ gate:
  import/introspection, reload persistence, watch-only tracking, and a
  non-signing PSBT-preparation path with no PQ proprietary partial signatures.
- 2026-04-08: Wallet RPC metadata now exposes an explicit
  `has_private_keys` field on `getaddressinfo` and `listunspent`, so fixed
  public `pq(...)` descriptors and active `pqpriv(...)` managers no longer
  need to overload deprecated `iswatchonly` / `spendable` fields to express
  signing capability.
- 2026-04-09: Remaining-slice map refreshed after the send-path / CI and CLI
  hotfix work. Recommended next PR is a docs-only Track A strategy and
  launch-posture pack in `docs/TRACK_A_NATIVE_PQ_BITCOIN.md`,
  `docs/TRACK_A_90_DAY_ROADMAP.md`,
  `docs/GENESIS_AND_NETWORK_POSTURE.md`, `docs/RESEARCH_INDEX.md`,
  `docs/PSBT_REPLACEMENT_TRANCHE.md`, `docs/TEST_COST_POSTURE.md`,
  `docs/TRACK_A_STATUS.md`, `docs/README_PQBTC.md`, `docs/Spec.md`, and
  `docs/DECISION_DEFERRAL_LEDGER.md`, with minimum validation limited to
  doc-only review and repo-relative links. Product identity/Qt naming work,
  `OPS_SLO` evidence/artifact updates, broad inherited address-type rehab, and
  inherited classical PSBT compatibility remain deferred.
- 2026-04-10: After merging the docs, identity, and `OPS_SLO` slices and
  resyncing the old dirty worktree to current `main`, no further real tranche
  remained in that worktree. The next clean owned slice is now a PQ-specific
  `signrawtransactionwithwallet` contract, implemented as a dedicated
  `wallet_pq_signrawtransaction.py` surface plus a matching posture doc and PQ
  gate/inventory updates. Broad inherited `wallet_signrawtransactionwithwallet`
  and `wallet_fundrawtransaction` rehab remain deferred.
- 2026-04-11: The next owned wallet surface remains a PQ-specific
  `signrawtransactionwithwallet` slice: direct wallet-owned raw spends,
  default/`ALL` parity, explicit non-`ALL` rejection, and fixed PQ witness
  shape, without reopening the broad inherited raw-signing matrix.
- 2026-04-11: The PQ-only raw-signing slice is now owned explicitly through
  `wallet_pq_signrawtransaction.py` and
  `PQ_WALLET_SIGNRAWTRANSACTION_POSTURE.md`, with required-gate promotion in
  `pq_functional_tests.txt` and `functional_suite_inventory.json`. The next
  wallet follow-on should extend active PQ manager restore semantics rather
  than reopening the inherited raw-signing matrix.
- 2026-04-12: Active PQ manager restore semantics now explicitly include
  restored keypool continuity and post-restore automatic PQ change on the
  restored internal manager. With the owned `rpc_psbt.py` PQ subset now
  frozen, the next clean Track A wallet follow-on shifts to the
  `wallet_createwalletdescriptor.py` boundary.
- 2026-04-12: `wallet_createwalletdescriptor.py` now freezes the inherited
  xpub-only boundary directly: inherited `bech32` / `bech32m` descriptor
  creation stays green, PQ-only active-manager wallets reject both families
  without mutating descriptor or manager state, and the next clean wallet
  follow-on shifts to `wallet_address_types.py`.
- 2026-04-12: `wallet_address_types.py` now freezes the inherited address-RPC
  boundary directly: low-risk inherited address-shape smoke coverage stays
  green, PQ-only active-manager wallets reject inherited `getnewaddress` /
  `getrawchangeaddress` across valid inherited address types including
  `bech32m`, and one explicit `sendmany` negative control keeps broad
  inherited classical send/sign compatibility deferred. The next clean wallet
  follow-on shifts to `wallet_miniscript_decaying_multisig_descriptor_psbt.py`.
- 2026-04-12: `feature_blocksxor.py` now freezes the narrow XORed block-file
  integrity boundary directly: deterministic mining replaces the inherited
  MiniWallet setup path, mined blk/rev files can be manually un-XORed with the
  stored key, `-blocksxor=0` restart stays blocked until that key is deleted,
  and full-chain `verifychain(checklevel=2, nblocks=0)` passes after the
  restart. The next adjacent storage follow-on shifts to `feature_fastprune.py`.
- 2026-04-12: `feature_fastprune.py` now freezes the narrow `-fastprune`
  large-block admission boundary directly: one large-annex block assembled
  through the non-signing MiniWallet `ADDRESS_OP_TRUE` path is accepted and
  advances the initialized chain to height 201 without crash or hang. The next
  adjacent prune follow-on shifts to
  `feature_remove_pruned_files_on_startup.py`.
- 2026-04-12: `feature_remove_pruned_files_on_startup.py` now freezes the
  prune-lifecycle cleanup boundary directly: prune-triggered blk/rev deletion,
  explicit platform-specific open-file behavior, restart cleanup after closing
  file descriptors, and `-reindex` recreation of a fresh blk/rev baseline all
  remain green under `-fastprune -prune=1`. The next remaining prune follow-on
  shifts to `feature_index_prune.py`.
- 2026-04-12: `feature_index_prune.py` now freezes the prune-plus-index matrix
  directly: blockfilter/coinstats indices remain usable before and after prune,
  exact prune-to-index-height restart continuity remains valid, prune-past-index
  restart fails until `-reindex`, and the reorg prune-lock path stays explicit.
  The next cheapest block-facing follow-on shifts to
  `feature_pq_block_limits.py`.
- 2026-04-12: `feature_pq_block_limits.py` now freezes the PQBTC launch block
  profile ceiling directly: `getblocktemplate` weightlimit remains
  `16_000_000`, exact-ceiling `-blockmaxweight` restarts stay valid, over-ceiling
  startup fails at `16000001`, and the node still mines after returning to the
  allowed limit. The next adjacent PQ-native chainstate follow-on shifts to
  `feature_pq_reorg.py`.
- 2026-04-12: `feature_pq_reorg.py` now freezes the PQ-native reorg/mempool
  reconciliation surface directly: a mined PQ spend is reinserted after a
  competing longer branch wins, restart-before-reconnect remains valid, the
  spend is remined on the final winning branch, and the SLO recorder completes
  successfully for the scenario. The next cheapest adjacent mempool follow-on
  shifts to `mempool_pq_limits.py`.
- 2026-04-12: `mempool_pq_limits.py` now freezes the single-node PQ-native
  mempool policy boundary directly: PQ signature-size checks, witness-item size
  checks, restart-stable oversized-witness reject reasons, large-witness RBF
  churn, and restart persistence all remain green. The next adjacent higher-
  churn mempool follow-on shifts to `mempool_pq_stress.py`.
- 2026-04-13: `mempool_pq_stress.py` now freezes the two-node PQ-native
  relay/mempool stress surface directly: witness-heavy RBF replacements and the
  broader spend batch relay across both nodes, survive restart on the receiving
  node, clear when mined, and restore/clear again across invalidate/reconsider.
  The next cheapest adjacent signing follow-on shifts to
  `feature_pqsig_basic.py`.
- 2026-04-13: `feature_pqsig_basic.py` now freezes the minimal PQ
  single-signature validation surface directly: a wallet-funded PQ CHECKSIG
  P2WSH witness is admitted when valid, truncated and tampered witnesses are
  rejected at mempool admission, and the accepted spend confirms successfully.
  The next adjacent signing follow-on shifts to `feature_pqsig_multisig.py`.
- 2026-04-13: `feature_pqsig_multisig.py` now freezes the minimal PQ 2-of-2
  multisignature validation surface directly: a wallet-funded PQ CHECKMULTISIG
  P2WSH witness is admitted when both signatures are valid, a tampered witness
  is rejected at mempool admission, and the accepted multisignature spend
  confirms successfully. The next clean import/bootstrap follow-on shifts to
  `feature_loadblock.py`.
- 2026-04-13: `feature_loadblock.py` now freezes the PQBTC bootstrap/import
  surface directly: linearization uses the live regtest message-start bytes,
  produces `bootstrap.dat` from the source node's block files, and an unsynced
  peer restarted with `-loadblock` imports to height `100` and converges on the
  same best block hash. The next owned follow-on shifts back to a dedicated
  `wallet_miniscript.py` funding/signing tranche.
- 2026-04-13: `wallet_miniscript.py` now freezes a miniscript
  funding/signing boundary directly: the prior static watch-only carveout stays
  intact, one wallet-local xprv-backed miniscript import plus direct coinbase
  funding creates a real spendable signer UTXO, `walletprocesspsbt(sign=false)`
  fills witness data without signatures, `walletprocesspsbt(finalize=false)`
  adds exactly one classical-looking `partial_sig`, and node-side
  decode/finalize of that signed PSBT now fails explicitly at the PQ-only
  signature-encoding wall. The next owned follow-on shifts to one
  chainstate/validation tranche, with broader inherited miniscript
  funding/finalization rehab remaining alternate.
- 2026-04-13: `feature_utxo_set_hash.py` now freezes the first dedicated
  txoutset-hash chainstate slice directly: the suite no longer depends on the
  inherited Taproot-shaped MiniWallet self-transfer path, one raw `OP_TRUE`
  self-transfer is mined directly by `generateblock(...)`, manual MuHash still
  matches `gettxoutsetinfo("muhash")`, and the PQBTC deterministic
  `hash_serialized_3` / `muhash` constants are now fixed for that sequence. The
  next owned follow-on shifts to `feature_coinstatsindex.py`, with
  `feature_reindex.py` as the lower-risk chainstate alternate.
- 2026-04-13: `feature_coinstatsindex.py` now freezes the adjacent
  txoutset/index slice directly: the suite replaces the inherited default
  MiniWallet mempool path with direct-mined raw `OP_TRUE` transactions, keeps
  the indexed/non-indexed `gettxoutsetinfo()` comparisons and verbose
  `block_info` accounting intact, and preserves restart, reorg, and reindex
  behavior on that owned dataset. The next owned follow-on shifts to
  `feature_reindex.py`, with `feature_coinstatsindex_compatibility.py` as the
  environment-dependent alternate.
- 2026-04-13: `feature_reindex.py` now freezes the adjacent restart/reindex
  slice directly: repeated `-reindex` and `-reindex-chainstate` restarts return
  to the same height, manual out-of-order blk-file swapping still recovers the
  full chain with the expected debug markers, and an interrupted
  `-blockfilterindex -reindex` run later resumes without wiping the existing
  blockfilter LevelDB. The next owned follow-on shifts to
  `feature_reindex_init.py`, with `feature_reindex_readonly.py` as the
  environment-sensitive alternate.
- 2026-04-13: `feature_reindex_init.py` now freezes the adjacent init-failure
  recovery slice directly: removing `blocks/index` triggers the exact expected
  startup failure with reindex guidance, and the current noninteractive
  recovery flag returns the node to height `200`. The next owned follow-on
  shifts to `feature_reindex_readonly.py`, with
  `feature_coinstatsindex_compatibility.py` as the environment-dependent
  alternate.
- 2026-04-13: `feature_reindex_readonly.py` now freezes the adjacent
  immutable/read-only blockstore restart slice directly: under `-fastprune`,
  the first blk file is made read-only and locally immutable, restart with
  `-reindex -fastprune` completes successfully with the expected
  `Reindexing finished` marker, and the chain returns to the same height. The
  next owned follow-on shifts to `feature_assumevalid.py`, with
  `feature_coinstatsindex_compatibility.py` as the environment-dependent
  alternate.
- 2026-04-14: `feature_assumevalid.py` now freezes the adjacent assumevalid
  validation slice directly: the invalid-signature block is rejected without
  assumevalid, accepted when it is buried deeply enough under assumevalid, and
  still rejected when it is not buried deeply enough. The next owned follow-on
  shifts to `feature_assumeutxo.py`, which now fails on the inherited default
  MiniWallet `scriptpubkey (-26)` path.
- 2026-04-14: `feature_assumeutxo.py` now freezes the adjacent snapshot
  activation slice directly: regtest assumeutxo metadata is committed for
  heights `110`, `200`, and `299`, snapshot activation/restart/reindex stays
  green under the current harness, and the inherited snapshot-only MiniWallet
  spend is now an explicit `scriptpubkey (-26)` negative control. The next
  owned follow-on shifts to `wallet_assumeutxo.py`, with
  `feature_coinstatsindex_compatibility.py` remaining the
  environment-dependent alternate.
- 2026-04-14: `wallet_assumeutxo.py` now freezes the adjacent wallet-side
  assumeutxo slice directly: inherited MiniWallet funding is replaced with
  direct-mined transactions that preserve the current snapshot chain, the
  snapshot-height backup remains restorable during background sync, the older
  backup and rescans remain blocked until validation completes, and final owned
  balances still settle to `34` and `340`. The next owned follow-on shifts to
  `feature_coinstatsindex_compatibility.py`, with broader inherited miniscript
  funding/finalization rehab remaining the local wallet alternate.
- 2026-04-14: `feature_assumeutxo.py` and `wallet_assumeutxo.py` are now
  promoted into the canonical `pq_required` gate. The current required PQ path
  therefore covers both snapshot activation and the adjacent wallet-side
  background-sync contract on the live regtest assumeutxo anchors. The next
  owned follow-on remains `feature_coinstatsindex_compatibility.py`, while
  `feature_assumevalid.py` remains the nearby validation-side gate candidate.
- 2026-04-06: Full `OPS_SLO` evidence bundle refreshed at
  `docs/artifacts/ops-slo/2026-04-06` and validated at signoff.
- 2026-04-06: Targeted `OPS_SLO` sanity check completed without running the full
  soak capture. The frozen `2026-03-30` bundle still validates at sign-off, the
  validator self-test passes, and a live `mempool_pq_limits.py` run still emits
  the expected summary contract with `pass=true`, `crash_assert_hang=false`, and
  stable restart counts.
- 2026-04-06: Current targeted Track A gate snapshot is green for
  `wallet_pq_active_ranged.py`, `wallet_pq_psbt.py`,
  `wallet_pq_create_tx.py`, `wallet_pq_send.py`,
  `wallet_pq_sendall.py`, `wallet_pq_sendmany.py`,
  `wallet_pq_descriptors.py`,
  `wallet_createwalletdescriptor.py`, and `pqsig_script_tests`.
- 2026-04-06: PQ-only active wallets now reject inherited `getnewaddress` and
  `getrawchangeaddress` outright, including explicit legacy-style address-type
  requests, and direct operators to `getnewpqaddress` /
  `getrawpqchangeaddress` instead.
- 2026-04-06: `keypoolrefill` is now explicitly treated as a supported PQ
  maintenance path: on PQ-only active wallets it expands the receive/change
  `pqpriv(...)` ranges rather than acting as an inherited address-family UX.
- 2026-04-06: `wallet_address_types.py` remains an inherited `dual_profile`
  suite. Its current failure is still in classical `sendmany` signing flow, so
  broad address-type rehabilitation is not the owned Track A wallet milestone.
- 2026-04-06: Launch-facing operator identity is tighter on the main CLI/RPC
  path: `pqbtcd`, `pqbtc-wallet`, and `pqbtc-util` help/version output now use
  PQBTC naming, and wallet/RPC error/help strings now prefer `PQBTC address`,
  `pqbtc-wallet`, and `pqbtcd` over inherited Bitcoin tool names on the active
  operator surfaces.
- 2026-04-06: The same identity cleanup now extends across the active Qt
  source surfaces: `pqbtc-qt` entrypoint naming, PQBTC address/network wording,
  payment/request UI text, and GUI metadata no longer default to inherited
  Bitcoin branding on the main operator path. The current build tree does not
  have the Qt target enabled, so this pass is source-level verified rather than
  GUI-built in this environment.
- 2026-04-06: `TEST_COST_POSTURE.md` added to freeze the development rule that
  PQBTC should validate by tranche, not by tiny commit, and that expensive CI
  or soak work should be paid only at explicit promotion or sign-off boundaries.

## Blockers

- `rpc_psbt.py` currently fails in the inherited broad PSBT RPC surface at `finalizepsbt` with `Signature is not a valid encoding`.
- This is no longer just a hypothesis. The narrowed failing case spends
  classical `pkh(...)` coinbase-style inputs, and the resulting ECDSA-looking
  `partial_sigs` are rejected because global pre-taproot signature encoding
  validation now requires fixed-size PQ signatures.
- The owned PQ-native `pqpriv(...)` PSBT path is still healthy. The blocker is
  only for inherited classical compatibility surfaces. Under the current Track A
  stance, that legacy path stays explicitly deferred rather than restored.
- There is no current `OPS_SLO` blocker. The refreshed `2026-04-06` evidence
  bundle satisfies the frozen signoff thresholds.
