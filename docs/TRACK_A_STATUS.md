# PQBTC Track A Status

## Status: ACTIVE
## Spec-ID: TRACK-A-STATUS-v1
## Updated: 2026-07-18
## Current Phase: Phase 1 - Cryptographic Production Hold

## Purpose

Operational status for the ninety-day Track A plan.

This file is the working handoff for Aineko. When no more specific repo task is
active, use this file to choose the next safe step for `quantum-proof-bitcoin`.

## Current Objective

Preserve the completed CI inventory baseline while moving Track A onto an
explicit cryptographic production hold. The implemented rc2 path remains a
research and Bitcoin-integration fixture only; it must not be released to
secure real value or described as establishing its claimed `2^40` signing
budget or NIST Level 1 security. `PQSIG_PRODUCTION_READINESS.md` is the
controlling evidence and replacement-gate record.

The next implementation lane is isolated standards conformance: first a FIPS
205 `SLH-DSA-SHA2-128s` prototype, then a FIPS 204 `ML-DSA-44` comparator. No
inventory policy class, `ALG_ID`, Script rule, or consensus accepted set changes
as part of this safety closeout.

The first isolated reference slice is recorded in
`SLH_DSA_SHA2_128S_REFERENCE.md`. It pins NIST ACVP and portable-C source
commits, requires official keygen/sign/verify outcomes plus full byte agreement
between OpenSSL and `slhdsa-c`, and records initial arm64 timings without adding
either implementation to the node.

Keep the live `pq_required` gate aligned with the repo as it exists today. PR
`#163` closed the initial inventory tranche at `pq_required: 120`,
`pq_backlog: 0`, `legacy_only: 14`, and `dual_profile: 142`. Promotion Matrix
run `#106` (`29540363398`) then completed on `main` at merge commit
`f363c99d4ef40a822477eef84b3afecfc76329fc` with all `26/26` checks
successful on attempt 1.

PR `#166` then landed the bounded dual-profile risk review. It selected
`feature_config_args.py` because the launch-facing `pqbtc.conf` namespace had
no required functional owner, deferred `tool_bitcoin.py` pending a dedicated
issue and a bounded cross-platform contract, and rejected `rpc_blockchain.py`
because the required replacement-deployment suite already owns that evidence.
This separate slice promotes only `feature_config_args.py` under issue `#165`.
The resulting baseline is `pq_required: 121`, `pq_backlog: 0`,
`legacy_only: 14`, and `dual_profile: 141`.

PR `#171` landed the bounded issue `#170` follow-up inside that already
required gate at merge commit
`31afe4e0c12fd9ef1d0f0f86ded40164288f17a8`. It asserts the startup-reported
platform default data-directory namespace on Linux, macOS, and Windows while
retaining the explicit Windows boundary for tests that depend on synthetic
shell-folder environment overrides. Branch Promotion Matrix run `29617449196`
completed `21/21` jobs successfully; post-merge Promotion Matrix run
`29621132550` also completed `21/21` jobs successfully, and the merge commit
completed all `26/26` checks successfully. Issue `#170` is closed. The slice
changed no inventory policy class, so the reviewed baseline remains
`pq_required: 121`, `pq_backlog: 0`, `legacy_only: 14`, and
`dual_profile: 141`.

The current asset boundary is recorded in
[PREVIOUS_RELEASE_ASSET_BOUNDARY.md](PREVIOUS_RELEASE_ASSET_BOUNDARY.md). The
compatibility harness maps `280200` to `v28.2` and expects PQBTC-named
previous-release binaries at `releases/v28.2/bin/pqbtcd` and
`releases/v28.2/bin/pqbtc-cli` unless `PREVIOUS_RELEASES_DIR` points at an
equivalent layout. The source audit found no authentic PQBTC artifact matching
that contract; the available v1 tags identify as v30.2 and already use the
fixed coinstats-index path. The suite remains inherited reference coverage, not
a skipped candidate for promotion. The unsupported-UTXO suite has the same
provenance boundary: Track A does not support migrating a Bitcoin Core 0.14
datadir into the new PQBTC chain. Nor does it support upgrading from or
downgrading to Bitcoin Core v0.20.1 through a shared `mempool.dat` file. The
same boundary applies to loading, upgrading, downgrading, or migrating wallet
files across inherited Bitcoin Core v0.20.1 through v25.0 releases, including
the v28.2 BDB-to-descriptor migration contract in `wallet_migration.py`. All
tracked suites now have an explicit policy class and none remains in
`pq_backlog`.

## Current Working Thesis

- `quantum-proof-bitcoin` stays on Track A as a post-quantum Bitcoin research
  and integration project; production activation is held until a conformant,
  independently reviewed signature profile passes its release gates.
- Track A assumes PQBTC launches as a new chain at block 0, not as an in-place
  continuation of inherited Bitcoin chain history.
- Blockstream's Liquid/Simplicity work is a benchmark and adjacent migration
  reference, not a reason to reset the repo.
- The best progress in this window is one bounded CI/docs promotion slice at a
  time, not broad speculative redesign.

## Current Follow-On Candidates

Preferred next owned tranche:

1. Hold the reviewed post-promotion baseline
   - Why next: the selected configuration-namespace gap and its platform
     default-datadir follow-up are closed, all `276` tracked functional suites
     retain explicit policy classes, and `pq_backlog` remains empty.
   - `tool_bitcoin.py` remains deferred; its low runtime does not replace the
     missing dedicated issue and cross-platform/optional-IPC boundary.
   - `rpc_blockchain.py` remains rejected because its replacement-deployment
     evidence duplicates an existing required gate.
   - production release remains blocked independently of CI inventory status;
     green rc2 tests are regression evidence, not cryptographic approval.

Future selection boundary:

2. Run another bounded risk review only when new evidence identifies a
   launch-critical PQ confidence gap
   - record the affected PQ path, owner, open issue, bounded contract, targeted
     command, expected CI cost, and promotion/rejection criteria before any
     further policy-class change
   - do not select a suite from inventory order or low runtime alone

Cryptography implementation lane:

3. Build isolated final-standard reference prototypes
   - start with FIPS 205 `SLH-DSA-SHA2-128s`
   - compare FIPS 204 `ML-DSA-44`
   - require official vectors and an independent differential oracle
   - do not allocate or activate an `ALG_ID` in the prototype slices

## Current Queue

1. Preserve the reviewed post-promotion baseline:
   - `pq_required`: 121
   - `pq_backlog`: 0
   - `legacy_only`: 14
   - `dual_profile`: 141
   - selection evidence: PR `#166` and
     [TRACK_A_RISK_REVIEW.md](TRACK_A_RISK_REVIEW.md)
   - follow-up hardening: PR `#171`, closed issue `#170`, merge commit
     `31afe4e0c12fd9ef1d0f0f86ded40164288f17a8`, branch matrix `21/21`,
     post-merge matrix `21/21`, and merge-commit checks `26/26`, with no
     inventory policy-class change
   - owned contract:
     [FEATURE_CONFIG_ARGS_POSTURE.md](FEATURE_CONFIG_ARGS_POSTURE.md)
2. `HOLD`: do not infer another promotion from queue order. Require a fresh
   risk decision before changing another policy class.


## Historical Queue Ledger

Entries below are the tranche-by-tranche freeze ledger. Use Current Follow-On
Candidates above as the controlling live next-PR handoff when this historical
queue differs from the current repo-wide recommendation.

1. This slice freezes `wallet_miniscript_decaying_multisig_descriptor_psbt.py`
   as:
   - inherited xpub-backed decaying miniscript descriptor import as reference
     context for the live decaying wallet contract
   - inherited coordinator `sendtoaddress(...)` funding into the decaying
     multisig receive address
   - direct watch-only PSBT creation and serial signer participation across the
     decaying locktime loop
   - explicit non-final rejection before the required locktime is reached
   - successful finalization and broadcast after maturity with the expected
     signer decay from 4-of-4 to 1-of-4
   Minimum validation only:
   - `python3 test/functional/wallet_miniscript_decaying_multisig_descriptor_psbt.py`
   Stays deferred:
   - replacement-path TapMiniscript meaning
   - broader policy claims beyond the current functional harness contract
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
   - broader CI ownership decisions for chainstate-facing backlog beyond this
     fixed functional contract
3. `wallet_miniscript.py` now owns:
   - inherited miniscript sanity rejection coverage for insane and
     unsatisfiable descriptors
   - watch-only import, address derivation, and coin detection across the full
     current descriptor set, including the tracked `tr(...)` branches in-file
   - signer-backed import, funding, PSBT signing, finalization, and broadcast
     across the current satisfiable miniscript and TapMiniscript descriptor
     set
   - deliberate incomplete cases when the wallet lacks sufficient keys or when
     multiple leaves remain intentionally ambiguous
   - max-size TapMiniscript positive import/spend coverage plus one oversize
     negative-control import failure
   - explicit ranged xpub/tprv invalid-key negative controls, including one
     TapMiniscript xpub import boundary
   Minimum validation target:
   - `python3 test/functional/wallet_miniscript.py`
   Still deferred inside this suite:
   - replacement-path TapMiniscript activation or migration semantics
   - broader policy/relay claims beyond the current wallet harness
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
   - explicit node-side `decodepsbt`, subsequent signer processing,
     `combinepsbt`, `finalizepsbt`, and successful broadcast of that signed
     PSBT under the current DER-or-PQ pre-taproot signature rules
   Minimum validation target:
   - `python3 test/functional/wallet_multisig_descriptor_psbt.py`
   Still deferred inside this suite:
   - broader inherited coordinator funding/send-path rehab beyond this
     watch-only multisig contract
6. `feature_blocksdir.py` now owns:
   - missing `-blocksdir` init failure when the external path does not exist
   - successful external blk/rev storage under the chosen blocksdir with the
     local chain path retaining the block index
   - explicit no-fallback contract: the node datadir does not recreate a local
     `blocks/` directory while the external blocksdir is active
   - restart persistence with the same external blocksdir
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
   Still deferred inside this suite:
   - block-file mutation/corruption handling
   - broader bootstrap/loadblock import behavior
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
   - `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
   Still deferred inside this suite:
   - broader block-file corruption handling
   - generic reindex behavior beyond the current storage/prune gate
   - broader bootstrap/loadblock import behavior
8. `feature_fastprune.py` now owns:
   - startup under `-fastprune`
   - one large witness-annex block assembled through the non-signing
     `MiniWalletMode.ADDRESS_OP_TRUE` path
   - direct `generateblock(...)` acceptance for that large block without crash
     or hang
   - explicit chain-height advancement from the initialized 200-block harness
     to 201
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
   Still deferred inside this suite:
   - generic restart and reindex behavior beyond the current storage/prune gate
   - broader bootstrap/loadblock import behavior
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
   - `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
   Still deferred inside this suite:
   - broader index recovery outside the bounded prune-plus-index matrix
   - broader bootstrap/loadblock import behavior
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
   - `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
   Still deferred inside this suite:
   - broader bootstrap/loadblock import behavior
11. `feature_pq_block_limits.py` now owns:
   - exact `getblocktemplate` block weight limit reporting at `4_000_000`
   - exact-ceiling `-blockmaxweight=4000000` restart acceptance
   - explicit startup rejection for `-blockmaxweight=4000001`
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
   - `build/test/functional/test_runner.py --jobs=1 feature_loadblock.py`
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
   - `build/test/functional/test_runner.py --jobs=1 feature_utxo_set_hash.py`
   Still deferred inside this suite:
   - adjacent coinstats-index coverage
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
   - `build/test/functional/test_runner.py --jobs=1 feature_coinstatsindex.py`
   Still deferred inside this suite:
   - previous-release coinstats index compatibility
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
   - `build/test/functional/test_runner.py --jobs=1 feature_reindex.py`
   Still deferred inside this suite:
   - init-time block-index failure recovery
   - immutable/read-only blockstore restart behavior
21. `feature_reindex_init.py` now owns:
   - explicit removal of the on-disk `blocks/index` directory before startup
   - the exact init-time block-database failure message that instructs the
     operator to restart with `-reindex` or `-reindex-chainstate`
   - the current noninteractive reindex-acceptance recovery path
   - successful recovery back to height `200` after that init failure
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 feature_reindex_init.py`
   Still deferred inside this suite:
   - broader restart-time reindex behavior
   - immutable/read-only blockstore restart behavior
22. `feature_reindex_readonly.py` now owns:
   - forced creation of a second blk file under `-fastprune`
   - explicit read-only plus host-level immutable treatment of the first blk
     file when the local platform supports it
   - successful restart under `-reindex -fastprune` with the immutable/read-only
     blockstore
   - explicit `Reindexing finished` log confirmation
   - restoration of file mutability and permissions for cleanup
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 feature_reindex_readonly.py`
   Still deferred inside this suite:
   - generic reindex behavior outside the immutable/read-only blockstore case
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
26. `wallet_fundrawtransaction.py` now owns:
   - restored inherited raw transaction funding under the current
     legacy-compatible PQC profile
   - default `add_inputs` behavior and preset-input selection
   - fee, feerate, change-position, and subtract-fee-from-output behavior
   - inherited address/change-type handling exercised by the suite
   - watch-only and all-watched-funds funding
   - external-input funding with `solving_data` and explicit input weights
   - transaction-size limits, duplicate outputs, unsafe-input controls, and
     input confirmation controls
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_fundrawtransaction.py`
   Still deferred inside this suite:
   - replacement-path Taproot or bech32m wallet semantics beyond existing tests
27. `wallet_send.py`, `wallet_sendall.py`, and `wallet_sendmany.py` now own:
   - restored inherited send RPC behavior under the current legacy-compatible
     PQC profile
   - destination sends, no-broadcast and PSBT creation, OP_RETURN outputs,
     fee/feerate and confirmation-target options, manual inputs and change
     controls, locktime, RBF, subtract-fee-from-output, unsafe/minconf handling,
     external-input solving data, and transaction weight limits
   - full-balance `sendall` sweeps, split recipients, specified outputs,
     invalid recipient/amount handling, send_max, specific inputs, watch-only
     PSBT creation, minconf/maxconf, anti-fee-sniping, unconfirmed
     input/change behavior, ancestor-aware funding, and too-large transaction
     errors
   - inherited `sendmany` subtract-fee-from-output validation for duplicate,
     missing, negative, out-of-bounds, invalid-type, and mixed
     destination/index cases
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_send.py wallet_sendall.py wallet_sendmany.py`
   Still deferred inside these suites:
   - replacement-path Taproot or bech32m wallet semantics beyond existing tests
   - new PQ-only active-manager RPC behavior
28. `wallet_resendwallettransactions.py` now owns:
   - restored inherited wallet transaction rebroadcast behavior under the
     current legacy-compatible PQC profile
   - initial wallet transaction announcement to peers
   - delayed rebroadcast timing after a sufficiently later block
   - scheduler-triggered `MaybeResendWalletTxs` resubmission
   - no early rebroadcast inside the first twelve-hour window
   - rebroadcast after the upper resend timer bound
   - parent-before-child rebroadcast for unconfirmed wallet transaction chains
   - resubmission after wallet transactions are evicted from the mempool
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_resendwallettransactions.py`
   Still deferred inside this suite:
   - wallet fast-rescan, unconfirmed-rescan, or reorg-restore semantics
29. `wallet_reindex.py` now owns:
   - restored inherited wallet reindex interaction under the current
     legacy-compatible PQC profile
   - watch-only descriptor import with `timestamp=now` missing an older
     transaction before explicit rescan
   - descriptor wallet birthtime adjustment to the chain MTP rescan window
   - explicit `rescanblockchain` detection of the previously missed
     transaction
   - `-reindex=1` restart completion while the wallet remains load-on-startup
   - confirmed wallet transaction survival after reindex
   - descriptor wallet birthtime convergence to the transaction time after
     reindex
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_reindex.py`
   Still deferred inside this suite:
   - broader wallet reorg-restore semantics
   - wallet backup/restore compatibility beyond existing PQ-owned backup
     coverage
30. `wallet_fast_rescan.py` now owns:
   - restored inherited descriptor-wallet fast-rescan behavior under the
     current legacy-compatible PQC profile
   - ranged descriptor end-range address derivation and top-up detection
   - fixed non-ranged descriptor funding detection
   - block-filter fast rescan during wallet backup restore and non-active
     descriptor import
   - slow full-block rescan during wallet backup restore and non-active
     descriptor import when block filters are disabled
   - parity between fast and slow rescan transaction discovery
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_fast_rescan.py`
   Still deferred inside this suite:
   - broader wallet backup/restore and transaction-time rescan semantics
   - wallet backup/restore compatibility beyond the fast-rescan backup fixture
31. `wallet_rescan_unconfirmed.py` now owns:
   - restored inherited descriptor-wallet unconfirmed-rescan behavior under the
     current legacy-compatible PQC profile
   - confirmed parent transaction creation in a block that is later
     disconnected
   - child `sendall` sweep creation without a wallet change output
   - mocked reorg that returns the parent transaction to the mempool after its
     child
   - descriptor import into a watch-only wallet after both transactions are in
     the mempool
   - watched parent address recognition as solvable and `ismine`
   - rescan detection of the re-entered unconfirmed parent and unconfirmed
     child
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_rescan_unconfirmed.py`
   Still deferred inside this suite:
   - broader wallet backup/restore and transaction-time rescan semantics
   - wallet backup/restore compatibility beyond existing PQ-owned backup
     coverage
32. `wallet_reorgsrestore.py` now owns:
   - restored inherited wallet reorg-restore behavior under the current
     legacy-compatible PQC profile
   - confirmed wallet transaction status restoration after wallet reload on a
     longer chain
   - restored confirmations with a different block hash after reorg
   - conflicted wallet transaction recovery when the formerly conflicted
     transaction becomes confirmed on the longer chain
   - startup abandonment of orphaned coinbase transactions and descendants
   - trusted-balance reset after orphaned coinbase abandonment
   - unclean-shutdown restart rescan after an invalidated block was not flushed
     to disk
   - duplicate block-disconnection tolerance across a follow-up reorg
   - abandon/un-abandon consistency across `invalidateblock` and
     `reconsiderblock`
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_reorgsrestore.py`
   Still deferred inside this suite:
   - broader wallet backup/restore compatibility
33. `wallet_transactiontime_rescan.py` now owns:
   - restored inherited wallet transaction-time rescan behavior under the
     current legacy-compatible PQC profile
   - watch-only descriptor imports for three received transactions separated
     by mock-time intervals
   - original transaction `blocktime` and wallet `time` matching the block
     times at initial detection
   - wallet restoration with `timestamp=now` descriptors starting with no
     detected historical transactions
   - idle `abortrescan` returning `false`
   - partial-history rescan followed by full-history rescan
   - restored balance, transaction count, and transaction times after full
     rescan
   - invalid `rescanblockchain` start/stop height rejection
   - locked encrypted wallet rescan rejection until unlock
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_transactiontime_rescan.py`
   Still deferred inside this suite:
   - broader wallet backup/restore compatibility
34. `wallet_backup.py` now owns:
   - restored inherited wallet backup/restore behavior under the current
     legacy-compatible PQC profile
   - multi-wallet transaction churn before and after `backupwallet`
   - restored wallet balances matching pre-restore balances after later
     transactions and fee-maturity mining
   - invalid and missing backup-file rejection without creating target wallets
   - existing wallet-name restore rejection without overwriting the destination
   - restore into existing empty directories, directories containing non-wallet
     files, and unnamed default wallets
   - backup-to-source-path failure for file, directory, and equivalent path
     forms
   - pruned-node restore success near the prune height and failure when backup
     synchronization goes beyond pruned data
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_backup.py`
   Still deferred inside this suite:
   - broader wallet backwards-compatibility and migration semantics
35. `wallet_startup.py` now owns:
   - restored inherited wallet startup and load-on-startup behavior under the
     current legacy-compatible PQC profile
   - node startup with no wallets loaded and an empty wallet directory
   - unnamed default wallet auto-load after restart when no other wallets exist
   - `createwallet(..., load_on_startup=true)` persistence across restart
   - `createwallet(..., load_on_startup=false)` exclusion from restart loading
   - `unloadwallet(..., load_on_startup=false)` removing startup persistence
   - `loadwallet(..., load_on_startup=true)` adding startup persistence
   - final restart state matching the configured startup wallet set
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_startup.py`
   Still deferred inside this suite:
   - broader wallet creation, blank-wallet, and multiwallet semantics now
     covered by adjacent required gates or tracked as broader lifecycle
     follow-ons
36. `wallet_blank.py` now owns:
   - restored inherited blank descriptor-wallet behavior under the current
     legacy-compatible PQC profile
   - blank flag preservation after descriptor import
   - blank flag preservation after blank-wallet encryption
   - descriptor metadata stability across blank-wallet encryption
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_blank.py`
   Still deferred inside this suite:
   - broader wallet creation arguments and lifecycle semantics
37. `wallet_createwallet.py` now owns:
   - restored inherited `createwallet` argument and lifecycle behavior under
     the current legacy-compatible PQC profile
   - invalid option combinations and disabled-private-key wallets
   - blank-wallet creation with private keys disabled and enabled
   - descriptor import behavior, wallet encryption, empty-passphrase warnings,
     `avoid_reuse`, legacy-wallet rejection, and wallet version logging
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_createwallet.py`
   Still deferred inside this suite:
   - broader lifecycle breadth beyond the adjacent multiwallet gate
38. `wallet_multiwallet.py` now owns:
   - restored inherited multiwallet lifecycle behavior under the current
     legacy-compatible PQC profile
   - wallet directory scanning and wallet-file creation
   - wallet path validation, invalid walletdir startup failures, duplicate
     wallet arguments, and symlinked wallet path rejection
   - dynamic wallet loading, creation, unloading, and concurrent load rejection
   - per-wallet balance, endpoint selection, and `settxfee` isolation
   - multiwallet backup/restore round trips and exclusive database locking
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_multiwallet.py`
   Still deferred inside this suite:
   - broader wallet lifecycle breadth outside the multiwallet contract now
     covered by adjacent key-management gates or tracked as accounting/list
     follow-ons
39. `wallet_descriptor.py`, `wallet_disable.py`, `wallet_encryption.py`,
   `wallet_gethdkeys.py`, `wallet_hd.py`, `wallet_keypool.py`,
   `wallet_keypool_topup.py`, and `wallet_listdescriptors.py` now own:
   - restored inherited key-management, descriptor-maintenance, and no-wallet
     runtime behavior under the current legacy-compatible PQC profile
   - descriptor wallet info, receive/change derivation, send/receive behavior,
     exports/imports, and legacy-key-type load rejection
   - `-disablewallet` wallet RPC hiding with non-wallet address validation
   - wallet encryption, passphrase timeout limits, signing lock/unlock,
     passphrase changes, and no-private-key wallet encryption rejection
   - `gethdkeys` reporting for public/private, encrypted, imported ranged,
     non-HD, and multisig HD-key cases
   - HD backup/restore, keypool refill, receive/change recovery, keypool
     exhaustion/refill, locked/encrypted wallet behavior, and restored keypool
     top-up balance detection
   - descriptor listing for empty/default wallets, sorted output, hardened
     derivations, private visibility, encrypted/watch-only wallets, and
     non-active combo descriptors
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_descriptor.py wallet_disable.py wallet_encryption.py wallet_gethdkeys.py wallet_hd.py wallet_keypool.py wallet_keypool_topup.py wallet_listdescriptors.py`
   Still deferred inside this suite:
   - wallet accounting, label, and transaction-listing semantics now covered
     by adjacent required gates; conflict semantics now covered by adjacent
     required gates; transaction construction and simulation now covered by
     adjacent required gates; raw signing, descriptor import, and migration
     remain separate
40. `wallet_balance.py`, `wallet_coinbase_category.py`, `wallet_labels.py`,
   `wallet_listreceivedby.py`, `wallet_listsinceblock.py`, and
   `wallet_listtransactions.py` now own:
   - restored inherited wallet accounting, label, received-by, since-block,
     and transaction-listing behavior under the current legacy-compatible PQC
     profile
   - mined, immature, trusted, untrusted, conflicted, and imported-output
     balance accounting
   - `getbalance`, `getbalances`, `getwalletinfo`, and `gettransaction`
     last-processed-block reporting
   - immature, generated, orphaned, and mature coinbase category reporting
   - label RPC validation, assignment, grouping, send persistence, and
     watch-only label handling
   - received-by address/label accounting, immature coinbase inclusion,
     matured rewards, and invalidated-block exclusion
   - `listsinceblock` and `listtransactions` behavior for reorgs,
     double-spends, double-sends, spend filtering, descriptor lookup, change
     inclusion, OP_RETURN output, labels, BIP125 replaceability, parameter
     validation, and from-me status changes
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_balance.py wallet_coinbase_category.py wallet_labels.py wallet_listreceivedby.py wallet_listsinceblock.py wallet_listtransactions.py`
   Still deferred inside this suite:
   - coin-selection grouping and bumpfee/conflict semantics now covered by
     adjacent required gates; transaction construction and simulation now
     covered by adjacent required gates; raw signing, descriptor import, and
     migration remain separate
41. `wallet_avoid_mixing_output_types.py`, `wallet_avoidreuse.py`,
   `wallet_change_address.py`, `wallet_fallbackfee.py`, `wallet_groups.py`,
   and `wallet_spend_unconfirmed.py` now own:
   - restored inherited coin-selection grouping, change selection, avoid-reuse,
     fallback-fee, and unconfirmed-input spend-policy behavior under the
     current legacy-compatible PQC profile
   - output-type grouping during coin selection across mixed wallet UTXOs
   - `avoid_reuse` persistence, immutable flags, reused-address spend
     rejection, used balance reporting, and destination-group coin selection
   - change destination selection, change detection, and explicit
     change-address behavior
   - RBF transaction creation with configured `fallbackfee` when fee
     estimation is unavailable
   - grouped UTXO spending, `avoidpartialspends`, `maxapsfee` thresholds, and
     large same-scriptPubKey UTXO selection limits
   - confirmed versus unconfirmed input feerate selection, ancestor and sibling
     feerate handling, subtract-fee behavior, preset low-fee unconfirmed
     inputs, RBF parent bumping, overlapping ancestry, and external-input
     package bumping
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_avoid_mixing_output_types.py wallet_avoidreuse.py wallet_change_address.py wallet_fallbackfee.py wallet_groups.py wallet_spend_unconfirmed.py`
   Still deferred inside this suite:
   - bumpfee and conflict semantics now covered by adjacent required gates;
     transaction construction, transaction simulation, and broad basic wallet
     behavior now covered by adjacent required gates; raw signing, descriptor
     import, and migration remain separate
42. `wallet_abandonconflict.py`, `wallet_bumpfee.py`,
   `wallet_conflicts.py`, `wallet_txn_clone.py`, and
   `wallet_txn_doublespend.py` now own:
   - restored inherited fee-bump, abandoned-conflict, clone, double-spend, and
     wallet conflict-tracking behavior under the current legacy-compatible PQC
     profile
   - abandoned transaction handling, balance/listing visibility, abandoned
     transactions in `listsinceblock`, and double-spend conflict handling
   - `bumpfee` and `psbtbumpfee` option validation, fee-rate validation,
     confirmation-target validation, estimate-mode validation, change handling,
     non-RBF replacement rejection, non-owned input and PSBT behavior,
     descendant and abandoned-descendant behavior, dust/change/drop-to-fee
     behavior, `maxtxfee`, watch-only PSBT behavior, successor and re-bump
     behavior, spent-coin failure, metadata persistence, locked-wallet
     rejection, change address reuse, confirmed-output availability,
     replaced-output feerate checks, and `walletincrementalrelayfee` behavior
   - block and mempool conflict tracking, reorg conflict state, inactive
     formerly conflicted transactions, conflict removal, combined block and
     mempool conflict handling, and parent mempool conflicts
   - cloned or malleated transaction accounting across the default, `--segwit`,
     and `--mineblock` variants
   - double-spend transaction accounting across the default and `--mineblock`
     variants
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_abandonconflict.py wallet_bumpfee.py wallet_conflicts.py wallet_txn_clone.py wallet_txn_doublespend.py`
   Fixed posture note:
   - `WALLET_BUMPFEE_CONFLICT_POSTURE.md`
   Still deferred inside this suite:
   - transaction construction, transaction simulation, and broad basic wallet
     behavior now covered by adjacent required gates; inherited raw transaction
     signing, descriptor import, and migration breadth remain separate
43. `wallet_basic.py`, `wallet_create_tx.py`, and
   `wallet_simulaterawtx.py` now own:
   - restored inherited basic wallet behavior, transaction creation, and raw
     transaction simulation under the current legacy-compatible PQC profile
   - basic wallet balances, UTXO visibility, `gettxout` mempool interactions,
     `lockunspent` persistence and validation, fee-setting behavior,
     descriptor imports, watch-only visibility, mature and immature coinbase
     handling, and address/accounting edge cases
   - anti-fee-sniping locktime behavior, transaction-size `maxtxfee`
     rejection, too-long mempool chain rejection, and current wallet
     transaction version behavior
   - `simulaterawtransaction` multiwallet balance deltas, watch-only descriptor
     visibility, funded raw transaction fee/payment accounting,
     duplicate-spend rejection, missing-input rejection, chained simulated
     transactions, and mined-input rejection
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_create_tx.py wallet_simulaterawtx.py wallet_basic.py`
   Fixed posture note:
   - `WALLET_TRANSACTION_CONSTRUCTION_POSTURE.md`
   Still deferred inside this suite:
   - raw transaction signing and descriptor import now covered by adjacent
     required gates; migration and prior-release compatibility remain blocked
     without previous-release fixtures
44. `wallet_importdescriptors.py` and
   `wallet_signrawtransactionwithwallet.py` now own:
   - restored inherited descriptor import and raw transaction signing behavior
     under the current legacy-compatible PQC profile
   - `importdescriptors` missing descriptor errors, checksum and range
     validation, pkh and sh(wpkh) descriptor imports, duplicate imports and
     label updates, internal-label rejection, invalid-key validation, multisig
     descriptor imports, ranged descriptor handling, private-key-enabled wallet
     constraints, and descriptor persistence across wallet reload
   - `signrawtransactionwithwallet` locked encrypted wallet rejection, invalid
     sighash validation, script verification error reporting, fully signed
     transaction no-op behavior, OP_1NEGATE signing, and CSV/CLTV witness
     signing
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_signrawtransactionwithwallet.py wallet_importdescriptors.py`
   Migration probe:
   - `build/test/functional/test_runner.py --jobs=1 wallet_signrawtransactionwithwallet.py wallet_importdescriptors.py wallet_migration.py`
   - expected local outcome: `wallet_migration.py` skipped because
     previous-release fixtures are unavailable
   Fixed posture note:
   - `WALLET_RAW_SIGNING_IMPORT_POSTURE.md`
   Still deferred inside this suite:
   - `wallet_migration.py`, which is skipped locally because previous-release
     fixtures are unavailable
   - import-pruned-funds, timelock, orphaned reward, and v3 transaction
     behavior now covered by adjacent required gates; the small remaining local
     wallet backlog stays separate
45. `wallet_importprunedfunds.py`, `wallet_timelock.py`,
   `wallet_orphanedreward.py`, and `wallet_v3_txs.py` now own:
   - restored inherited import-pruned-funds, timelock, orphaned reward, and
     v3/TRUC wallet behavior under the current legacy-compatible PQC profile
   - `importprunedfunds` and `removeprunedfunds` proof import rejection for
     unaffiliated addresses, watch-only descriptor import, private-key import,
     balance/listing updates, removal behavior, transaction decode errors,
     proof mismatch errors, malformed merkleblock rejection, and missing-block
     rejection
   - confirmed timelocked send accounting stability across received-by-address,
     received-by-label, listreceived, trusted balance, and unspent coin state
     when mock time changes finality
   - orphaned block reward handling, descendant abandonment, reload
     persistence, and preserving abandoned descendants when the reward returns
     to the active chain
   - wallet v3/TRUC behavior for version-mixing spend availability, v3 UTXO
     visibility, conflicting sibling handling, mempool conflict removal, parent
     and child weight checks, user input weight preservation, `createpsbt`,
     `send`, `sendall`, funded-PSBT v3 flows, TRUC weight-limit errors,
     non-TRUC mixing rejection, multiple unconfirmed TRUC output rejection, and
     third-generation spend rejection
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_importprunedfunds.py wallet_timelock.py wallet_orphanedreward.py wallet_v3_txs.py`
   Fixed posture note:
   - `WALLET_REMAINING_TRANSACTION_BREADTH_POSTURE.md`
   Still deferred inside this suite:
   - `wallet_migration.py`, which is skipped locally because previous-release
     fixtures are unavailable
   - `wallet_crosschain.py` and `wallet_createwalletdescriptor.py` are now
     covered by the adjacent required descriptor-creation/cross-chain gate;
     `wallet_backwards_compatibility.py` remains previous-release blocked
46. `wallet_createwalletdescriptor.py` and `wallet_crosschain.py` now own:
   - restored inherited xpub descriptor creation and cross-chain wallet-file
     safety behavior under the current legacy-compatible PQC profile
   - `createwalletdescriptor` xpub-based bech32/wpkh and bech32m/tr descriptor
     manager creation, active descriptor key selection, duplicate/invalid
     HD-key validation, encrypted-wallet unlock behavior, and explicit
     PQ-only active-manager rejection without mutating wallet state
   - wallet and backup rejection from a different genesis/network through
     `loadwallet` and `restorewallet`
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 wallet_crosschain.py wallet_createwalletdescriptor.py`
   Compatibility probe:
   - `build/test/functional/test_runner.py --jobs=1 wallet_crosschain.py wallet_createwalletdescriptor.py wallet_backwards_compatibility.py`
   - expected local outcome: `wallet_backwards_compatibility.py` skipped
     because previous-release fixtures are unavailable
   Fixed posture note:
   - `WALLET_CROSSCHAIN_DESCRIPTOR_CREATION_POSTURE.md`
   Still deferred inside this suite:
   - `wallet_backwards_compatibility.py` and `wallet_migration.py`, which are
     skipped locally at this historical checkpoint because previous-release
     fixtures are unavailable
   - `feature_coinstatsindex_compatibility.py`, which was still awaiting a
     release-asset boundary decision at this checkpoint; later bounded
     decisions classified all three suites as `legacy_only`
47. `mempool_accept.py` now owns:
   - inherited raw transaction mempool acceptance under the current
     legacy-compatible PQC profile
   - `testmempoolaccept` RPC argument validation for malformed, empty,
     oversized, and undecodable batches
   - already-known, already-in-block, already-in-mempool, missing-input,
     duplicate-input, coinbase, and prevout-null rejection paths
   - fee, maxfeerate, negative-feerate, replacement, non-final, and BIP68
     sequence-lock acceptance or rejection behavior
   - version, scriptPubKey, bare-multisig, scriptSig, dust, standard
     transaction-size, small non-witness-size, and OP_RETURN policy boundaries
   - anchor output standardness, nested-anchor rejection, and confirmed
     bare-multisig spending policy
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_accept.py`
   Fixture probe:
   - `build/test/functional/test_runner.py --jobs=1 feature_unsupported_utxo_db.py`
   - expected local outcome: `feature_unsupported_utxo_db.py` skipped because
     previous-release fixtures are unavailable
   Fixed posture note:
   - `MEMPOOL_ACCEPT_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `feature_unsupported_utxo_db.py` and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
48. `mempool_accept_wtxid.py` now owns:
   - inherited wtxid-aware mempool acceptance under the current
     legacy-compatible PQC profile
   - construction of two valid witness-malleated children with identical
     non-witness data, identical `txid`, and distinct `wtxid` values
   - mempool storage of the first child's expected `wtxid`
   - exact `txn-already-in-mempool` reporting for the already-accepted child
   - exact `txn-same-nonwitness-data-in-mempool` rejection for the alternate
     witness
   - no replacement of the canonical mempool transaction by repeated
     `sendrawtransaction` calls
   - rebroadcast of the canonical mempool `wtxid` to a newly connected peer
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_accept_wtxid.py`
   Fixed posture note:
   - `MEMPOOL_ACCEPT_WTXID_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
49. `mempool_datacarrier.py` now owns:
   - inherited OP_RETURN/datacarrier mempool policy under the current
     legacy-compatible PQC profile
   - default uncapped datacarrier relay behavior
   - disabled datacarrier relay rejection behavior
   - custom `-datacarriersize=83` acceptance and rejection boundaries
   - empty, zero-byte, and one-byte OP_RETURN payload policy under a small
     `-datacarriersize=2` limit
   - `getmempoolinfo()["maxdatacarriersize"]` reporting for default,
     disabled, historical custom, and small custom limits
   - the suite-local confirmed bare-multisig policy smoke check
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_datacarrier.py`
   Fixed posture note:
   - `MEMPOOL_DATACARRIER_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
50. `mempool_dust.py` now owns:
   - inherited dust-relay mempool policy under the current legacy-compatible
     PQC profile
   - `-dustrelayfee=0` acceptance for small outputs that would otherwise trip
     dust policy
   - exact-threshold acceptance and one-satoshi-below-threshold `dust`
     rejection for covered standard output script types
   - OP_RETURN/null-data zero dust threshold behavior
   - default dust relay fee behavior and multiple configured `-dustrelayfee`
     rates
   - inherited output-script coverage for P2PK, P2PKH, P2SH, P2WPKH, P2WSH,
     P2TR-shaped script construction, future witness versions, bare multisig,
     and OP_RETURN
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_dust.py`
   Fixed posture note:
   - `MEMPOOL_DUST_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
51. `mempool_ephemeral_dust.py` now owns:
   - inherited ephemeral-dust package policy under the current
     legacy-compatible PQC profile
   - zero-fee TRUC parent rejection individually and acceptance when the
     package child spends the dust
   - prioritisation rejection for in-mempool dust-output transactions
   - restart dropping ephemeral-dust packages because individual reload cannot
     reconstruct the CPFP package
   - fee-having parent, modified-fee parent, multidust, non-TRUC, and
     missing-ephemeral-spend rejection paths
   - sponsor cycling where a zero-fee dust parent becomes childless and
     unmined before a later sweep
   - reorg restoration for valid ephemeral-dust shapes and rejection for fee
     parents, multidust parents, and invalid follow-on TRUC chains
   - disabled-minrelay non-TRUC and batched sweep behavior across many parents
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_ephemeral_dust.py`
   Fixed posture note:
   - `MEMPOOL_EPHEMERAL_DUST_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
52. `mempool_expiry.py` now owns:
   - inherited mempool transaction expiry under the current legacy-compatible
     PQC profile
   - default `DEFAULT_MEMPOOL_EXPIRY_HOURS` behavior
   - custom `-mempoolexpiry=<n>` behavior
   - parent transaction expiry with child transaction eviction
   - independent transaction survival across parent and child expiry
   - prioritisation persistence after expiry with `in_mempool=false`
   - expiry triggering through normal mempool admission after mocktime advance
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_expiry.py`
   Fixed posture note:
   - `MEMPOOL_EXPIRY_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
53. `mempool_limit.py` now owns:
   - inherited mempool size, eviction, and package-limit policy under the
     current legacy-compatible PQC profile
   - full-mempool `mempoolminfee` behavior and minimum-fee rejection
   - CPFP package admission with a parent below the mempool minimum
   - package broadcast behavior that still respects peer fee filters
   - immediate rejection for a low-ranked package after full-mempool eviction
   - `-maxmempool` floor init rejection
   - mid-package eviction without evicting the newly accepted package
   - mid-package replacement without stale descendants
   - RBF carveout limit rejection for package members
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_limit.py`
   Fixed posture note:
   - `MEMPOOL_LIMIT_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
54. `mempool_package_limits.py` now owns:
   - inherited package ancestor/descendant limit policy under the current
     legacy-compatible PQC profile
   - combined in-mempool and in-package chain-limit accounting
   - descendant-count accounting across shared-ancestor package topologies
   - ancestor-count accounting across V-shaped, Y-shaped, and bushy package
     topologies
   - ancestor-size accounting for large independent mempool parents plus
     in-package descendants
   - descendant-size accounting for large mempool descendants that continue
     into the package
   - stable `package-mempool-limits` rejection before clearing mempool state
   - package acceptance after mining clears the pre-submitted mempool
     transactions
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_package_limits.py`
   Fixed posture note:
   - `MEMPOOL_PACKAGE_LIMITS_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
55. `mempool_package_onemore.py` now owns:
   - inherited one-more-descendant package carveout policy under the current
     legacy-compatible PQC profile
   - full `DEFAULT_ANCESTOR_LIMIT` chain construction from a confirmed UTXO
   - ancestor-limit rejection for adding one more transaction to the chain tip
   - descendant-limit rejection for middle-of-chain descendants and
     two-parent descendants
   - oversized descendant rejection outside the carveout size boundary
   - package rejection diagnostics for a rejected parent plus missing-input
     child
   - direct-child carveout acceptance from the first transaction in the chain
   - independent second-chain admission after the carveout path
   - single direct-conflict RBF replacement of the chain using the carveout
     rule
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_package_onemore.py`
   Fixed posture note:
   - `MEMPOOL_PACKAGE_ONEMORE_POSTURE.md`
   Still deferred inside this suite:
   - remaining mempool mining policy suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
56. `mempool_package_rbf.py` now owns:
   - inherited package RBF policy under the current legacy-compatible PQC
     profile
   - 1-parent-1-child package replacement with child-paid conflicts
   - `testmempoolaccept` conflict rejection during subpackage evaluation
   - p2p propagation of a basic package RBF replacement to the second node
   - singleton conflict replacement
   - absolute-fee and incremental-relay-fee replacement requirements
   - maximum replacement-candidate limits
   - package-size, mempool-ancestor, and conflict-cluster shape rejection
   - package feerate diagram rejection
   - TRUC zero-fee-parent plus high-fee-child package RBF
   - filled-mempool ancestor-conflict rejection without evicting the ancestor
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_package_rbf.py`
   Fixed posture note:
   - `MEMPOOL_PACKAGE_RBF_POSTURE.md`
   Still deferred inside this suite:
   - broader package relay, persistence, reorg, mining policy, and
     prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
57. `mempool_packages.py` now owns:
   - inherited mempool ancestor/descendant tracking under the current
     legacy-compatible PQC profile
   - default ancestor-chain admission through the configured ceiling and
     `too-long-mempool-chain` rejection for the next hop
   - verbose `getmempoolentry`, `getrawmempool`, `getmempoolancestors`, and
     `getmempooldescendants` accounting
   - `gettxspendingprevout` consistency for in-mempool spends
   - `prioritisetransaction` ancestor and descendant fee-delta accounting
   - cross-node propagation into a peer with custom ancestor and descendant
     limits
   - descendant-chain limit rejection at the configured ceiling
   - block disconnect/reconnect handling when a transaction depends on mined
     parents and one parent is not accepted back due to the custom ancestor
     limit
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_packages.py`
   Fixed posture note:
   - `MEMPOOL_PACKAGES_POSTURE.md`
   Still deferred inside this suite:
   - mining policy and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
58. `mempool_persist.py` now owns:
   - inherited mempool persistence and runtime import behavior under the
     current legacy-compatible PQC profile
   - default `mempool.dat` reload across shutdown/startup
   - `-persistmempool=0` dump and load suppression without overwriting a valid
     saved mempool
   - `savemempool` file recreation and filename reporting
   - runtime `importmempool` with optional priority-delta and unbroadcast-set
     restoration
   - `prioritisetransaction` fee-delta persistence for in-mempool transactions
     and not-yet-submitted transactions
   - watch-only wallet accounting after reload when wallet support is compiled
   - cross-node `mempool.dat` import
   - import union behavior without replacing the current mempool
   - disk-write failure handling for `savemempool`
   - unbroadcast-set persistence and later peer announcement after restart
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_persist.py`
   Fixed posture note:
   - `MEMPOOL_PERSIST_POSTURE.md`
   Still deferred inside this suite:
   - mining policy and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
59. `mempool_reorg.py` now owns:
   - inherited mempool reorg behavior under the current legacy-compatible PQC
     profile
   - timelock non-final rejection and later acceptance after the chain advances
   - direct and indirect coinbase-spend scenarios across mempool and chain
   - disconnected-block child transaction return to the mempool after shallow
     invalidation
   - no-longer-final timelocked transaction removal after reorg
   - immature coinbase-spend cleanup after deeper invalidation
   - immediate explicit relay availability for transactions from recently
     disconnected blocks
   - early explicit request rejection for very recent unannounced mempool
     transactions until mock time advances
   - expected inventory announcement after mock time advances
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_reorg.py`
   Fixed posture note:
   - `MEMPOOL_REORG_POSTURE.md`
   Still deferred inside this suite:
   - mining policy and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
60. `mempool_resurrect.py` now owns:
   - inherited mempool resurrection behavior under the current
     legacy-compatible PQC profile
   - first-level spend admission and confirmation into one block
   - descendant spend admission and confirmation into a second block
   - empty mempool while the original two-block confirmation path is active
   - two-block disconnect after invalidating the first mined block
   - all disconnected parent and descendant transactions returning to the
     mempool with zero confirmations
   - replacement-block mining of the resurrected transaction set
   - empty mempool after the replacement confirmation path
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_resurrect.py`
   Fixed posture note:
   - `MEMPOOL_RESURRECT_POSTURE.md`
   Still deferred inside this suite:
   - mining policy and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
61. `mempool_sigoplimit.py` now owns:
   - inherited bytes-per-sigop mempool resource-envelope policy under the
     current legacy-compatible PQC profile
   - default and custom `-bytespersigop` settings across fixed sigop counts
   - `testmempoolaccept` vsize reporting at, above, and below the
     sigop-equivalent threshold
   - ancestor and descendant size accounting with adjusted vsize
   - package-size rejection for sigop-heavy bare multisig packages
   - direct package submission where the parent enters mempool and the child
     fails ancestor-size policy
   - legacy P2SH sigops standardness rejection and one-input-smaller
     acceptance
   - explicit block mining of the non-standard high-sigop transaction
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_sigoplimit.py`
   Fixed posture note:
   - `MEMPOOL_SIGOPLIMIT_POSTURE.md`
   Still deferred inside this suite:
   - mining policy and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
62. `mempool_spend_coinbase.py` now owns:
   - inherited mempool coinbase-spend maturity policy under the current
     legacy-compatible PQC profile
   - chain invalidation to a height where one coinbase spend is mature for the
     next block and the adjacent coinbase spend is premature
   - near-mature coinbase-spend admission to the mempool
   - premature coinbase-spend rejection with
     `bad-txns-premature-spend-of-coinbase`
   - mempool contents containing only the mature spend before mining
   - mined confirmation of the mature coinbase spend and mempool cleanup
   - later admission of the formerly premature coinbase spend after height
     advances
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_spend_coinbase.py`
   Fixed posture note:
   - `MEMPOOL_SPEND_COINBASE_POSTURE.md`
   Still deferred inside this suite:
   - mining policy and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
63. `mempool_truc.py` now owns:
   - inherited TRUC/v3 mempool policy under the current legacy-compatible PQC
     profile
   - v3 maximum-vsize and child-size rejection while equivalent v2
     transactions remain accepted
   - direct TRUC acceptance, replacement, and inheritance policy checks
   - reorg restoration of disconnected transactions without enforcing direct
     mempool TRUC topology at re-entry time
   - nondefault ancestor and descendant package-limit interactions
   - package ancestor rejection for multiparent, oversized-child, and
     three-generation TRUC package shapes
   - sibling eviction behavior across individual submission,
     `testmempoolaccept`, CPFP package submission, and RBF constraints
   - `testmempoolaccept` inheritance diagnostics for independent, in-package,
     and in-mempool parent cases
   - minrelay package combinations for zero-fee TRUC parents paid by children
     versus non-TRUC equivalents
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_truc.py`
   Fixed posture note:
   - `MEMPOOL_TRUC_POSTURE.md`
   Still deferred inside this suite:
   - mining policy, orphan transaction, and prior-release
     compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
64. `mempool_unbroadcast.py` now owns:
   - inherited mempool unbroadcast delivery policy under the current
     legacy-compatible PQC profile
   - local raw transaction entry into the unbroadcast set
   - wallet-originated transaction entry into the unbroadcast set when wallet
     support is compiled
   - `getmempoolinfo()["unbroadcastcount"]` and verbose `getrawmempool`
     unbroadcast flag reporting
   - `mempool.dat` persistence of unbroadcast state across restart
   - delivery to a peer after reconnect and scheduler advance
   - removal from the first node's unbroadcast set after peer delivery
   - no repeat broadcast to later peer connections after delivery
   - no re-addition to the unbroadcast set when an already-known transaction is
     rebroadcast
   - removal from the unbroadcast set before block confirmation when the
     transaction leaves the mempool
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_unbroadcast.py`
   Fixed posture note:
   - `MEMPOOL_UNBROADCAST_POSTURE.md`
   Still deferred inside this suite:
   - mining policy, orphan transaction, and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
65. `mempool_updatefromblock.py` now owns:
   - inherited mempool update-from-block reorg accounting under the current
     legacy-compatible PQC profile
   - 100-transaction tournament-graph re-entry from disconnected blocks after
     an empty-fork reorg
   - descendant count, descendant size, ancestor count, and ancestor size
     reconstruction for every re-added transaction
   - mempool cleanup after mining the re-added graph and MiniWallet UTXO
     rescan
   - `MAX_DISCONNECTED_TX_POOL_BYTES` disconnect-pool trimming across large
     independent parent transactions
   - recursive child removal whenever the trimmed parent is dropped during
     reorg handling
   - FIFO trimming of the most recently confirmed parents and children while
     preserving earlier parent/child pairs
   - standard chain-limit enforcement when a non-standardly mined too-long
     chain is returned to the mempool
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mempool_updatefromblock.py`
   Fixed posture note:
   - `MEMPOOL_UPDATEFROMBLOCK_POSTURE.md`
   Still deferred inside this suite:
   - mining policy, orphan transaction, and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
66. `mining_basic.py` now owns:
   - inherited mining RPC and block-template policy under the current
     legacy-compatible PQC profile
   - `getmininginfo` chain, height, bits, target, difficulty, next-block,
     networkhashps, and pooled transaction fields
   - `getblocktemplate` default witness commitment construction
   - `-blockversion` override behavior and normal versionbits template behavior
     after restart
   - `getblocktemplate` segwit-rule enforcement and proposal capability
   - `submitblock` and `submitheader` decode, missing-ancestor,
     bad-merkle-root, nonfinal, bad-prevblk, old-time, duplicate, and active-tip
     outcomes
   - block-template transaction fee and sigop ordering
   - `-blockmintxfee` filtering across many configured fee-rate boundaries
   - BIP94 timewarp protection at the first-block retarget-period boundary
   - pruned-block `submitblock` replay when the pruning run exposes a pruned
     historical block
   - `-blockmaxweight` and `-blockreservedweight` block-template packing and
     invalid startup value rejection
   - generated coinbase height-locktime behavior
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mining_basic.py`
   Fixed posture note:
   - `MINING_BASIC_POSTURE.md`
   Still deferred inside this suite:
   - longpoll, mainnet mining, package-template selection, prioritisation,
     orphan transaction, and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
67. `mining_getblocktemplate_longpoll.py` now owns:
   - inherited `getblocktemplate` longpoll behavior under the current
     legacy-compatible PQC profile
   - stable `longpollid` reporting across successive `getblocktemplate` calls
     when no chain or mempool event occurs
   - longpoll wait behavior on a separate RPC connection
   - longpoll wakeup after another connected node generates a block
   - longpoll wakeup after the local node generates a block
   - longpoll wakeup after a new transaction enters the mempool
   Minimum validation target:
   - `build/test/functional/test_runner.py --jobs=1 mining_getblocktemplate_longpoll.py`
   Fixed posture note:
   - `MINING_GETBLOCKTEMPLATE_LONGPOLL_POSTURE.md`
   Still deferred inside this suite:
   - mainnet mining, package-template selection, prioritisation, orphan
     transaction, and prior-release compatibility suites
   - `mempool_compatibility.py`, `feature_unsupported_utxo_db.py`, and
     `feature_coinstatsindex_compatibility.py`, which remain blocked until
     real prior PQBTC release assets exist
68. Historical next PR after this tranche at the time:
   - preferred: `feature_coinstatsindex_compatibility.py`
   - alternate: `mining_mainnet.py` as the next local mining policy
     candidate after a fresh targeted pass, while
     `mempool_compatibility.py` stays previous-release blocked
   Why next:
   - `feature_coinstatsindex_compatibility.py` is the remaining nearby
     chainstate/index follow-on now that both assumeutxo slices are frozen
   - the restart/reindex family is now fully represented in the required gate,
     and the unknown-versionbits warning, BIP68 sequence-lock, CLTV,
     CSV activation, and broad pruning surfaces are now represented in the
     required gate, so any local alternate should be a fresh bounded migration
     decision outside those surfaces
   - this dated tranche note is now superseded by the live repo-local handoff
     in `Current Follow-On Candidates` above; the intervening
     `mining_prioritisetransaction.py` and `mining_template_verification.py`
     slices have since landed, and the live next owned slice is now the
     asset-dependent `feature_coinstatsindex_compatibility.py` promotion once
     real prior PQBTC release assets exist locally
   - the first two inherited mempool acceptance gates plus datacarrier, dust,
     ephemeral-dust, expiry, limit, package-limit, and one-more-descendant
     carveout policy are now frozen, and package RBF plus package accounting
     are now frozen, and mempool persistence, reorg, and resurrection behavior
     are now frozen, and sigop resource-envelope, coinbase-spend maturity, and
     TRUC policy are now frozen, and unbroadcast delivery is now frozen, so the
     adjacent update-from-block reorg-accounting gate is now frozen, so the
     broad inherited mining RPC and block-template gate is now frozen, so the
     getblocktemplate longpoll gate is now frozen, so the local follow-on can
     move to another bounded mining policy gate only after a fresh targeted
     pass
   - `wallet_backwards_compatibility.py` and `wallet_migration.py` remain
     useful, but both stay asset-dependent after the current
     startup, blank-wallet, createwallet, multiwallet, descriptor, encryption,
     HD, keypool, descriptor-listing, accounting, label, transaction-listing,
     coin-selection, spend-policy, bumpfee/conflict, basic wallet,
     transaction-construction, simulation, raw-signing, and import-descriptor
     gates are frozen, and after the current import-pruned-funds, timelock,
     orphaned reward, v3/TRUC transaction, descriptor-creation, and
     cross-chain wallet-file gates are frozen
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
32. Use `MEMPOOL_ACCEPT_POSTURE.md` as the fixed note for the current
   `mempool_accept.py` contract.
33. Use `MEMPOOL_ACCEPT_WTXID_POSTURE.md` as the fixed note for the current
   `mempool_accept_wtxid.py` contract.
34. Use `MEMPOOL_DATACARRIER_POSTURE.md` as the fixed note for the current
   `mempool_datacarrier.py` contract.
35. Use `MEMPOOL_DUST_POSTURE.md` as the fixed note for the current
   `mempool_dust.py` contract.
36. Use `MEMPOOL_EPHEMERAL_DUST_POSTURE.md` as the fixed note for the current
   `mempool_ephemeral_dust.py` contract.
37. Use `MEMPOOL_EXPIRY_POSTURE.md` as the fixed note for the current
   `mempool_expiry.py` contract.
38. Use `FEATURE_PQSIG_BASIC_POSTURE.md` as the fixed note for the current
   `feature_pqsig_basic.py` contract.
39. Use `FEATURE_PQSIG_MULTISIG_POSTURE.md` as the fixed note for the current
   `feature_pqsig_multisig.py` contract.
40. Use `FEATURE_LOADBLOCK_POSTURE.md` as the fixed note for the current
   `feature_loadblock.py` contract.
41. Use `WALLET_MINISCRIPT_POSTURE.md` as the fixed note for the current
   `wallet_miniscript.py` contract.
42. Use `FEATURE_UTXO_SET_HASH_POSTURE.md` as the fixed note for the current
   `feature_utxo_set_hash.py` contract.
43. Use `FEATURE_COINSTATSINDEX_POSTURE.md` as the fixed note for the current
   `feature_coinstatsindex.py` contract.
44. Use `FEATURE_BIP68_SEQUENCE_POSTURE.md` as the fixed note for the current
   `feature_bip68_sequence.py` contract.
45. Use `FEATURE_CLTV_POSTURE.md` as the fixed note for the current
   `feature_cltv.py` contract.
46. Use `FEATURE_CSV_ACTIVATION_POSTURE.md` as the fixed note for the current
   `feature_csv_activation.py` contract.
47. Use `FEATURE_PRUNING_POSTURE.md` as the fixed note for the current
   `feature_pruning.py` contract.
48. Use `FEATURE_REINDEX_POSTURE.md` as the fixed note for the current
   `feature_reindex.py` contract.
49. Use `FEATURE_REINDEX_INIT_POSTURE.md` as the fixed note for the current
   `feature_reindex_init.py` contract.
50. Use `FEATURE_REINDEX_READONLY_POSTURE.md` as the fixed note for the current
   `feature_reindex_readonly.py` contract.
51. Use `FEATURE_VERSIONBITS_WARNING_POSTURE.md` as the fixed note for the
   current `feature_versionbits_warning.py` contract.
52. Use `FEATURE_ASSUMEVALID_POSTURE.md` as the fixed note for the current
   `feature_assumevalid.py` contract.
53. Use `FEATURE_ASSUMEUTXO_POSTURE.md` as the fixed note for the current
   `feature_assumeutxo.py` contract.
54. Use `WALLET_ASSUMEUTXO_POSTURE.md` as the fixed note for the current
   `wallet_assumeutxo.py` contract.
29. Treat inherited `getnewaddress` / `getrawchangeaddress` as unsupported on
   PQ-only active-manager wallets; the owned PQ address UX remains
   `getnewpqaddress` / `getrawpqchangeaddress`.
30. Treat `createwalletdescriptor` as an inherited xpub builder, not a PQ-native
   wallet-manager creation path under the all-PQ Track A stance.
31. Use `GENESIS_AND_NETWORK_POSTURE.md` as the launch-level interpretation for
   a fresh block-0 chain with its own network identity.
32. Keep the restored broad miniscript and PSBT decode/finalize coverage
   separate from replacement-path TapMiniscript activation semantics.
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
- `PQSIG_PRODUCTION_READINESS.md`
- `SLH_DSA_SHA2_128S_REFERENCE.md`
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
- `MEMPOOL_ACCEPT_POSTURE.md`
- `MEMPOOL_ACCEPT_WTXID_POSTURE.md`
- `TEST_COST_POSTURE.md`
- `POST_RC_EPICS.md`
- `CI_COMPLETENESS.md`
- `TAPROOT_MIGRATION_MATRIX.md`
- `OPS_SLO.md`

## Decision Log

Entries below are dated decision snapshots. Use Current Follow-On Candidates
above as the controlling live next-PR handoff when these older notes disagree.

- 2026-07-18: Cryptographic conformance review placed all production activation
  on hold. The rc2 implementation does not enforce the WOTS+C fixed-sum rule,
  does not implement the cited PORS+FP grinding/authentication-set behavior,
  and does not establish its claimed hypertree signing budget. rc2 remains a
  research integration fixture. `PQSIG_PRODUCTION_READINESS.md` defines the
  standards-based replacement lane and hold exit criteria.
- 2026-04-06: Track A confirmed as the repo anchor. No Liquid/Simplicity reset.
- 2026-04-13: `SHRINCS_DECISION_TRACK.md` added to keep SHRINCS-family
  evaluation explicit but separate: the repo can study or benchmark a future
  profile in parallel, but the active Track A execution baseline remains
  `PQSig rc2` until a dedicated go / no-go decision says otherwise.
- 2026-04-13: `PQSIG_PROFILE_COMPARISON.md` added as the first concrete
  decision memo: the then-active launch recommendation remained `PQSig rc2`, a
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
- 2026-04-12: `wallet_address_types.py` froze the inherited address-RPC
  boundary directly: inherited address-shape smoke coverage stays green,
  PQ-only active-manager wallets reject inherited `getnewaddress` /
  `getrawchangeaddress` across valid inherited address types including
  `bech32m`, and inherited mixed-address `sendmany` now stays green as the
  suite moves into the required gate. The next clean wallet follow-on shifted
  to `wallet_miniscript_decaying_multisig_descriptor_psbt.py`.
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
- 2026-04-12: `feature_pq_block_limits.py` now freezes the restored legacy
  block profile ceiling directly: `getblocktemplate` weightlimit remains
  `4_000_000`, exact-ceiling `-blockmaxweight` restarts stay valid,
  over-ceiling startup fails at `4000001`, and the node still mines after
  returning to the allowed limit. The next adjacent PQ-native chainstate
  follow-on shifts to `feature_pq_reorg.py`.
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
- 2026-04-14: `feature_assumevalid.py` is now promoted into the canonical
  `pq_required` gate. The current required PQ path therefore also covers the
  fixed assumevalid burial-depth validation slice alongside the live assumeutxo
  activation and wallet background-sync surfaces. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py`, while `feature_block.py`
  becomes the nearby validation-side gate candidate.
- 2026-04-14: `feature_block.py` is now promoted into the canonical
  `pq_required` gate. The current required PQ path therefore also covers the
  bounded full-block invalid-branch, transport-oversize, and resurrection
  harness surface. The next local owned follow-on shifts to
  `feature_coinstatsindex.py`, while
  `feature_coinstatsindex_compatibility.py` was still awaiting a release-asset
  boundary decision at this dated checkpoint. PR `#159` later classified it as
  `legacy_only`.
- 2026-04-23: `rpc_psbt.py` and `wallet_multisig_descriptor_psbt.py` are now
  promoted into the canonical `pq_required` gate. The inherited pre-taproot
  PSBT RPC surface, watch-only multisig descriptor partial-signature flow,
  node-side decode/combine/finalize, and successful broadcast path are green
  under the current DER-or-PQ signature encoding rules. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist, with broader inherited wallet/miniscript rehab
  remaining local-only while compatibility assets are unavailable.
- 2026-04-23: `wallet_miniscript.py` and
  `wallet_miniscript_decaying_multisig_descriptor_psbt.py` are now promoted
  into the canonical `pq_required` gate. The broader inherited miniscript
  funding/signing/finalization surface is green in the current tree: watch-only
  and signer-backed miniscript descriptors fund and track correctly,
  satisfiable PSBTs finalize and broadcast, deliberate under-keyed cases remain
  incomplete, and the decaying multisig locktime path finalizes successfully as
  the signer threshold drops. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited address-type/send-path rehab as the
  local alternate.
- 2026-04-23: `feature_assumevalid.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The non-assumevalid node still rejects the invalid block at height
  `102`, the deeply buried assumevalid path still reaches height `2202`, and
  the shallow assumevalid path still rejects the invalid block when it is not
  buried deeply enough. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited address-type/send-path rehab beyond the
  current `wallet_address_types.py` boundary now the local alternate.
- 2026-04-23: `wallet_address_types.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers inherited address-shape smoke coverage,
  descriptor-wallet `bech32m` smoke coverage, inherited mixed-address
  `sendmany`, PQ-only inherited-address RPC rejections, and invalid address-type
  precedence. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited address-type/send-path rehab beyond the
  current `wallet_address_types.py` boundary as the local alternate.
- 2026-04-23: `wallet_fundrawtransaction.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers inherited raw funding behavior under the
  current legacy-compatible PQC profile: default and preset input selection,
  fee/change handling, address/change-type handling, watch-only and
  external-input funding, transaction-size limits, duplicate outputs,
  unsafe-input controls, and input confirmation controls. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist, with broader inherited send-path rehab beyond
  this funding gate as the local alternate.
- 2026-04-24: `wallet_send.py`, `wallet_sendall.py`, and
  `wallet_sendmany.py` are now promoted into the canonical `pq_required` gate
  and locally revalidated with the build-tree functional runner. The owned
  boundary covers restored inherited destination send, sweep, PSBT/no-broadcast,
  fee/change/input-selection, watch-only, confirmation-control,
  anti-fee-sniping, transaction-size, and subtract-fee-from-output validation
  surfaces under the current legacy-compatible PQC profile. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist, with broader inherited wallet
  lifecycle/rebroadcast rehab beyond this send-path gate as the local alternate.
- 2026-04-24: `wallet_resendwallettransactions.py` is now promoted into the
  canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers restored inherited wallet
  rebroadcast timing, scheduler-triggered resubmission, peer inventory
  announcement, and parent-before-child rebroadcast for unconfirmed wallet
  transaction chains evicted from the mempool. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited wallet reindex/rescan/reorg rehab beyond
  this rebroadcast gate as the local alternate.
- 2026-04-24: `wallet_reindex.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited wallet reindex
  interaction under the current legacy-compatible PQC profile: watch-only
  descriptor birthtime adjustment, explicit rescan detection for a previously
  missed transaction, `-reindex` restart completion, confirmed transaction
  survival after reindex, and descriptor wallet birthtime convergence to the
  transaction time. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited wallet
  fast-rescan/unconfirmed-rescan/reorg-restore rehab beyond this reindex gate
  as the local alternate.
- 2026-04-25: `wallet_fast_rescan.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited descriptor-wallet
  fast-rescan behavior under the current legacy-compatible PQC profile:
  block-filter fast rescan and slow full-block rescan parity across wallet
  backup restore and non-active descriptor import paths, including ranged
  descriptor top-ups and one fixed non-ranged descriptor. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist, with broader inherited wallet
  unconfirmed-rescan/reorg-restore rehab beyond this fast-rescan gate as the
  local alternate.
- 2026-04-25: `wallet_rescan_unconfirmed.py` is now promoted into the
  canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers restored inherited
  descriptor-wallet unconfirmed-rescan behavior under the current
  legacy-compatible PQC profile: descriptor import rescans mempool transactions
  after a mocked reorg, recognizes the watched parent address as `ismine`,
  detects the re-entered parent, and detects the unconfirmed child sweep
  through input ordering. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited wallet reorg-restore rehab beyond this
  unconfirmed-rescan gate as the local alternate.
- 2026-04-25: `wallet_reorgsrestore.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited wallet reorg-restore
  behavior under the current legacy-compatible PQC profile: confirmed
  transaction status restoration after wallet reload on a longer chain,
  conflicted transaction recovery, startup abandonment of orphaned coinbase
  transactions and descendants, and unclean-shutdown reorg recovery without
  duplicate-disconnect crashes. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited wallet backup/restore and
  transaction-time rescan rehab beyond this reorg-restore gate as the local
  alternate.
- 2026-04-26: `wallet_transactiontime_rescan.py` is now promoted into the
  canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers restored inherited wallet
  transaction-time rescan behavior under the current legacy-compatible PQC
  profile: watch-only descriptor transaction times match original block times,
  restoration rescans preserve those times, idle `abortrescan` returns false,
  invalid `rescanblockchain` parameters are rejected, and locked encrypted
  wallets reject rescans until unlock. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited wallet backup/restore rehab beyond this
  transaction-time rescan gate as the local alternate.
- 2026-04-26: `wallet_backup.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited wallet backup/restore
  behavior under the current legacy-compatible PQC profile: backup and restore
  preserve multi-wallet balances after transaction churn, invalid and missing
  backup files are rejected without target-wallet creation, destination paths
  are handled safely, backup-to-source paths fail, unnamed restore succeeds,
  and pruned-node restore behavior respects backup/prune-height boundaries.
  The next owned follow-on remains `feature_coinstatsindex_compatibility.py`
  when real prior PQBTC release assets exist, with broader inherited wallet
  lifecycle coverage beyond this backup/restore gate as the local alternate.
- 2026-04-26: `wallet_startup.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited wallet startup and
  load-on-startup behavior under the current legacy-compatible PQC profile:
  empty wallet startup, unnamed default wallet auto-load, persisted
  `load_on_startup` flags from `createwallet`, startup-list removal through
  `unloadwallet`, startup-list addition through `loadwallet`, and final restart
  state matching the configured startup wallet set. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py` when real prior PQBTC
  release assets exist, with adjacent inherited wallet
  creation/blank/multiwallet lifecycle coverage beyond this startup gate as the
  local alternate.
- 2026-04-26: `wallet_blank.py` and `wallet_createwallet.py` are now promoted
  into the canonical `pq_required` gate and locally revalidated with the
  build-tree functional runner. The owned boundary covers blank
  descriptor-wallet flag preservation across descriptor import and encryption,
  plus restored inherited `createwallet` option validation, disabled-private-key
  wallets, blank-wallet creation, descriptor import behavior, encryption,
  empty-passphrase warnings, `avoid_reuse`, legacy-wallet rejection, and wallet
  version logging. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with `wallet_multiwallet.py` as the local alternate.
- 2026-04-26: `wallet_multiwallet.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited multiwallet lifecycle
  behavior under the current legacy-compatible PQC profile: wallet directory
  scanning, wallet-file creation, path validation, invalid walletdir startup
  failures, duplicate wallet arguments, symlinked wallet path rejection,
  dynamic wallet loading/creation/unloading, concurrent load rejection,
  per-wallet balance and fee isolation, multiwallet backup/restore round
  trips, and exclusive database locking. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with broader inherited wallet lifecycle breadth beyond this
  multiwallet gate as the local alternate.
- 2026-04-27: `wallet_descriptor.py`, `wallet_disable.py`,
  `wallet_encryption.py`, `wallet_gethdkeys.py`, `wallet_hd.py`,
  `wallet_keypool.py`, `wallet_keypool_topup.py`, and
  `wallet_listdescriptors.py` are now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited descriptor-wallet
  maintenance, no-wallet runtime behavior, wallet encryption, HD key reporting,
  HD backup/restore, keypool exhaustion/refill and restored top-up behavior,
  and descriptor listing under the current legacy-compatible PQC profile. The
  next owned follow-on remains `feature_coinstatsindex_compatibility.py` when
  real prior PQBTC release assets exist, with wallet accounting, labels, and
  transaction-listing surfaces as the local alternate.
- 2026-04-27: `wallet_balance.py`, `wallet_coinbase_category.py`,
  `wallet_labels.py`, `wallet_listreceivedby.py`, `wallet_listsinceblock.py`,
  and `wallet_listtransactions.py` are now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited balance accounting,
  coinbase category reporting, label RPCs, received-by accounting,
  since-block listing, and transaction-listing/gettransaction behavior under
  the current legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with coin-selection grouping and adjacent spend-policy surfaces
  as the local alternate.
- 2026-04-27: `wallet_avoid_mixing_output_types.py`,
  `wallet_avoidreuse.py`, `wallet_change_address.py`, `wallet_fallbackfee.py`,
  `wallet_groups.py`, and `wallet_spend_unconfirmed.py` are now promoted into
  the canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers restored inherited output-type
  grouping, avoid-reuse coin selection, change-address selection,
  fallback-fee/RBF creation, grouped UTXO selection, avoid-partial-spends
  behavior, and unconfirmed-input spend policy under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with fee-bump and adjacent transaction-conflict surfaces as the
  local alternate.
- 2026-04-27: `wallet_abandonconflict.py`, `wallet_bumpfee.py`,
  `wallet_conflicts.py`, `wallet_txn_clone.py`, and
  `wallet_txn_doublespend.py` are now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited abandoned/conflicted
  transaction handling, `bumpfee`/`psbtbumpfee` behavior, wallet conflict
  tracking, cloned/malleated transaction accounting, and double-spend
  transaction accounting under the current legacy-compatible PQC profile. The
  next owned follow-on remains `feature_coinstatsindex_compatibility.py` when
  real prior PQBTC release assets exist, with transaction construction,
  transaction simulation, and remaining wallet transaction breadth beyond this
  bumpfee/conflict gate as the local alternate.
- 2026-04-28: `wallet_basic.py`, `wallet_create_tx.py`, and
  `wallet_simulaterawtx.py` are now promoted into the canonical `pq_required`
  gate and locally revalidated with the build-tree functional runner. The
  owned boundary covers restored inherited basic wallet behavior, transaction
  creation, and raw transaction simulation under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist, with inherited raw transaction signing, descriptor import,
  migration, and remaining wallet transaction breadth beyond this construction
  and simulation gate as the local alternate.
- 2026-04-28: `wallet_importdescriptors.py` and
  `wallet_signrawtransactionwithwallet.py` are now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers restored inherited descriptor import and
  raw transaction signing behavior under the current legacy-compatible PQC
  profile. `wallet_migration.py` was still locally blocked at this dated
  checkpoint because previous-release fixtures were unavailable. PR `#163`
  later classified it as `legacy_only`. The next owned follow-on at that time
  remained `feature_coinstatsindex_compatibility.py`, with remaining wallet
  transaction breadth beyond this raw-signing/import gate as the local
  alternate.
- 2026-04-29: `wallet_importprunedfunds.py`, `wallet_timelock.py`,
  `wallet_orphanedreward.py`, and `wallet_v3_txs.py` are now promoted into the
  canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers restored inherited
  import-pruned-funds, timelock, orphaned reward, and v3/TRUC wallet behavior
  under the current legacy-compatible PQC profile. `wallet_migration.py`
  remains blocked locally because previous-release fixtures are unavailable.
  The next owned follow-on remains `feature_coinstatsindex_compatibility.py`
  when real prior PQBTC release assets exist, with `wallet_crosschain.py`,
  `wallet_createwalletdescriptor.py`, and `wallet_backwards_compatibility.py`
  as the local alternate backlog.
- 2026-04-29: `wallet_createwalletdescriptor.py` and `wallet_crosschain.py`
  are now promoted into the canonical `pq_required` gate and locally
  revalidated with the build-tree functional runner. The owned boundary covers
  inherited xpub descriptor creation, explicit PQ-only active-manager
  rejection, and cross-genesis wallet load/restore rejection under the current
  legacy-compatible PQC profile. `wallet_backwards_compatibility.py` and
  `wallet_migration.py` remain blocked locally because previous-release
  fixtures are unavailable. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the next local step is a non-wallet backlog tranche.
- 2026-04-29: `feature_blocksdir.py`, `feature_blocksxor.py`,
  `feature_fastprune.py`, `feature_remove_pruned_files_on_startup.py`, and
  `feature_index_prune.py` are now promoted into the canonical `pq_required`
  gate and locally revalidated with the build-tree functional runner. The
  owned boundary covers external block storage, XORed blk/rev handling,
  `-fastprune` large-block admission, pruned-file cleanup on startup, and
  blockfilter/coinstats index behavior under prune. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py` when real prior PQBTC
  release assets exist; otherwise the local storage/import alternate is
  `feature_loadblock.py`.
- 2026-04-29: `feature_loadblock.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers linearized `bootstrap.dat` production from
  live PQBTC regtest block files and `-loadblock` import convergence on a
  disconnected peer. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the local chainstate alternate is
  `feature_utxo_set_hash.py`.
- 2026-04-30: `feature_utxo_set_hash.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers the bounded raw `OP_TRUE` chainstate
  sequence, manual MuHash equality, and fixed PQBTC `hash_serialized_3` /
  `muhash` constants. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the local txoutset/index alternate is
  `feature_coinstatsindex.py`.
- 2026-04-30: `feature_coinstatsindex.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers direct-mined raw `OP_TRUE` txoutset deltas,
  indexed-vs-non-indexed `gettxoutsetinfo()` parity, verbose block accounting,
  restart, reindex, reindex-chainstate, reorg, and stale-index recovery on the
  bounded PQBTC dataset. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the local restart/index alternate is
  `feature_reindex.py`.
- 2026-04-30: `feature_reindex.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers repeated `-reindex` and
  `-reindex-chainstate` recovery, out-of-order blockfile recovery, expected
  debug markers, and interrupted blockfilter reindex resume without wiping the
  existing LevelDB. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the local restart/index alternate is
  `feature_reindex_init.py`.
- 2026-05-01: `feature_reindex_init.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers missing `blocks/index` startup failure,
  explicit `-reindex` / `-reindex-chainstate` recovery guidance, the
  noninteractive reindex-acceptance path, and return to height `200`. The next
  owned follow-on remains `feature_coinstatsindex_compatibility.py` when real
  prior PQBTC release assets exist; otherwise the local restart/index
  alternate is `feature_reindex_readonly.py`.
- 2026-05-01: `feature_reindex_readonly.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers `-fastprune` blockfile rollover,
  read-only and host-level immutable treatment of the first blk file when
  supported, successful `-reindex -fastprune` restart, the expected
  `Reindexing finished` marker, preserved chain height, and cleanup permission
  restoration. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the local alternate should be a fresh bounded
  `pq_backlog` migration decision outside the restart/reindex family.
- 2026-05-03: `feature_versionbits_warning.py` is now promoted into the
  canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers warning-free behavior below the
  unknown-bit threshold, active unknown-rules warnings through mining and
  network info, and `alertnotify` output once the unknown versionbit activates
  on regtest. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the local alternate should be another bounded
  `pq_backlog` migration decision from the remaining validation, mempool, or
  mining backlog.
- 2026-05-03: `feature_bip68_sequence.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers sequence-lock disable-flag behavior,
  `non-BIP68-final` rejection and acceptance across confirmed and unconfirmed
  inputs, pre-CSV-activation block acceptance for BIP68-invalid spends,
  mempool cleanup after reorg, suite-local CSV activation, and version-2 relay
  standardness. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local validation candidates are
  `feature_cltv.py` and `feature_csv_activation.py`.
- 2026-05-03: `feature_cltv.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers buried BIP65 deployment metadata,
  pre-activation acceptance of CLTV-invalid transactions in blocks,
  post-activation block-version enforcement, exact mempool and block rejection
  reasons for CLTV failures, and valid CLTV spend acceptance. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist; otherwise the adjacent CSV activation surface is
  now covered by the required gate.
- 2026-05-03: `feature_csv_activation.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers suite-local activation for BIP68, BIP112,
  and BIP113; pre-activation acceptance; post-activation rejection and
  acceptance across relative locktime, CHECKSEQUENCEVERIFY, and MedianTimePast
  nLockTime cases; and exact block rejection reasons. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py` when real prior PQBTC
  release assets exist; otherwise the local alternate should be another
  bounded `pq_backlog` migration decision from the remaining validation,
  mempool, or mining backlog.
- 2026-05-03: `feature_pruning.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers automatic and manual pruning over large
  block files, stale-block and deep-reorg retention, redownload of previously
  pruned block data, invalid prune option handling, `scanblocks` behavior over
  pruned data, pruneheight handling when undo data is absent, and wallet
  load/rescan boundaries where wallet support is compiled. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist; otherwise the local alternate should be another
  bounded `pq_backlog` migration decision from the remaining validation,
  mempool, or mining backlog.
- 2026-05-04: `mempool_accept.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers inherited raw transaction
  `testmempoolaccept` behavior, reject-reason stability, fee and replacement
  checks, standardness and resource-envelope policy, anchor output handling,
  and confirmed bare-multisig policy under the current legacy-compatible PQC
  profile. `feature_unsupported_utxo_db.py` was probed and skipped locally
  because previous-release assets are unavailable. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py` when real prior PQBTC
  release assets exist; otherwise the adjacent local mempool candidate is
  `mempool_accept_wtxid.py` after a fresh targeted pass.
- 2026-05-04: `mempool_accept_wtxid.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers same-`txid` / different-`wtxid` child
  transactions, exact already-in-mempool and same-nonwitness-data reporting,
  preservation of the canonical mempool transaction, and rebroadcast of the
  canonical mempool `wtxid` to a newly connected peer. `mempool_compatibility.py`
  remains previous-release blocked. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_datacarrier.py` after a fresh targeted pass.
- 2026-05-04: `mempool_datacarrier.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers default uncapped OP_RETURN relay, disabled
  datacarrier relay, custom `-datacarriersize` acceptance and rejection
  boundaries, empty and zero-byte OP_RETURN payload handling, and
  `getmempoolinfo` datacarrier-size reporting under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_dust.py` after a fresh targeted pass.
- 2026-05-04: `mempool_dust.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers `-dustrelayfee=0` small-output acceptance,
  exact dust-threshold acceptance, one-satoshi-below-threshold `dust`
  rejection, OP_RETURN zero-threshold behavior, multiple configured dust relay
  fee rates, and the inherited standard output-script set under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_ephemeral_dust.py` after a fresh targeted pass.
- 2026-05-04: `mempool_ephemeral_dust.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers TRUC 1P1C ephemeral-dust package
  acceptance, zero-fee dust parent rules, sponsor cycling, restart behavior,
  fee-having and multidust rejection, missing ephemeral spends, reorg
  restoration, and disabled-minrelay batched sweep behavior under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_expiry.py` after a fresh targeted pass.
- 2026-05-05: `mempool_expiry.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers default and custom mempool expiry windows,
  parent and child eviction, independent transaction survival, prioritisation
  persistence after expiry, and mocktime-driven expiry checks under the
  current legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_limit.py` after a fresh targeted pass.
- 2026-05-05: `mempool_limit.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers full-mempool minimum-fee rejection, CPFP
  package admission below the mempool minimum, peer broadcast fee-filter
  behavior, immediate low-feerate package eviction, `-maxmempool` floor init
  rejection, mid-package eviction, mid-package replacement, and RBF carveout
  limit rejection under the current legacy-compatible PQC profile. The next
  owned follow-on remains `feature_coinstatsindex_compatibility.py` when real
  prior PQBTC release assets exist; otherwise the adjacent local mempool
  candidate is `mempool_package_limits.py` after a fresh targeted pass.
- 2026-05-05: `mempool_package_limits.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers combined in-mempool and in-package chain
  limits, ancestor and descendant count limits, bushy package ancestor
  accounting, ancestor-size limits, descendant-size limits, stable
  `package-mempool-limits` rejection, and acceptance after clearing the
  conflicting mempool state under the current legacy-compatible PQC profile.
  The next owned follow-on remains `feature_coinstatsindex_compatibility.py`
  when real prior PQBTC release assets exist; otherwise the adjacent local
  mempool candidate is `mempool_package_onemore.py` after a fresh targeted
  pass.
- 2026-05-05: `mempool_package_onemore.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers full ancestor-chain construction,
  ancestor and descendant limit rejection, oversized descendant rejection,
  package rejection diagnostics, direct-child carveout acceptance, independent
  chain admission, and single-conflict RBF replacement of the carveout chain
  under the current legacy-compatible PQC profile. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py` when real prior PQBTC
  release assets exist; otherwise the adjacent local mempool candidate is
  `mempool_package_rbf.py` after a fresh targeted pass.
- 2026-05-06: `mempool_package_rbf.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers 1-parent-1-child package replacement,
  singleton conflict replacement, additional-fee and incremental-relay-fee
  requirements, replacement-candidate caps, package and conflict-cluster shape
  rejection, feerate diagram rejection, TRUC zero-fee-parent package RBF, and
  mempool-ancestor conflict rejection under the current legacy-compatible PQC
  profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_packages.py` after a fresh targeted pass.
- 2026-05-06: `mempool_packages.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers default and custom ancestor/descendant
  chain limits, verbose ancestor and descendant accounting,
  `gettxspendingprevout` consistency, `prioritisetransaction` fee-delta
  accounting, cross-node custom limit propagation, and reorg disconnect
  handling under the current legacy-compatible PQC profile. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist; otherwise the adjacent local mempool candidate is
  `mempool_persist.py` after a fresh targeted pass.
- 2026-05-07: `mempool_persist.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers default `mempool.dat` reload,
  `-persistmempool=0` dump/load suppression, `savemempool` and
  `importmempool` RPC behavior, priority-delta and unbroadcast-set
  persistence, wallet watch-only accounting after reload where wallet support
  is compiled, cross-node mempool import, import union behavior, and disk-write
  failure handling under the current legacy-compatible PQC profile. The next
  owned follow-on remains `feature_coinstatsindex_compatibility.py` when real
  prior PQBTC release assets exist; otherwise the adjacent local mempool
  candidate is `mempool_reorg.py` after a fresh targeted pass.
- 2026-05-07: `mempool_reorg.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers coinbase-spend mempool removal when reorgs
  make coinbase spends immature, timelock non-final rejection and later
  acceptance, disconnected block transactions returning to the mempool, invalid
  descendant removal after deeper invalidation, and relay/request behavior for
  transactions from recently disconnected blocks under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_resurrect.py` after a fresh targeted pass.
- 2026-05-07: `mempool_resurrect.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers parent and descendant transactions mined
  across two blocks, full transaction resurrection into mempool after
  invalidating the first block, zero-confirmation reporting for the
  resurrected set, and replacement-block mining under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_sigoplimit.py` after a fresh targeted pass.
- 2026-05-07: `mempool_sigoplimit.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers bytes-per-sigop adjusted vsize accounting,
  ancestor and descendant size accounting with adjusted vsize, package-limit
  rejection for sigop-heavy bare multisig packages, direct package submission
  at the ancestor-size boundary, and legacy sigops standardness boundaries
  under the current legacy-compatible PQC profile. The next owned follow-on
  remains `feature_coinstatsindex_compatibility.py` when real prior PQBTC
  release assets exist; otherwise the adjacent local mempool candidate is
  `mempool_spend_coinbase.py` after a fresh targeted pass.
- 2026-05-07: `mempool_spend_coinbase.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers near-mature coinbase-spend admission,
  adjacent premature coinbase-spend rejection with
  `bad-txns-premature-spend-of-coinbase`, mined confirmation of the mature
  spend, and later admission of the formerly premature spend after height
  advances under the current legacy-compatible PQC profile. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist; otherwise the adjacent local mempool candidate
  is `mempool_truc.py` after a fresh targeted pass.
- 2026-05-08: `mempool_truc.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers v3/TRUC size limits, inheritance,
  replacement, reorg restoration, package ancestor checks, sibling eviction,
  `testmempoolaccept` diagnostics, and minrelay package combinations under the
  current legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_unbroadcast.py` after a fresh targeted pass.
- 2026-05-08: `mempool_unbroadcast.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers unbroadcast accounting, mempool.dat
  persistence across restart, peer delivery after reconnect and scheduler
  advance, suppression of repeat announcements to later peers, no re-addition
  for already-known transactions, and confirmation cleanup under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mempool candidate is
  `mempool_updatefromblock.py` after a fresh targeted pass.
- 2026-05-08: `mempool_updatefromblock.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers descendant and ancestor accounting after
  disconnected-block re-entry, disconnect-pool trimming at the
  `MAX_DISCONNECTED_TX_POOL_BYTES` boundary with coupled child removal, and
  standard chain-limit handling for non-standardly mined too-long chains under
  the current legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mining candidate is
  `mining_basic.py` after a fresh targeted pass.
- 2026-05-08: `mining_basic.py` is now promoted into the canonical
  `pq_required` gate and locally revalidated with the build-tree functional
  runner. The owned boundary covers `getmininginfo`, `getblocktemplate`
  witness commitment and version behavior, `submitblock` and `submitheader`
  validation, block-template fee and sigop ordering, `-blockmintxfee`
  filtering, BIP94 timewarp protection, pruned-block replay, block weight and
  reserved-weight startup boundaries, and generated coinbase height-locktime
  behavior under the current legacy-compatible PQC profile. The next owned
  follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
  PQBTC release assets exist; otherwise the adjacent local mining candidate is
  `mining_getblocktemplate_longpoll.py` after a fresh targeted pass.
- 2026-05-08: `mining_getblocktemplate_longpoll.py` is now promoted into the
  canonical `pq_required` gate and locally revalidated with the build-tree
  functional runner. The owned boundary covers stable `longpollid` reporting,
  longpoll wait behavior on a separate RPC connection, wakeup after another
  node generates a block, wakeup after the local node generates a block, and
  wakeup after a new mempool transaction enters under the current
  legacy-compatible PQC profile. The next owned follow-on remains
  `feature_coinstatsindex_compatibility.py` when real prior PQBTC release
  assets exist; otherwise the adjacent local mining candidate is
  `mining_mainnet.py` after a fresh targeted pass. That dated note was later
  followed by the now-landed `mining_prioritisetransaction.py` and
  `mining_template_verification.py` slices and is superseded by the live
  repo-local handoff above, which now treats the asset-dependent
  `feature_coinstatsindex_compatibility.py` promotion as the next owned slice
  once real prior PQBTC release assets exist locally.
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
- 2026-04-23: `wallet_address_types.py` no longer remains an inherited
  `dual_profile` suite. It is now a required PQ gate for the explicit
  address/RPC boundary, including inherited mixed-address `sendmany`; broader
  replacement-path address semantics remain outside this tranche.
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

- There is no active inventory blocker. The selected configuration-namespace
  gap is promoted, its platform default-datadir namespace is asserted, and no
  suites remain in `pq_backlog`.
- A further promotion requires a newly reviewed PQ confidence gap with a named
  owner, open tracking issue, bounded contract, targeted test, and acceptable
  CI cost. Until another selection exists, `HOLD` is the intended baseline
  rather than a blocked state.
- The five inherited previous-release compatibility suites are `legacy_only`,
  not asset-blocked promotion candidates. Do not reopen them or fabricate
  PQBTC v28.2 assets unless the supported migration policy changes. Their
  provenance boundary remains documented in
  [PREVIOUS_RELEASE_ASSET_BOUNDARY.md](PREVIOUS_RELEASE_ASSET_BOUNDARY.md).
