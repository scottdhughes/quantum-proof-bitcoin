# PQBTC Wallet Bumpfee And Conflict Posture

## Status: ACTIVE
## Spec-ID: WALLET-BUMPFEE-CONFLICT-POSTURE-v1
## Updated: 2026-04-27
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet fee-bump, PSBT fee-bump, abandoned-conflict,
clone, and double-spend accounting contracts under the current
legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_abandonconflict.py](../test/functional/wallet_abandonconflict.py)
- [wallet_bumpfee.py](../test/functional/wallet_bumpfee.py)
- [wallet_conflicts.py](../test/functional/wallet_conflicts.py)
- [wallet_txn_clone.py](../test/functional/wallet_txn_clone.py)
- [wallet_txn_doublespend.py](../test/functional/wallet_txn_doublespend.py)

The owned boundary covers:

- abandoned transaction handling, balance/listing visibility, abandoned
  transactions in `listsinceblock`, and double-spend conflict handling
- `bumpfee` and `psbtbumpfee` option validation, fee-rate validation,
  confirmation-target validation, estimate-mode validation, change handling,
  non-RBF replacement rejection, non-owned input and PSBT behavior,
  descendant and abandoned-descendant behavior, dust/change/drop-to-fee
  behavior, `maxtxfee`, watch-only PSBT behavior, successor and re-bump
  behavior, spent-coin failure, metadata persistence, locked-wallet rejection,
  change address reuse, confirmed-output availability, replaced-output
  feerate checks, and `walletincrementalrelayfee` behavior
- block and mempool conflict tracking, reorg conflict state, inactive formerly
  conflicted transactions, conflict removal, combined block and mempool
  conflict handling, and parent mempool conflicts
- cloned or malleated transaction accounting across the default, `--segwit`,
  and `--mineblock` variants
- double-spend transaction accounting across the default and `--mineblock`
  variants

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- generic transaction construction, transaction simulation, or broad basic
  wallet behavior inside these fee-bump and conflict contracts
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-27:

- `build/test/functional/test_runner.py --jobs=1 wallet_abandonconflict.py wallet_bumpfee.py wallet_conflicts.py wallet_txn_clone.py wallet_txn_doublespend.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=69`, `pq_backlog=56`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet fee-bump,
abandoned-conflict, clone, double-spend, and conflict-tracking contracts that
already pass under the current PQC-compatible legacy profile.

The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moved to transaction construction, transaction simulation, and
basic wallet behavior beyond this bumpfee/conflict gate; that adjacent surface
is now covered by `WALLET_TRANSACTION_CONSTRUCTION_POSTURE.md`, so the current
local alternate is inherited raw transaction signing, descriptor import,
migration, and remaining wallet transaction breadth beyond the construction and
simulation gate.
