# PQBTC `wallet_reindex.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-REINDEX-POSTURE-v1
## Updated: 2026-04-24
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_reindex.py](../test/functional/wallet_reindex.py) wallet/reindex
interaction contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_reindex.py` is now a required PQ gate for restored inherited wallet
reindex behavior. The owned boundary covers:

- watch-only descriptor import with `timestamp=now` missing an older
  transaction before explicit rescan
- descriptor wallet birthtime adjustment to the chain MTP rescan window
- explicit `rescanblockchain` detection of the previously missed transaction
- trusted balance and confirmation preservation before restart
- `-reindex=1` restart completion while the wallet remains load-on-startup
- confirmed wallet transaction survival after reindex
- descriptor wallet birthtime convergence to the transaction time after reindex

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet fast-rescan, unconfirmed-rescan, or reorg-restore semantics
- wallet backup/restore compatibility beyond existing PQ-owned backup coverage
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-24:

- `build/test/functional/test_runner.py --jobs=1 wallet_reindex.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=35`, `pq_backlog=90`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet reindex interaction
contract that already passes under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moves to adjacent inherited wallet lifecycle surfaces:
fast rescan, unconfirmed rescan, and reorg restore behavior.
