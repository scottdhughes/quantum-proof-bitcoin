# PQBTC `wallet_fast_rescan.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-FAST-RESCAN-POSTURE-v1
## Updated: 2026-04-25
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_fast_rescan.py](../test/functional/wallet_fast_rescan.py)
descriptor-wallet fast-rescan contract under the current legacy-compatible PQC
profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_fast_rescan.py` is now a required PQ gate for restored inherited
descriptor-wallet fast-rescan behavior. The owned boundary covers:

- descriptor wallet backup before funded top-up activity
- ranged descriptor end-range address derivation and top-up detection
- fixed non-ranged descriptor funding detection
- block-filter fast rescan during wallet backup restore
- block-filter fast rescan during non-active descriptor import
- slow full-block rescan during wallet backup restore when block filters are
  disabled
- slow full-block rescan during non-active descriptor import when block filters
  are disabled
- parity between fast and slow rescan transaction discovery

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- unconfirmed-rescan or reorg-restore semantics
- wallet backup/restore compatibility beyond the fast-rescan backup fixture
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-25:

- `build/test/functional/test_runner.py --jobs=1 wallet_fast_rescan.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=36`, `pq_backlog=89`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited descriptor-wallet fast-rescan
contract that already passes under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moves to adjacent inherited wallet lifecycle surfaces:
unconfirmed rescan and reorg restore behavior.
