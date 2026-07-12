# PQBTC `feature_coinstatsindex.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-COINSTATSINDEX-POSTURE-v1
## Updated: 2026-07-12
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for `coinstatsindex` consistency against the
live PQBTC chainstate.

## Current Owned Surface

The current passing
[feature_coinstatsindex.py](../test/functional/feature_coinstatsindex.py) suite
owns a narrow txoutset/index slice:

- a raw `OP_TRUE` MiniWallet seeds the initial matured funds instead of the
  inherited default MiniWallet mempool path
- one direct-mined raw `OP_TRUE` self-transfer establishes the first
  non-coinbase txoutset delta before index-vs-non-index comparisons
- one direct-mined parent/child pair covers a spendable raw output plus an
  explicit `OP_RETURN` unspendable output without relying on inherited mempool
  acceptance
- `gettxoutsetinfo()` remains consistent between indexed and non-indexed nodes
  for current tip queries and indexed historical height/hash queries
- verbose `block_info` accounting for genesis, ordinary spends, explicit
  unspendables, and unclaimed rewards remains fixed
- restart, `-reindex`, `-reindex-chainstate`, reorg, and stale-index recovery
  behavior remain covered under the same bounded dataset

## What This Does Not Mean

This posture note does **not** mean:

- the inherited default MiniWallet mempool/send path is owned
- inherited Bitcoin Core v28.2 coinstats-index migration is on the PQBTC
  migration path

The first remains a separate follow-on surface. The second is retained as
explicit `legacy_only` reference coverage.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-30:

- `build/test/functional/test_runner.py --jobs=1 feature_coinstatsindex.py`
  - result: passed
  - current posture:
    - indexed and non-indexed `gettxoutsetinfo()` results still agree on the
      owned PQBTC dataset
    - historical height/hash queries, reorg handling, and reindex recovery
      remain stable
- pre-slice baseline:
  - the inherited default MiniWallet mempool self-transfer path failed with
    `scriptpubkey (-26)` and remains deferred rather than owned here

## Interpretation

- `feature_coinstatsindex.py` is now a required PQBTC txoutset/index gate
- it remains bounded to the direct-mined raw `OP_TRUE` dataset and current
  local index/reorg/reindex behavior
- the adjacent restart/index follow-on,
  [feature_reindex.py](../test/functional/feature_reindex.py), is now covered
  by the required gate
- the inherited alternate,
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py),
  is now `legacy_only`
- the compatibility suite hard-codes `versions=[None, 280200]`, but the
  inherited `v28.2` tag is Bitcoin Core rather than PQBTC, and the available
  PQBTC v1 tags identify as v30.2 and already use the fixed index path
- the provenance audit and reconsideration boundary are recorded in
  [PREVIOUS_RELEASE_ASSET_BOUNDARY.md](PREVIOUS_RELEASE_ASSET_BOUNDARY.md)
- this decision does not claim a passing PQBTC previous-release compatibility
  test; it prevents a skipped inherited suite from being promoted as one
