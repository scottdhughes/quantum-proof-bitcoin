# PQBTC `feature_coinstatsindex.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-COINSTATSINDEX-POSTURE-v1
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
- previous-release coinstats index compatibility is owned in this local harness
- this suite is promoted into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_coinstatsindex.py`
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

- `feature_coinstatsindex.py` is now a fixed PQBTC txoutset/index slice
- it remains `pq_backlog`, not a required PQ-first gate
- the next clean actionable follow-on is
  [feature_reindex.py](../test/functional/feature_reindex.py), which is already
  green under the current harness and is the cheaper adjacent restart/index
  freeze
- the environment-dependent alternate is
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py),
  which stays relevant when previous-release test data is available
