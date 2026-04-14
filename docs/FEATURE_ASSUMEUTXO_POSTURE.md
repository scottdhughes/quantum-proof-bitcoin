# PQBTC `feature_assumeutxo.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-ASSUMEUTXO-POSTURE-v1
## Frozen-By: track-a-phase1-20260414
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for assumeutxo snapshot activation and
follow-on chainstate/index behavior on the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_assumeutxo.py](../test/functional/feature_assumeutxo.py) suite owns a
narrow assumeutxo slice:

- regtest assumeutxo metadata is committed in
  [`src/kernel/chainparams.cpp`](../src/kernel/chainparams.cpp) for heights
  `110`, `200`, and `299` under the live PQBTC harness
- snapshot creation and activation at height `299` succeed across the current
  pruning, blockfilterindex, coinstatsindex, and txindex node profiles
- invalid snapshot file, metadata, hash, and chainstate cases are frozen
  against the current PQBTC snapshot contents and error texts
- the non-empty-mempool activation rejection is covered on a dedicated clean
  node using PQ-safe raw `P2WSH` funding rather than inherited wallet signing
  paths
- a snapshot-only inherited default MiniWallet spend is now an explicit
  negative control and is rejected with `scriptpubkey (-26)` instead of failing
  implicitly mid-suite
- restart, `-reindex`, `-reindex-chainstate`, and IBD-sync-from-assumeutxo
  behavior remain covered under the same fixed dataset

## What This Does Not Mean

This posture note does **not** mean:

- wallet behavior during assumeutxo background sync is owned here
- inherited MiniWallet mempool acceptance is rehabilitated here
- this suite is promoted into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-14:

- `python3 test/functional/feature_assumeutxo.py`
  - result: passed
  - current posture:
    - snapshot activation succeeds with the current regtest assumeutxo anchors
    - invalid snapshot and restart/reindex paths remain green
    - the inherited snapshot-only MiniWallet spend is explicitly rejected with
      `scriptpubkey (-26)`

## Interpretation

- `feature_assumeutxo.py` is now a fixed PQBTC assumeutxo activation slice
- it remains `pq_backlog`, not a required PQ-first gate
- the adjacent wallet-side background-sync surface is now owned by
  [wallet_assumeutxo.py](../test/functional/wallet_assumeutxo.py)
- the next clean actionable follow-on is
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py),
  if the required previous-release assets are available locally
- the environment-dependent alternate remains
  broader inherited miniscript funding/finalization rehab
