# PQBTC `feature_pruning.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-PRUNING-POSTURE-v1
## Updated: 2026-05-03
## Frozen-By: track-a-phase1-20260503
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for the broad pruning lifecycle on the
current PQBTC node profile.

## Current Owned Surface

The current passing
[feature_pruning.py](../test/functional/feature_pruning.py) suite owns the
general pruning contract:

- automatic pruning waits until the minimum retain window is available, then
  removes old blk/rev files after additional large blocks are mined
- high stale-block rates can temporarily keep disk usage above target without
  corrupting the active chain
- a pruned node survives a deep reorg while retaining enough recent history to
  reorganize safely
- a previously pruned block can be redownloaded from a peer when it is needed
  for a later reorg
- manual pruning by block height and timestamp preserves expected no-op,
  future-height, negative-height, and pruneheight behavior
- startup rejects invalid prune combinations, including negative prune values,
  values below the minimum, `-prune` with `-txindex`, and `-prune` with
  `-reindex-chainstate`
- wallet load/rescan behavior on pruned nodes remains covered when wallet
  support is compiled, including the expected rejection when rescan would need
  pruned data
- `scanblocks` cannot return pruned data when false-positive filtering requires
  unavailable block data
- fetching a block without undo data does not incorrectly advance pruneheight

## What This Does Not Mean

This posture note does **not** mean:

- external `-blocksdir` storage behavior is owned here
- XORed block-file storage behavior is owned here
- prune-plus-index restart/recovery behavior is owned here
- previous-release compatibility behavior is owned here
- wallet spend, signing, or funding semantics are broadened by this gate

Those remain separate required or blocked follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-03:

- `build/test/functional/test_runner.py --jobs=1 feature_pruning.py`
  - result: passed
  - current posture:
    - broad automatic/manual pruning behavior passes under the current PQBTC
      profile
    - deep reorg and redownload behavior remain functional on a pruned node
    - scanblocks and pruneheight boundaries preserve expected pruned-data
      errors and accounting

## Interpretation

- `feature_pruning.py` is now a required broad pruning lifecycle gate
- it complements the narrower required storage/prune gates without replacing
  them
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded
  `pq_backlog` migration decision from the remaining validation, mempool, or
  mining backlog
