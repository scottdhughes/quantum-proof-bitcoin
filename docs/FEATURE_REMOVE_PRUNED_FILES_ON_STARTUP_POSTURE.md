# PQBTC `feature_remove_pruned_files_on_startup.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-REMOVE-PRUNED-FILES-ON-STARTUP-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for prune-triggered blk/rev file removal and
startup cleanup under `-fastprune -prune=1`.

## Current Owned Surface

The current passing
[feature_remove_pruned_files_on_startup.py](../test/functional/feature_remove_pruned_files_on_startup.py)
suite owns a small prune-lifecycle contract:

- the node can mine enough blocks under `-fastprune -prune=1` to create
  multiple blk/rev files
- `pruneblockchain(600)` removes pruned blk/rev files immediately on platforms
  where open file descriptors do not block deletion
- the Windows-specific open-file behavior remains explicit: open blk/rev file
  descriptors can delay deletion until restart
- after closing those file descriptors, restarting the node removes the delayed
  pruned files
- restarting with `-reindex` wipes the prior pruned blk/rev set and recreates
  a fresh `blk00000.dat` / `rev00000.dat` pair at height 0

## What This Does Not Mean

This posture note does **not** mean:

- prune-plus-index interaction is covered
- blockfilter or coinstats index recovery under prune is covered
- broader reorg or index prune-lock behavior is covered
- this suite should move into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/feature_remove_pruned_files_on_startup.py`
  - result: passed
  - current posture:
    - prune-triggered blk/rev removal still behaves as expected under
      `-fastprune -prune=1`
    - platform-specific delayed deletion with open file descriptors remains
      explicit
    - restart after closing file descriptors completes the pending cleanup
    - `-reindex` wipes the prior pruned files and recreates a fresh two-file
      blk/rev baseline

## Interpretation

- `feature_remove_pruned_files_on_startup.py` is now an owned prune-lifecycle
  cleanup slice
- it is not the broader prune-plus-index migration surface
- the next adjacent tranche is
  [feature_index_prune.py](../test/functional/feature_index_prune.py), which is
  the broader prune-plus-index matrix and is already green under the current
  harness
