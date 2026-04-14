# PQBTC `feature_reindex_readonly.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-REINDEX-READONLY-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for `-reindex` restart behavior when the
blockstore contains a read-only or immutable block file.

## Current Owned Surface

The current passing
[feature_reindex_readonly.py](../test/functional/feature_reindex_readonly.py)
suite owns a narrow restart-family slice:

- one `-fastprune` node mines a large enough block to force creation of a
  second blk file
- the first blk file is made read-only and, when supported by the host,
  immutable through the platform toolchain
- restarting the node with `-reindex -fastprune` succeeds without requiring the
  block file to become writable again first
- the node emits the expected `Reindexing finished` debug marker and returns to
  the same block height after restart
- the file immutability bit is later removed and file permissions are restored
  for cleanup

## What This Does Not Mean

This posture note does **not** mean:

- generic `-reindex` and `-reindex-chainstate` restart behavior is owned here
- init-time block-index failure recovery is owned here
- this suite is promoted into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_reindex_readonly.py`
  - result: passed
  - current posture:
    - the local host used `chflags` to make the block file immutable
    - restart under `-reindex -fastprune` completed successfully and preserved
      chain height

## Interpretation

- `feature_reindex_readonly.py` is now a fixed PQBTC read-only blockstore
  reindex slice
- it remains `pq_backlog`, not a required PQ-first gate
- the next clean actionable follow-on is
  [feature_assumevalid.py](../test/functional/feature_assumevalid.py), which is
  a runnable local chainstate/validation slice and is already green here
- the environment-dependent alternate remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
