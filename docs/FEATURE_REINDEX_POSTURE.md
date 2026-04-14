# PQBTC `feature_reindex.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-REINDEX-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for restart-time reindex and
reindex-chainstate behavior on the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_reindex.py](../test/functional/feature_reindex.py) suite owns a narrow
restart/index slice:

- one node generates three post-genesis blocks and then restarts under
  `-reindex`, with startup blocking until the node returns to the same height
- the same three-block restart-time contract is exercised again under
  `-reindex-chainstate`
- repeated alternation between `-reindex` and `-reindex-chainstate` remains
  stable on the same datadir
- manual on-disk reordering of the first post-genesis blocks in `blk00000.dat`
  is tolerated by the reindex path
- the node emits the expected out-of-order block debug markers and still
  recovers the full `12`-block chain after restart
- an interrupted `-blockfilterindex -reindex` run can be resumed without wiping
  the existing blockfilter LevelDB on the later non-reindex startup

## What This Does Not Mean

This posture note does **not** mean:

- init-time block-index failure recovery is owned here
- read-only or immutable blockstore restart behavior is owned here
- this suite is promoted into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_reindex.py`
  - result: passed
  - current posture:
    - `-reindex` and `-reindex-chainstate` both return to the expected chain
      height on restart
    - out-of-order blockfile processing still recovers the full chain
    - interrupted reindex resumes without wiping the existing blockfilter index

## Interpretation

- `feature_reindex.py` is now a fixed PQBTC restart/reindex slice
- it remains `pq_backlog`, not a required PQ-first gate
- the next clean actionable follow-on is
  [feature_reindex_init.py](../test/functional/feature_reindex_init.py), which
  freezes the adjacent init-error recovery path and is already green here
- the environment-sensitive alternate is
  [feature_reindex_readonly.py](../test/functional/feature_reindex_readonly.py),
  which exercises immutable/read-only blockstore restart behavior
