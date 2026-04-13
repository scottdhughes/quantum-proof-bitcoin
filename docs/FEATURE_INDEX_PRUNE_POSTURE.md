# PQBTC `feature_index_prune.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-INDEX-PRUNE-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for blockfilter/coinstats index behavior in
conjunction with pruning.

## Current Owned Surface

The current passing
[feature_index_prune.py](../test/functional/feature_index_prune.py) suite owns
a bounded prune-plus-index matrix:

- pruned nodes with `-blockfilterindex=1`, `-coinstatsindex=1`, or both can
  sync indices linearly over RPC without relying on P2P sync ordering
- both indices remain queryable at the tip before and after pruning begins
- both indices remain queryable for already-pruned block heights while the
  index state is still available
- restarting without indices removes those RPC surfaces cleanly
- pruning exactly up to the indices' best block while the indices are disabled
  still allows later restart and continued index sync
- pruning past the indices' best block causes the expected init failures on
  restart until `-reindex` is used
- restarting with `-reindex` recovers the index state under prune
- prune-lock handling remains explicit in the reorg scenario and still lets the
  index fail safely instead of silently drifting

## What This Does Not Mean

This posture note does **not** mean:

- this suite should move into `pq_required`
- bootstrap or `-loadblock` import behavior is covered
- broader block-file import or external-storage behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/feature_index_prune.py`
  - result: passed
  - current posture:
    - blockfilter and coinstats indices remain usable before and after pruning
    - exact prune-to-index-height restart and continued sync remain valid
    - prune-past-index-height restart fails with the expected init errors until
      `-reindex` is used
    - the reorg scenario still emits the expected prune-lock movement and
      finishes cleanly

## Interpretation

- `feature_index_prune.py` is now an owned prune-plus-index matrix
- it is a higher-cost prune surface, but still a bounded functional contract
- the next clean follow-on is
  [feature_pq_block_limits.py](../test/functional/feature_pq_block_limits.py),
  which is a cheaper PQ-native block-profile slice
- the slower storage-import alternate remains
  [feature_loadblock.py](../test/functional/feature_loadblock.py)
