# PQBTC `feature_fastprune.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-FASTPRUNE-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for the narrow `-fastprune` large-block
admission path.

## Current Owned Surface

The current passing
[feature_fastprune.py](../test/functional/feature_fastprune.py) suite owns a
small block-assembly contract:

- the node starts successfully under `-fastprune`
- a large witness-annex block can be assembled and mined without using the
  inherited wallet send path
- the transaction input uses the non-signing
  `MiniWalletMode.ADDRESS_OP_TRUE` path, keeping the slice focused on block
  construction rather than classical signing behavior
- the mined block is accepted and advances chain height from the initialized
  200-block test chain to 201

## What This Does Not Mean

This posture note does **not** mean:

- prune lifecycle or file-deletion behavior is covered
- restart or reindex behavior is covered
- prune-plus-index interaction is covered
- this suite should move into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/feature_fastprune.py`
  - result: passed
  - current posture:
    - `-fastprune` still accepts the large-annex block path
    - the test stays on a non-signing OP_TRUE witness spend instead of
      reopening inherited wallet send semantics
    - the chain advances cleanly to height 201 without crash or hang

## Interpretation

- `feature_fastprune.py` is now an owned narrow large-block admission slice
- it is not a general pruning or storage-lifecycle migration surface
- the next adjacent tranche is
  [feature_remove_pruned_files_on_startup.py](../test/functional/feature_remove_pruned_files_on_startup.py),
  which is the smallest prune-lifecycle follow-on after `blocksdir`,
  `blocksxor`, and `fastprune`
- the broader alternate remains
  [feature_index_prune.py](../test/functional/feature_index_prune.py)
