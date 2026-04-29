# PQBTC `feature_fastprune.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-FASTPRUNE-POSTURE-v1
## Updated: 2026-04-29
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

- generic restart or reindex behavior is covered
- bootstrap or `-loadblock` import behavior is covered
- broad pruning behavior outside the exact required storage/prune family is
  covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-29:

- `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
  - result: passed
  - current posture:
    - `-fastprune` still accepts the large-annex block path
    - the test stays on a non-signing OP_TRUE witness spend instead of
      reopening inherited wallet send semantics
    - the chain advances cleanly to height 201 without crash or hang

## Interpretation

- `feature_fastprune.py` is now a required narrow large-block admission gate
- it is not a general pruning or storage-lifecycle migration surface
- adjacent prune-cleanup and prune-plus-index behavior is now covered by the
  same required storage/prune gate family
