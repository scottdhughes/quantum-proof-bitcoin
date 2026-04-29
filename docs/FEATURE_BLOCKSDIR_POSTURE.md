# PQBTC `feature_blocksdir.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-BLOCKSDIR-POSTURE-v1
## Updated: 2026-04-29
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for external block storage layout via
`-blocksdir`.

## Current Owned Surface

The current passing
[feature_blocksdir.py](../test/functional/feature_blocksdir.py) suite owns a
small storage-layout contract:

- startup still fails cleanly when `-blocksdir` points to a nonexistent path
- startup succeeds when `-blocksdir` points to an existing external directory
- block files are written under `<blocksdir>/<chain>/blocks`
- the block index remains under the node's local chain path at
  `<datadir>/<chain>/blocks/index`
- the node datadir does not silently recreate a local `blocks/` directory
- restarting with the same `-blocksdir` preserves that external layout

## What This Does Not Mean

This posture note does **not** mean:

- broader block-file corruption or mutation handling is covered
- pruning, reindex, or transport-layer block-delivery semantics are owned by
  this suite
- bootstrap or `-loadblock` import behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-29:

- `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
  - result: passed
  - current posture:
    - missing external blocksdir still fails at init
    - existing external blocksdir is used for mined blk/rev file storage while
      the local chain path keeps the block index
    - restart preserves the same split storage layout without creating a
      top-level datadir `blocks/` fallback

## Interpretation

- `feature_blocksdir.py` is now a required external-storage configuration gate
- it is a storage-layout contract, not a broader chainstate or block-format
  migration surface
- adjacent XOR, fastprune, prune-cleanup, and prune-plus-index behavior is now
  covered by the same required storage/prune gate family
