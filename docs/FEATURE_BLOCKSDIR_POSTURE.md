# PQBTC `feature_blocksdir.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-BLOCKSDIR-POSTURE-v1
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
- XORed block-file behavior is covered here
- pruning, reindex, or transport-layer block-delivery semantics are owned by
  this suite
- this suite should move into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/feature_blocksdir.py`
  - result: passed
  - current posture:
    - missing external blocksdir still fails at init
    - existing external blocksdir is used for mined blk/rev file storage while
      the local chain path keeps the block index
    - restart preserves the same split storage layout without creating a
      top-level datadir `blocks/` fallback

## Interpretation

- `feature_blocksdir.py` is now an owned external-storage configuration slice
- it is a storage-layout contract, not a broader chainstate or block-format
  migration surface
- the next adjacent tranche is
  [feature_blocksxor.py](../test/functional/feature_blocksxor.py), where the
  first current Track A break is in the inherited `MiniWallet`-based block-file
  setup path
