# PQBTC `feature_blocksxor.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-BLOCKSXOR-POSTURE-v1
## Updated: 2026-04-29
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for XORed block and undo file handling via
`-blocksxor`.

## Current Owned Surface

The current passing
[feature_blocksxor.py](../test/functional/feature_blocksxor.py) suite owns a
small storage-integrity contract:

- block and undo files can be created under `-blocksxor=1` without using the
  inherited wallet send path
- the node stores a random XOR key and uses it to encode mined `blk*.dat` and
  `rev*.dat` files
- manually un-XORing those files with the stored key produces a valid on-disk
  layout for a later `-blocksxor=0` restart
- restarting with `-blocksxor=0` still fails while the stored random key
  remains present
- deleting the stored key and restarting with `-blocksxor=0` succeeds
- `verifychain(checklevel=2, nblocks=0)` still validates the full blk/rev set
- restarting without the stored random key recreates the null XOR key state

## What This Does Not Mean

This posture note does **not** mean:

- broader block-file corruption handling is covered
- generic reindex behavior is owned here
- bootstrap or `-loadblock` import behavior is owned here
- transport or P2P block-delivery semantics are owned here

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-29:

- `build/test/functional/test_runner.py --jobs=1 feature_blocksdir.py feature_blocksxor.py feature_fastprune.py feature_remove_pruned_files_on_startup.py feature_index_prune.py`
  - result: passed
  - current posture:
    - deterministic coinbase mining creates multiple XORed blk/rev files under
      `-fastprune` without reopening inherited wallet send behavior
    - the stored XOR key can be used to manually decode the files
    - `-blocksxor=0` restart remains blocked until that stored random key is
      deleted
    - once the key is removed, full-chain blk/rev integrity verification passes
      and the null XOR key is recreated

## Interpretation

- `feature_blocksxor.py` is now a required block-storage integrity gate
- it is a narrow XOR-key and blk/rev file handling contract, not a broader
  chainstate or pruning migration surface
- adjacent `-fastprune`, prune-cleanup, and prune-plus-index behavior is now
  covered by the same required storage/prune gate family
