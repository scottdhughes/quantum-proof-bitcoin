# PQBTC `feature_reindex_init.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-REINDEX-INIT-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for init-time block-index failure recovery on
the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_reindex_init.py](../test/functional/feature_reindex_init.py) suite
owns a narrow init-recovery slice:

- one node is stopped and its on-disk `blocks/index` directory is removed
- the next startup without an explicit recovery choice fails with the exact
  block-database initialization error plus the explicit `-reindex` /
  `-reindex-chainstate` recovery guidance
- restarting with the current noninteractive reindex-acceptance test flag
  succeeds without manual intervention
- after that recovery startup, the node returns to height `200`

## What This Does Not Mean

This posture note does **not** mean:

- broader restart-time `-reindex` and `-reindex-chainstate` behavior is owned
  here
- immutable or read-only blockstore behavior is owned here

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-01:

- `build/test/functional/test_runner.py --jobs=1 feature_reindex_init.py`
  - result: passed
  - current posture:
    - the missing block-index directory triggers the expected init error
    - the noninteractive recovery path returns the node to height `200`

## Interpretation

- `feature_reindex_init.py` is now a required PQBTC init-recovery gate
- the adjacent read-only blockstore follow-on,
  [feature_reindex_readonly.py](../test/functional/feature_reindex_readonly.py),
  which extends the same restart family into immutable/read-only blockstore
  handling, is now covered by the required gate
- the environment-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
