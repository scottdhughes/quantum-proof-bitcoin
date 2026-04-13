# PQBTC `feature_loadblock.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-LOADBLOCK-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for bootstrap import via `-loadblock` on the
current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_loadblock.py](../test/functional/feature_loadblock.py) suite owns a
bounded block-import/bootstrap surface:

- one source node generates the first `100` post-genesis blocks while the second
  node stays disconnected
- the linearization config is built from the live source-node environment,
  including the current regtest message-start bytes
- `linearize-hashes.py` and `linearize-data.py` produce a `bootstrap.dat` file
  from the source node's existing block files
- restarting the unsynced peer with `-loadblock=<bootstrap.dat>` blocks until
  import completes
- after import, the restarted node reaches height `100`
- the imported node converges on the same best block hash as the source node

## What This Does Not Mean

This posture note does **not** mean:

- pruning-plus-bootstrap behavior is covered
- index rebuild or reindex interactions are covered
- partial import, malformed bootstrap, or interrupted import recovery is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_loadblock.py`
  - result: passed
  - current posture:
    - linearization succeeds against the live PQBTC regtest block files
    - `bootstrap.dat` is produced and consumed successfully
    - the restarted unsynced node reaches the expected height and tip

## Interpretation

- `feature_loadblock.py` is now a fixed PQBTC bootstrap/import slice
- it remains `pq_backlog`, not a required PQ-first gate
- the next clean follow-on shifts back to wallet-level inherited miniscript
  funding/signing work
- broader prune, reindex, malformed-import, and interrupted-import behavior
  remain deferred
