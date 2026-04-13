# PQBTC `mempool_pq_stress.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PQ-STRESS-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for two-node relay and restart stress under
PQ-native witness-heavy mempool traffic.

## Current Owned Surface

The current passing
[mempool_pq_stress.py](../test/functional/mempool_pq_stress.py) suite owns a
bounded two-node PQ-native stress surface:

- a sequence of witness-heavy RBF replacements remains accepted on both nodes
  and evicts prior replacements cleanly
- a larger batch of independent witness-heavy spends is accepted and relayed to
  both nodes
- restarting the receiving node preserves the relayed mempool set after
  reconnect and sync
- mining the stress block clears the witness-heavy transactions from both
  mempools
- invalidating that block restores the transactions to mempool on the mining
  node
- reconsidering the block clears those transactions again once the block is
  accepted
- the run emits a `PQBTCSLORecorder` success summary for the
  `invalidate-reconsider-restored-then-cleared` scenario
- this suite remains protected by the required PQ-first functional gate

## What This Does Not Mean

This posture note does **not** mean:

- multi-peer network partitions beyond the current two-node shape are covered
- signature-validity edge cases are covered
- storage/import bootstrap behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/mempool_pq_stress.py`
  - result: passed
  - current posture:
    - witness-heavy relay and RBF churn remain stable across both nodes
    - restart of the receiving node preserves the live mempool set
    - invalidate/reconsider restores and then clears the stress set as expected
    - the SLO recorder completes successfully for the stress scenario

## Interpretation

- `mempool_pq_stress.py` is now a fixed PQ-native relay/mempool stress slice
- it is already protected by the required PQ-first functional gate
- the next clean follow-on is
  [feature_pqsig_basic.py](../test/functional/feature_pqsig_basic.py), which is
  the cheapest adjacent PQ-native signing slice and is already green under the
  current harness
- the slower storage/import alternate remains
  [feature_loadblock.py](../test/functional/feature_loadblock.py)
