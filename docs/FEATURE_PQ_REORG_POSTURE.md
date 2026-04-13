# PQBTC `feature_pq_reorg.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-PQ-REORG-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for PQ-signed reorg handling and mempool
reconciliation across restart and competing branches.

## Current Owned Surface

The current passing
[feature_pq_reorg.py](../test/functional/feature_pq_reorg.py) suite owns a
small PQ-native chainstate/reorg contract:

- a PQ-signed spend from a wallet-funded P2WSH PQ output is accepted into the
  mempool and mined on the first branch
- a competing longer branch can overtake that mined spend after the nodes are
  disconnected and later reconnected
- restarting the first node before reconnect does not break the later reorg or
  mempool reconciliation path
- after the reorg to the competing tip, the previously mined PQ spend is
  reinserted into the mempool
- rebroadcast on the competing node remains tolerant of "already in mempool" or
  "already known" outcomes
- once the spend is mined on the winning branch, it is removed from both
  mempools and both nodes converge on the same final tip
- the run emits a `PQBTCSLORecorder` success summary for the
  `competing-branch-reinserted-then-remined` scenario

## What This Does Not Mean

This posture note does **not** mean:

- broader multi-transaction reorg conflict matrices are covered
- large-witness mempool churn or restart persistence boundaries are covered
- storage/import bootstrap behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/feature_pq_reorg.py`
  - result: passed
  - current posture:
    - PQ-signed spend reinsertion across a competing-branch reorg remains valid
    - node restart before reconnect does not break the reconciliation path
    - the spend is remined on the winning branch and cleared from both mempools
    - the SLO recorder completes successfully for this scenario

## Interpretation

- `feature_pq_reorg.py` is now a fixed PQ-native reorg/mempool reconciliation
  slice
- it is already protected by the required PQ-first functional gate
- the next clean follow-on is
  [mempool_pq_limits.py](../test/functional/mempool_pq_limits.py), which is the
  cheaper adjacent PQ-native mempool boundary and is already green under the
  current harness
- the slower storage/import alternate remains
  [feature_loadblock.py](../test/functional/feature_loadblock.py)
