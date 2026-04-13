# PQBTC `mempool_pq_limits.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PQ-LIMITS-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for PQ-native mempool policy boundaries around
signature sizing, witness-item limits, and restart-stable large-witness churn.

## Current Owned Surface

The current passing
[mempool_pq_limits.py](../test/functional/mempool_pq_limits.py) suite owns a
small PQ-native mempool boundary:

- exact-size PQ signatures are accepted while short and long PQ signatures are
  rejected
- a `10_000` byte witness item is accepted while a `10_001` byte witness item
  is rejected
- the reject reason for the malformed oversized witness item remains stable
  across repeated admission attempts and after restart
- RBF replacement with large witness payloads remains valid across increasing
  fee steps
- independent large-witness spends can coexist in mempool, survive restart, and
  clear once mined
- the run emits a `PQBTCSLORecorder` success summary and records the stable
  oversized-witness reject reason
- this suite remains protected by the required PQ-first functional gate

## What This Does Not Mean

This posture note does **not** mean:

- the broader two-node relay stress matrix is covered
- reorg reconciliation is covered
- storage/import bootstrap behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/mempool_pq_limits.py`
  - result: passed
  - current posture:
    - PQ signature-size and witness-item boundaries remain enforced
    - the oversized-witness reject reason remains stable across restart
    - large-witness RBF churn and restart persistence remain valid
    - mined cleanup still clears the large-witness transactions from mempool

## Interpretation

- `mempool_pq_limits.py` is now a fixed PQ-native mempool policy slice
- it is already protected by the required PQ-first functional gate
- the next clean follow-on is
  [mempool_pq_stress.py](../test/functional/mempool_pq_stress.py), which is the
  heavier adjacent relay/stress variant and is already green under the current
  harness
- the slower storage/import alternate remains
  [feature_loadblock.py](../test/functional/feature_loadblock.py)
