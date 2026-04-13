# PQBTC `feature_pq_block_limits.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-PQ-BLOCK-LIMITS-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for the PQBTC block weight limit profile and
`-blockmaxweight` operator boundary.

## Current Owned Surface

The current passing
[feature_pq_block_limits.py](../test/functional/feature_pq_block_limits.py)
suite owns a small PQ-native block-profile contract:

- the node reports a `getblocktemplate()["weightlimit"]` of `16_000_000`
- restarting with `-blockmaxweight=16000000` preserves that same limit
- starting with `-blockmaxweight=16000001` fails with the expected init error
  because it exceeds the PQBTC consensus maximum block weight
- restarting again at the exact consensus ceiling succeeds and leaves the node
  able to continue mining blocks
- this suite remains protected by the required PQ-first functional gate

## What This Does Not Mean

This posture note does **not** mean:

- broader mining policy or template-construction behavior is covered
- mempool packing or fee-driven block assembly behavior is covered
- reorg handling is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/feature_pq_block_limits.py`
  - result: passed
  - current posture:
    - the advertised block weight limit remains exactly `16_000_000`
    - exact-ceiling `-blockmaxweight` restarts remain valid
    - over-ceiling `-blockmaxweight` startup still fails with the expected
      init error
    - the node still mines successfully after returning to the exact allowed
      limit

## Interpretation

- `feature_pq_block_limits.py` is now a fixed PQ-native consensus/profile slice
- it is a very small contract, but it is directly tied to the launch block
  profile and already belongs in the required PQ gate
- the next clean follow-on is
  [feature_pq_reorg.py](../test/functional/feature_pq_reorg.py), which is the
  adjacent PQ-native reorg/mempool reconciliation surface and is already green
  under the current harness
- the slower storage/import alternate remains
  [feature_loadblock.py](../test/functional/feature_loadblock.py)
