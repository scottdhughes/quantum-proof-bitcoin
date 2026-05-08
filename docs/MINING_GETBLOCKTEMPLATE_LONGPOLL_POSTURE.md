# PQBTC `mining_getblocktemplate_longpoll.py` Posture

## Status: ACTIVE
## Spec-ID: MINING-GETBLOCKTEMPLATE-LONGPOLL-POSTURE-v1
## Updated: 2026-05-08
## Frozen-By: track-a-phase1-20260508
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited `getblocktemplate` longpoll
behavior under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mining_getblocktemplate_longpoll.py](../test/functional/mining_getblocktemplate_longpoll.py)
suite owns the longpoll wakeup boundary:

- repeated `getblocktemplate` calls keep the same `longpollid` when no chain or
  mempool event occurs
- a longpoll request on a separate RPC connection waits when there is no
  wakeup event
- generating a block on another connected node wakes the longpoll request
- generating a block on the local node wakes the longpoll request
- submitting a new mempool transaction wakes the longpoll request within the
  expected polling window

## What This Does Not Mean

This posture note does **not** mean:

- mainnet mining, package-template selection, prioritisation, or orphan
  transaction suites are owned by this tranche
- prior-release mempool or mining compatibility behavior is covered without
  real prior PQBTC release assets
- PQ-native block-size stress replaces this inherited longpoll surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-08:

- `build/test/functional/test_runner.py --jobs=1 mining_getblocktemplate_longpoll.py`
  - result: passed
  - current posture:
    - stable longpoll IDs remain stable when nothing changes
    - chain updates from a peer node and the local node wake longpolls
    - mempool updates wake longpolls under the current legacy-compatible PQC
      profile

## Interpretation

- `mining_getblocktemplate_longpoll.py` is now a required inherited
  `getblocktemplate` longpoll gate
- it complements, but does not replace,
  [mining_basic.py](MINING_BASIC_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mining
  `pq_backlog` migration decision, with `mining_mainnet.py` the adjacent
  candidate after a fresh targeted pass
