# PQBTC `mining_prioritisetransaction.py` Posture

## Status: ACTIVE
## Spec-ID: MINING-PRIORITISETRANSACTION-POSTURE-v1
## Updated: 2026-06-11
## Frozen-By: track-a-phase3-20260611
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mining transaction
prioritisation behavior under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mining_prioritisetransaction.py](../test/functional/mining_prioritisetransaction.py)
suite owns the prioritisation and modified-fee mining boundary:

- `prioritisetransaction` and `getprioritisedtransactions` reject missing,
  malformed, and extra arguments with the expected RPC errors
- fee deltas are additive, survive replacement of the prioritised transaction,
  and are removed after mining
- diamond-shaped package prioritisation updates modified, ancestor, and
  descendant fee accounting while transactions are in and out of the mempool
- persisted fee deltas are cleared where the suite requires deterministic
  restart behavior
- prioritised low-fee transactions can be mined ahead of otherwise comparable
  low-fee transactions
- deprioritised high-fee transactions can remain in the mempool while other
  high-fee transactions are mined
- zero-delta calls do not create prioritisation entries
- a prioritised free transaction can satisfy relay-fee admission and enter the
  mempool
- `getblocktemplate` refreshes after a prioritisation change

## What This Does Not Mean

This posture note does **not** mean:

- package-template verification or orphan transaction suites are owned by this
  tranche
- prior-release mempool or mining compatibility behavior is covered without
  real prior PQBTC release assets
- PQ-native block-size stress replaces this inherited prioritisation surface
- this tranche changes consensus, RPC, wallet, P2P, descriptor, or policy
  behavior

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-06-11:

- `build/test/functional/test_runner.py --jobs=1 mining_prioritisetransaction.py`
  - result: passed
  - current posture:
    - prioritisation RPC validation remains stable
    - modified-fee accounting and mining selection effects remain green
    - template refresh after prioritisation remains green under the current
      legacy-compatible PQC profile

## Interpretation

- `mining_prioritisetransaction.py` is now a required inherited mining
  prioritisation gate
- it complements, but does not replace,
  [mining_basic.py](MINING_BASIC_POSTURE.md),
  [mining_getblocktemplate_longpoll.py](MINING_GETBLOCKTEMPLATE_LONGPOLL_POSTURE.md),
  and [mining_mainnet.py](MINING_MAINNET_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mining
  `pq_backlog` migration decision, with
  `mining_template_verification.py` the adjacent candidate after a fresh
  targeted pass
