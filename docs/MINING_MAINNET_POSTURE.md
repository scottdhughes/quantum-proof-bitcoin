# PQBTC `mining_mainnet.py` Posture

## Status: ACTIVE
## Spec-ID: MINING-MAINNET-POSTURE-v1
## Updated: 2026-06-11
## Frozen-By: track-a-phase3-20260610
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited alternate-mainnet
difficulty-adjustment mining behavior under the current legacy-compatible PQC
profile.

## Current Owned Surface

The current passing [mining_mainnet.py](../test/functional/mining_mainnet.py)
suite owns the deterministic alternate-mainnet retarget boundary:

- deterministic `data/mainnet_alt.json` block timestamp and nonce data is
  loaded for the first 2016 blocks
- the first 2015 blocks are accepted at difficulty 1 on the alternate mainnet
  chain
- `getmininginfo` reports current difficulty, bits, and target values for the
  first retarget period
- `getmininginfo` reports the next height, difficulty, bits, and target values
  for the first retarget boundary
- the first block of the second retarget period is accepted at difficulty 4
- historical `getblock` reporting for an earlier block keeps the original
  difficulty 1 bits and target values

## What This Does Not Mean

This posture note does **not** mean:

- mining prioritisation, package-template selection, or orphan transaction
  suites are owned by this tranche
- prior-release mempool or mining compatibility behavior is covered without
  real prior PQBTC release assets
- PQ-native block-size stress replaces this inherited alternate-mainnet
  retarget surface
- this tranche changes consensus, RPC, wallet, P2P, descriptor, or policy
  behavior

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-06-10:

- `build/test/functional/test_runner.py --jobs=1 mining_mainnet.py`
  - result: passed
  - current posture:
    - deterministic alternate-mainnet block construction remains green
    - first-period and second-period difficulty reporting remains stable
    - historical block difficulty reporting remains stable under the current
      legacy-compatible PQC profile

## Interpretation

- `mining_mainnet.py` is now a required inherited alternate-mainnet
  difficulty-adjustment mining gate
- it complements, but does not replace,
  [mining_basic.py](MINING_BASIC_POSTURE.md) and
  [mining_getblocktemplate_longpoll.py](MINING_GETBLOCKTEMPLATE_LONGPOLL_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mining
  `pq_backlog` migration decision, with
  `mining_template_verification.py` the adjacent candidate after a fresh
  targeted pass
