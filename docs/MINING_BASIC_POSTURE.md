# PQBTC `mining_basic.py` Posture

## Status: ACTIVE
## Spec-ID: MINING-BASIC-POSTURE-v1
## Updated: 2026-06-11
## Frozen-By: track-a-phase1-20260508
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mining RPC and block-template
policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing [mining_basic.py](../test/functional/mining_basic.py) suite
owns the broad mining RPC and template boundary:

- `getmininginfo` reports the expected chain, height, bits, target,
  difficulty, next-block, networkhashps, and pooled transaction fields
- `getblocktemplate` builds the expected default witness commitment for the
  current mempool transaction set
- `-blockversion` overrides the advertised block template version and normal
  versionbits behavior resumes after restart
- `getblocktemplate` requires the segwit rule and advertises proposal
  capability without `coinbasetxn`
- `submitblock` and `submitheader` preserve decode, empty-block,
  missing-ancestor, bad-merkle-root, nonfinal, bad-prevblk, old-time,
  duplicate, and active-tip outcomes
- block templates order transactions by the expected fee and sigop accounting
  behavior
- `-blockmintxfee` filters transactions at and below many configured fee-rate
  boundaries
- BIP94 timewarp protection enforces the first-block retarget-period timestamp
  boundary
- `submitblock` can restore a previously pruned block to a pruned node when
  the host pruning run exposes that path
- `-blockmaxweight` and `-blockreservedweight` affect block template packing
  and reject invalid startup values
- generated blocks keep coinbase locktime tied to block height

## What This Does Not Mean

This posture note does **not** mean:

- longpoll, mainnet mining, block-template package selection, prioritisation,
  or orphan transaction suites are owned by this tranche
- prior-release mempool or mining compatibility behavior is covered without
  real prior PQBTC release assets
- PQ-native block-size stress replaces this inherited mining RPC surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-08:

- `build/test/functional/test_runner.py --jobs=1 mining_basic.py`
  - result: passed
  - current posture:
    - mining RPC fields and block-template construction remain stable
    - block submission, header submission, fee filtering, and weight-boundary
      behavior keep their expected outcomes
    - BIP94 timewarp, pruning replay, and generated coinbase locktime behavior
      remain green under the current legacy-compatible PQC profile

## Interpretation

- `mining_basic.py` is now a required inherited mining RPC and block-template
  policy gate
- it complements, but does not replace,
  [feature_pq_block_limits.py](FEATURE_PQ_BLOCK_LIMITS_POSTURE.md) and
  [mempool_updatefromblock.py](MEMPOOL_UPDATEFROMBLOCK_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mining
  `pq_backlog` migration decision, with
  `mining_template_verification.py` the adjacent candidate after a fresh
  targeted pass
