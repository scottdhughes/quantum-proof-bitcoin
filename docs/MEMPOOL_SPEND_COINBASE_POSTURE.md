# PQBTC `mempool_spend_coinbase.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-SPEND-COINBASE-POSTURE-v1
## Updated: 2026-05-07
## Frozen-By: track-a-phase1-20260507
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool coinbase-spend maturity
policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_spend_coinbase.py](../test/functional/mempool_spend_coinbase.py)
suite owns the mempool coinbase-spend maturity boundary:

- the chain is invalidated to a height where one coinbase spend is mature for
  the next block while the adjacent coinbase spend is still premature
- the near-mature coinbase spend enters the mempool
- the premature coinbase spend is rejected with
  `bad-txns-premature-spend-of-coinbase`
- the mempool contains only the mature coinbase spend before mining
- mining one block confirms the mature coinbase spend and clears the mempool
- after height advances, the previously premature coinbase spend is accepted
  into the mempool

## What This Does Not Mean

This posture note does **not** mean:

- the broader mining-template or orphan
  transaction suites are owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited coinbase maturity
  surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-07:

- `build/test/functional/test_runner.py --jobs=1 mempool_spend_coinbase.py`
  - result: passed
  - current posture:
    - near-mature coinbase-spend admission remains stable
    - premature coinbase-spend rejection keeps the expected policy reason
    - the formerly premature spend is accepted after the chain height advances

## Interpretation

- `mempool_spend_coinbase.py` is now a required inherited mempool
  coinbase-spend maturity gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md),
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md),
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md),
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md),
  [mempool_unbroadcast.py](MEMPOOL_UNBROADCAST_POSTURE.md),
  [mempool_updatefromblock.py](MEMPOOL_UPDATEFROMBLOCK_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
