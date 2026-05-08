# PQBTC `mempool_unbroadcast.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-UNBROADCAST-POSTURE-v1
## Updated: 2026-05-08
## Frozen-By: track-a-phase1-20260508
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool unbroadcast delivery
policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_unbroadcast.py](../test/functional/mempool_unbroadcast.py) suite owns
the local unbroadcast delivery boundary:

- locally submitted raw transactions enter the unbroadcast set
- wallet-originated transactions enter the unbroadcast set when wallet support
  is compiled
- `getmempoolinfo()["unbroadcastcount"]` and verbose `getrawmempool`
  `unbroadcast` flags report the expected pending-delivery state
- unbroadcast transactions persist through `mempool.dat` after node restart
- after peers reconnect and the scheduler advances, the unbroadcast
  transactions are delivered to the peer mempool
- delivered transactions leave the first node's unbroadcast set
- a later peer connection does not receive repeat announcements for already
  delivered transactions
- rebroadcasting an already-known transaction does not re-add it to the
  unbroadcast set
- transactions removed by block confirmation are removed from the unbroadcast
  set before delivery confirmation

## What This Does Not Mean

This posture note does **not** mean:

- the mining-template or orphan transaction suites are
  owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited unbroadcast delivery
  surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-08:

- `build/test/functional/test_runner.py --jobs=1 mempool_unbroadcast.py`
  - result: passed
  - current posture:
    - unbroadcast accounting and per-entry reporting remain stable
    - restart persistence and peer delivery clear the unbroadcast state as
      expected
    - confirmation cleanup removes transactions from the unbroadcast set under
      the current legacy-compatible PQC profile

## Interpretation

- `mempool_unbroadcast.py` is now a required inherited mempool unbroadcast
  delivery gate
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
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md),
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision, with
  `mining_basic.py` the adjacent candidate after a fresh targeted pass
