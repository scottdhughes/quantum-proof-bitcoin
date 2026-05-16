# PQBTC `mempool_reorg.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-REORG-POSTURE-v1
## Updated: 2026-05-07
## Frozen-By: track-a-phase1-20260507
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool behavior across
coinbase-spend reorgs and recently disconnected block transaction relay under
the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_reorg.py](../test/functional/mempool_reorg.py) suite owns the
two-node mempool reorg boundary:

- timelocked coinbase-spend transactions are rejected while non-final and later
  accepted when the chain height makes them final
- direct and indirect coinbase spends enter the mempool or chain in the three
  tested shapes: direct coinbase spend, coinbase spend in-chain with a child in
  mempool, and coinbase plus child both in-chain
- invalidating the most recent block returns the disconnected child
  transaction to the mempool while removing the no-longer-final timelocked
  transaction
- deeper invalidation makes the relevant coinbase spends immature and clears
  the mempool
- transactions from disconnected blocks are immediately available for explicit
  `getdata` relay even before normal announcement delay elapses
- very recent unannounced mempool transactions remain unavailable for early
  explicit requests until mock time advances
- after mock time advances, disconnected-block and mempool transactions are
  announced to the peer with the expected inventory behavior

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool resurrection, unbroadcast, sigop-limit,
  spend-coinbase, or
  mining-template suite is owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited reorg surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-07:

- `build/test/functional/test_runner.py --jobs=1 mempool_reorg.py`
  - result: passed
  - current posture:
    - immature coinbase-spend removal and disconnected-block return remain
      stable
    - timelock rejection/acceptance across the reorg path remains stable
    - explicit relay of recently disconnected block transactions remains green
      under the current legacy-compatible PQC profile

## Interpretation

- `mempool_reorg.py` is now a required inherited mempool reorg gate
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
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md),
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md),
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md), and
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
