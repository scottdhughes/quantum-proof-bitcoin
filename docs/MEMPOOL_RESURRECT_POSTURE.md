# PQBTC `mempool_resurrect.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-RESURRECT-POSTURE-v1
## Updated: 2026-05-07
## Frozen-By: track-a-phase1-20260507
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool transaction
resurrection after a multi-block reorg under the current legacy-compatible PQC
profile.

## Current Owned Surface

The current passing
[mempool_resurrect.py](../test/functional/mempool_resurrect.py) suite owns a
small one-node mempool resurrection boundary:

- three first-level spends are accepted and mined into one block
- three descendant spends are accepted and mined into the next block
- while both blocks are active, the mempool is empty and all six spend
  transactions are confirmed
- invalidating the first mined block disconnects both blocks and returns all
  six spend transactions to the mempool with zero confirmations
- mining a replacement block confirms the resurrected transaction set again
  and leaves the mempool empty

## What This Does Not Mean

This posture note does **not** mean:

- the broader mempool reorg, relay, update-from-block, sigop-limit,
  spend-coinbase, or
  mining-template suites are owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited resurrection surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-07:

- `build/test/functional/test_runner.py --jobs=1 mempool_resurrect.py`
  - result: passed
  - current posture:
    - disconnected parent and descendant transactions return to the mempool
      after the reorg
    - resurrected transactions are mined again in the replacement block
    - the mempool is empty after both the original confirmation path and the
      replacement confirmation path

## Interpretation

- `mempool_resurrect.py` is now a required inherited mempool resurrection gate
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
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md),
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md), and
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md), and
  [mempool_unbroadcast.py](MEMPOOL_UNBROADCAST_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
