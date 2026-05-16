# PQBTC `mempool_expiry.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-EXPIRY-POSTURE-v1
## Updated: 2026-05-05
## Frozen-By: track-a-phase1-20260505
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool transaction expiry
policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing [mempool_expiry.py](../test/functional/mempool_expiry.py)
suite owns the single-node mempool expiry boundary:

- the default `DEFAULT_MEMPOOL_EXPIRY_HOURS` timeout keeps parent transactions
  in mempool until the configured expiry point
- `-mempoolexpiry=<n>` custom timeout behavior matches the same boundary
- a child transaction spending the expiring parent is evicted with its parent
- an independent transaction received later remains in mempool after the
  parent and child expire
- transaction prioritisation survives expiry and flips from `in_mempool=true`
  to `in_mempool=false`
- expiry is triggered through normal mempool admission after mocktime advances

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool policy suite is owned by this tranche
- package relay, package RBF, persistence, broad reorg behavior,
  mining-template behavior, or prior-release compatibility behavior is covered
  here
- PQ-native witness-size stress replaces this inherited expiry policy surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-05:

- `build/test/functional/test_runner.py --jobs=1 mempool_expiry.py`
  - result: passed
  - current posture:
    - default and custom mempool expiry windows remain stable
    - expired parent and child transactions are evicted together
    - independent transactions and prioritisation state preserve their expected
      behavior

## Interpretation

- `mempool_expiry.py` is now a required inherited mempool expiry policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md),
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md),
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md),
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md), and
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md), and
  [mempool_unbroadcast.py](MEMPOOL_UNBROADCAST_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
