# PQBTC `mempool_packages.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PACKAGES-POSTURE-v1
## Updated: 2026-05-06
## Frozen-By: track-a-phase1-20260506
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool ancestor/descendant
package tracking under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_packages.py](../test/functional/mempool_packages.py) suite owns the
two-node mempool package accounting boundary:

- default ancestor-chain admission succeeds up to the configured limit and the
  next chained transaction is rejected with `too-long-mempool-chain`
- `getmempoolentry`, `getrawmempool`, `getmempoolancestors`, and
  `getmempooldescendants` report consistent ancestor/descendant counts, sizes,
  fees, dependencies, and spent-by relationships
- `gettxspendingprevout` stays consistent with each mempool spend in the
  ancestor chain
- `prioritisetransaction` fee deltas are reflected in ancestor and descendant
  modified-fee accounting before and after a mined-block invalidation
- a second node with custom ancestor and descendant limits accepts only the
  expected prefix of the relayed chains
- descendant chain limits reject the next chained transaction after the
  configured descendant ceiling
- block disconnect/reconnect handling preserves mempool consistency when a
  transaction depends on mined parents and one parent is not accepted back due
  to the custom ancestor limit

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool package suite is owned by this tranche
- persistence, broad package relay, package RBF, TRUC policy, mining-template
  behavior, or prior-release compatibility behavior is covered here
- PQ-native witness-size stress replaces this inherited accounting surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-06:

- `build/test/functional/test_runner.py --jobs=1 mempool_packages.py`
  - result: passed
  - current posture:
    - default and custom ancestor/descendant limits remain stable
    - verbose mempool package accounting remains internally consistent
    - fee-delta, cross-node propagation, and reorg disconnect handling remain
      green under the current legacy-compatible PQC profile

## Interpretation

- `mempool_packages.py` is now a required inherited mempool
  ancestor/descendant tracking gate
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
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md),
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md),
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md), and
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
