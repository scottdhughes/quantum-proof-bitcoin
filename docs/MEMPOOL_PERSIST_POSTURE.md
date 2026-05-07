# PQBTC `mempool_persist.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PERSIST-POSTURE-v1
## Updated: 2026-05-07
## Frozen-By: track-a-phase1-20260507
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool persistence and
runtime mempool import behavior under the current legacy-compatible PQC
profile.

## Current Owned Surface

The current passing
[mempool_persist.py](../test/functional/mempool_persist.py) suite owns the
three-node mempool persistence boundary:

- default shutdown/startup persistence reloads `mempool.dat`
- `-persistmempool=0` suppresses both mempool dump and startup load without
  overwriting a previously valid on-disk mempool
- `savemempool` recreates `mempool.dat` on demand and returns the expected
  filename
- `importmempool` can load a saved mempool at runtime, with optional
  priority-delta and unbroadcast-set restoration
- `prioritisetransaction` fee deltas persist for in-mempool transactions and
  for transactions prioritised before submission
- watch-only wallet accounting remains stable across mempool reload when wallet
  support is compiled
- a saved mempool can be moved between nodes and loaded successfully
- disk-write failure during `savemempool` returns the expected RPC error
- importing a saved mempool unions transactions into the existing mempool
  without replacing it and stacks fee deltas as expected
- the unbroadcast set persists and later announces to a peer after restart

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool reorg, resurrection, TRUC, or mining-template suite
  is owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited persistence surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-07:

- `build/test/functional/test_runner.py --jobs=1 mempool_persist.py`
  - result: passed
  - current posture:
    - default persistence and `-persistmempool=0` behavior remain stable
    - runtime `savemempool` / `importmempool` behavior remains stable
    - priority-delta, unbroadcast-set, cross-node import, and disk-write
      failure handling remain green under the current legacy-compatible PQC
      profile

## Interpretation

- `mempool_persist.py` is now a required inherited mempool persistence gate
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
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md), and
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
