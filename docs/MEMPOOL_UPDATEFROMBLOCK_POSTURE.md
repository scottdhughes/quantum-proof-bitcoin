# PQBTC `mempool_updatefromblock.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-UPDATEFROMBLOCK-POSTURE-v1
## Updated: 2026-05-08
## Frozen-By: track-a-phase1-20260508
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool update-from-block reorg
accounting under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_updatefromblock.py](../test/functional/mempool_updatefromblock.py)
suite owns the reorg-time mempool accounting boundary:

- a 100-transaction tournament graph is mined in batches and re-added from
  disconnected blocks after an empty-fork reorg
- every re-added transaction preserves expected descendant count, descendant
  size, ancestor count, and ancestor size
- after mining the re-added graph, the mempool returns to empty and the
  MiniWallet UTXO view is rescanned
- large independent parent transactions exercise the
  `MAX_DISCONNECTED_TX_POOL_BYTES` disconnect-pool trimming boundary
- child transactions are recursively removed whenever their trimmed parent is
  dropped during reorg handling
- trimming removes the most recently confirmed parents and their children while
  preserving the earlier parent/child pairs
- a non-standardly mined chain that exceeds normal ancestor limits is returned
  to the mempool only up to the standard chain-limit boundary

## What This Does Not Mean

This posture note does **not** mean:

- the mining-template, mining basic, mining prioritisation, or orphan
  transaction suites are owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited reorg accounting
  surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-08:

- `build/test/functional/test_runner.py --jobs=1 mempool_updatefromblock.py`
  - result: passed
  - current posture:
    - descendant and ancestor accounting survives disconnected-block re-entry
    - disconnect-pool trimming preserves coupled parent/child removal behavior
    - long-chain reorg handling keeps the expected standard chain-limit
      boundary under the current legacy-compatible PQC profile

## Interpretation

- `mempool_updatefromblock.py` is now a required inherited mempool
  mining-template behavior reorg-accounting gate
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
  [mempool_unbroadcast.py](MEMPOOL_UNBROADCAST_POSTURE.md),
  [mempool_updatefromblock.py](MEMPOOL_UPDATEFROMBLOCK_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision, with
  `mining_getblocktemplate_longpoll.py` the adjacent candidate after a fresh
  targeted pass
