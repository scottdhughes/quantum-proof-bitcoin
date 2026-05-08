# PQBTC `mempool_truc.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-TRUC-POSTURE-v1
## Updated: 2026-05-08
## Frozen-By: track-a-phase1-20260508
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited TRUC/v3 mempool policy under
the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_truc.py](../test/functional/mempool_truc.py) suite owns the TRUC/v3
mempool policy boundary:

- v3 transactions over the TRUC maximum vsize are rejected while equivalent v2
  transactions remain accepted
- children of v3 transactions enforce the TRUC child-size limit
- v3 and v2 replacements preserve direct TRUC policy and inheritance checks
- reorg restoration can re-enter disconnected transactions even when the
  resulting mempool shape would violate direct TRUC admission topology
- nondefault ancestor and descendant package limits still override TRUC package
  admission where appropriate
- package ancestor checks reject multiparent, oversized-child, and
  three-generation TRUC package shapes
- sibling eviction works only under the expected individual and package
  submission rules and keeps RBF fee and feerate constraints intact
- `testmempoolaccept` reports TRUC inheritance violations consistently for
  independent, in-package, and in-mempool parent cases
- minrelay combinations keep the expected distinction between zero-fee TRUC
  parents paid by children and non-TRUC equivalents

## What This Does Not Mean

This posture note does **not** mean:

- the unbroadcast, update-from-block, mining-template, or orphan transaction
  suites are owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited TRUC policy surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-08:

- `build/test/functional/test_runner.py --jobs=1 mempool_truc.py`
  - result: passed
  - current posture:
    - TRUC size, inheritance, and replacement policy remains stable
    - reorg restoration and sibling eviction boundaries keep their expected
      outcomes
    - package ancestor and minrelay combinations remain green under the current
      legacy-compatible PQC profile

## Interpretation

- `mempool_truc.py` is now a required inherited TRUC/v3 mempool policy gate
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
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision, with `mempool_unbroadcast.py` the
  adjacent candidate after a fresh targeted pass
