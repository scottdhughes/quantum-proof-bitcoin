# PQBTC `mempool_package_limits.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PACKAGE-LIMITS-POSTURE-v1
## Updated: 2026-05-05
## Frozen-By: track-a-phase1-20260505
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited package ancestor and descendant
limit policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_package_limits.py](../test/functional/mempool_package_limits.py)
suite owns the single-node package-limit boundary:

- packages that only exceed chain limits when in-mempool and in-package
  transactions are counted together fail with stable `package-mempool-limits`
  errors
- chain-limit accounting covers `24+2`, `2+24`, and `13+13`
  mempool/package transaction splits
- descendant-count accounting covers A-shaped and two-leg package topologies
  where a shared mempool ancestor would exceed descendant limits
- ancestor-count accounting covers V-shaped, Y-shaped, and bushy package
  topologies where the lowest in-package descendant exceeds ancestor limits
- ancestor-size accounting covers two large independent mempool parents plus
  an in-package parent/child pair
- descendant-size accounting covers a top mempool ancestor with two large
  descendant legs that continue into the package
- the same package transactions are accepted after mining a block clears the
  pre-submitted mempool transactions

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool package suite is owned by this tranche
- one-more-descendant carveout, package RBF, package relay, persistence,
  broad reorg behavior, TRUC policy, mining-template behavior, or
  prior-release compatibility behavior is covered here
- PQ-native witness-size stress replaces this inherited package-limit surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-05:

- `build/test/functional/test_runner.py --jobs=1 mempool_package_limits.py`
  - result: passed
  - current posture:
    - combined in-mempool and in-package ancestor/descendant counting remains
      stable
    - package count and size limits reject with the expected
      `package-mempool-limits` boundary
    - the packages become acceptable once the conflicting mempool state is
      cleared by mining

## Interpretation

- `mempool_package_limits.py` is now a required inherited package
  ancestor/descendant limit policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md), and
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
