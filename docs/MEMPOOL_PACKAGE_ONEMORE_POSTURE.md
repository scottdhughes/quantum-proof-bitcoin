# PQBTC `mempool_package_onemore.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PACKAGE-ONEMORE-POSTURE-v1
## Updated: 2026-05-05
## Frozen-By: track-a-phase1-20260505
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited one-more-descendant package
carveout behavior under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_package_onemore.py](../test/functional/mempool_package_onemore.py)
suite owns the single-node one-more-descendant carveout boundary:

- a chain of `DEFAULT_ANCESTOR_LIMIT` transactions can be built from a
  confirmed wallet UTXO while a second independent unconfirmed chain remains
  available
- adding one more transaction to the chain tip is rejected with the expected
  `too-long-mempool-chain` ancestor-limit error
- adding a descendant from the middle of the chain is rejected with stable
  descendant-limit errors
- adding a descendant that spends both the chain and an independent mempool
  parent is still rejected by descendant limits
- oversized descendants that would exceed the carveout size remain rejected
- two-transaction package submission reports the first transaction's
  `too-long-mempool-chain` error and the child's missing-input result
- the direct child of the first chain transaction is accepted through the
  one-more-descendant carveout
- the independent second chain remains admissible after the carveout path
- a single direct-conflict replacement can RBF the chain that used the carveout
  rule

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool package suite is owned by this tranche
- broad package RBF, package relay, persistence, broad reorg behavior, TRUC
  policy, mining-template behavior, or prior-release compatibility behavior is
  covered here
- PQ-native witness-size stress replaces this inherited one-more-descendant
  carveout surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-05:

- `build/test/functional/test_runner.py --jobs=1 mempool_package_onemore.py`
  - result: passed
  - current posture:
    - one-more-descendant carveout admission remains stable
    - ancestor, descendant, oversized-child, and package rejection diagnostics
      keep their expected outcomes
    - direct-conflict RBF replacement of the carveout chain remains green under
      the current legacy-compatible PQC profile

## Interpretation

- `mempool_package_onemore.py` is now a required inherited
  one-more-descendant carveout policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_limit.py](MEMPOOL_LIMIT_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_rbf.py](MEMPOOL_PACKAGE_RBF_POSTURE.md),
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
  [mempool_persist.py](MEMPOOL_PERSIST_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_reorg.py](MEMPOOL_REORG_POSTURE.md),
  [mempool_resurrect.py](MEMPOOL_RESURRECT_POSTURE.md), and
  [mempool_sigoplimit.py](MEMPOOL_SIGOPLIMIT_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
