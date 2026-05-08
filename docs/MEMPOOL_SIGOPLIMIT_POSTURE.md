# PQBTC `mempool_sigoplimit.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-SIGOPLIMIT-POSTURE-v1
## Updated: 2026-05-07
## Frozen-By: track-a-phase1-20260507
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool bytes-per-sigop
resource-envelope policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_sigoplimit.py](../test/functional/mempool_sigoplimit.py) suite owns
the mempool sigop adjusted-vsize boundary:

- default and custom `-bytespersigop` settings are exercised across a fixed
  range of sigop counts
- `testmempoolaccept` reports the sigop-equivalent vsize when it is larger
  than serialized vsize
- vsize reporting grows when serialized vsize is above the sigop-equivalent
  threshold
- ancestor and descendant size accounting use adjusted vsize for sigop-heavy
  transactions
- sigop-heavy bare multisig packages hit the expected package-size limit in
  package validation
- direct package submission admits the parent while rejecting the child at the
  ancestor-size boundary
- legacy P2SH sigops standardness rejects the too-large input set while the
  one-input-smaller transaction is accepted
- the non-standard high-sigop transaction remains mineable when explicitly
  included in a block

## What This Does Not Mean

This posture note does **not** mean:

- the broader spend-coinbase, unbroadcast, mining-template, or orphan
  transaction suites are owned by this tranche
- prior-release mempool compatibility behavior is covered without real prior
  PQBTC release assets
- PQ-native witness-size stress replaces this inherited sigop accounting
  surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-07:

- `build/test/functional/test_runner.py --jobs=1 mempool_sigoplimit.py`
  - result: passed
  - current posture:
    - bytes-per-sigop adjusted vsize remains stable across tested settings
    - package-limit rejection still uses adjusted vsize for sigop-heavy
      packages
    - legacy sigops standardness and explicit block mining boundaries remain
      green

## Interpretation

- `mempool_sigoplimit.py` is now a required inherited mempool sigop
  resource-envelope gate
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
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md),
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md),
  [mempool_spend_coinbase.py](MEMPOOL_SPEND_COINBASE_POSTURE.md), and
  [mempool_truc.py](MEMPOOL_TRUC_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
