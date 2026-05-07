# PQBTC `mempool_limit.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-LIMIT-POSTURE-v1
## Updated: 2026-05-05
## Frozen-By: track-a-phase1-20260505
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited mempool size, eviction, and
package-limit policy under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing [mempool_limit.py](../test/functional/mempool_limit.py)
suite owns the single-node mempool limit boundary:

- `-maxmempool=5` full-mempool behavior bumps `mempoolminfee` above the relay
  fee after filling the mempool
- transactions below the rolling mempool minimum are rejected with stable
  `mempool min fee not met` policy errors
- CPFP package submission can admit a parent below the mempool minimum when the
  child raises the package effective feerate
- accepted package transactions are rebroadcast while still respecting the
  peer fee filter
- packages that clear the rolling minimum but rank below existing descendant
  packages are rejected as `mempool full`
- `-maxmempool` values below the 5 MB floor fail init with the expected error
- mid-package eviction keeps all accepted package parents and the child in
  mempool while evicting lower-ranked existing transactions
- mid-package replacement does not leave stale descendants behind after a
  replacement transaction spends the original input
- individually evaluated package replacements do not expand descendant limits
  for other package members, preserving the RBF carveout rejection

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool policy suite is owned by this tranche
- broad package relay, package RBF, persistence, reorg behavior,
  mining-template behavior, or prior-release compatibility behavior is covered
  here
- PQ-native witness-size stress replaces this inherited mempool limit surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-05:

- `build/test/functional/test_runner.py --jobs=1 mempool_limit.py`
  - result: passed
  - current posture:
    - full-mempool minimum-fee and eviction behavior remains stable
    - CPFP package admission, immediate package eviction, and peer broadcast
      filtering keep their expected outcomes
    - mid-package eviction, mid-package replacement, and RBF carveout rejection
      remain green under the current legacy-compatible PQC profile

## Interpretation

- `mempool_limit.py` is now a required inherited mempool size, eviction, and
  package-limit policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_ephemeral_dust.py](MEMPOOL_EPHEMERAL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_package_limits.py](MEMPOOL_PACKAGE_LIMITS_POSTURE.md),
  [mempool_package_onemore.py](MEMPOOL_PACKAGE_ONEMORE_POSTURE.md),
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
