# PQBTC `mempool_package_rbf.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-PACKAGE-RBF-POSTURE-v1
## Updated: 2026-05-06
## Frozen-By: track-a-phase1-20260506
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited package replace-by-fee policy
under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_package_rbf.py](../test/functional/mempool_package_rbf.py) suite owns
the two-node package RBF boundary:

- a 1-parent-1-child package can replace its conflicting parent/child package
  when the child pays enough fee
- `testmempoolaccept` still rejects conflicts during subpackage evaluation with
  `bip125-replacement-disallowed`
- package RBF propagates across the second node through normal sync
- a child can pay to replace a parent's singleton conflict
- replacements must increase absolute fee, pay incremental relay cost, and
  preserve the required CPFP package shape
- replacements that would evict more than `MAX_REPLACEMENT_CANDIDATES` stay
  rejected, while the maximum allowed candidate count succeeds
- packages larger than 1-parent-1-child and packages with mempool ancestors are
  rejected for package RBF
- conflicting clusters with linear, multiple-parent, or multiple-child shapes
  are rejected with stable diagnostics
- replacement packages must improve the feerate diagram
- TRUC zero-fee-parent plus high-fee-child package RBF replaces the prior
  default-fee package
- package members that conflict with a parent mempool ancestor are rejected
  without evicting the ancestor

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool package suite is owned by this tranche
- broad package relay, persistence, broad reorg behavior, mining-template
  behavior, or prior-release compatibility behavior is covered here
- PQ-native witness-size stress replaces this inherited package RBF surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-06:

- `build/test/functional/test_runner.py --jobs=1 mempool_package_rbf.py`
  - result: passed
  - current posture:
    - package RBF admission and rejection diagnostics remain stable
    - absolute-fee, incremental-relay-fee, candidate-count, cluster-shape, and
      feerate-diagram constraints keep their expected outcomes
    - TRUC zero-fee-parent package RBF and mempool-ancestor conflict rejection
      remain green under the current legacy-compatible PQC profile

## Interpretation

- `mempool_package_rbf.py` is now a required inherited package RBF policy gate
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
  [mempool_packages.py](MEMPOOL_PACKAGES_POSTURE.md),
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
