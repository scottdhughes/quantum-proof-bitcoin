# PQBTC `mempool_ephemeral_dust.py` Posture

## Status: ACTIVE
## Spec-ID: MEMPOOL-EPHEMERAL-DUST-POSTURE-v1
## Updated: 2026-05-04
## Frozen-By: track-a-phase1-20260504
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited ephemeral-dust package policy
under the current legacy-compatible PQC profile.

## Current Owned Surface

The current passing
[mempool_ephemeral_dust.py](../test/functional/mempool_ephemeral_dust.py)
suite owns the two-node ephemeral-dust package policy boundary:

- zero-fee TRUC parents with a single dust output are rejected individually but
  accepted when the package child spends the dust
- modified fees do not bypass dust-output policy, and prioritisation is
  rejected for in-mempool transactions with dust outputs
- package restart drops ephemeral-dust packages because individual mempool
  reload cannot reconstruct the CPFP package
- fee-having dust parents, modified-fee dust parents, and multiple dust
  outputs are rejected with stable package errors
- nonzero dust output values are accepted when minrelay is disabled
- non-TRUC dust packages keep the expected minrelay rejection under normal
  relay policy
- children that fail to spend a parent's ephemeral dust are rejected with
  `missing-ephemeral-spends`
- sponsor cycling can leave the zero-fee dust parent childless and unmined,
  then allow a later sweep
- reorg handling restores only valid ephemeral-dust shapes and rejects fee
  parents, multidust parents, and invalid follow-on TRUC chains
- disabled-minrelay mode covers non-TRUC and batched ephemeral-dust sweep
  behavior across many parents

## What This Does Not Mean

This posture note does **not** mean:

- every remaining mempool policy suite is owned by this tranche
- expiry, package relay, package RBF, persistence, broad reorg behavior,
  mining-template behavior, or prior-release compatibility behavior is covered
  here
- PQ-native witness-size stress replaces this inherited ephemeral-dust package
  policy surface

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-04:

- `build/test/functional/test_runner.py --jobs=1 mempool_ephemeral_dust.py`
  - result: passed
  - current posture:
    - TRUC 1P1C ephemeral-dust package acceptance remains stable
    - fee, multidust, missing-spend, restart, reorg, and minrelay edge cases
      keep their expected outcomes
    - two-node relay and mempool-content checks remain green under the current
      legacy-compatible PQC profile

## Interpretation

- `mempool_ephemeral_dust.py` is now a required inherited ephemeral-dust
  package policy gate
- it complements, but does not replace,
  [mempool_accept.py](MEMPOOL_ACCEPT_POSTURE.md),
  [mempool_accept_wtxid.py](MEMPOOL_ACCEPT_WTXID_POSTURE.md),
  [mempool_datacarrier.py](MEMPOOL_DATACARRIER_POSTURE.md),
  [mempool_dust.py](MEMPOOL_DUST_POSTURE.md),
  [mempool_expiry.py](MEMPOOL_EXPIRY_POSTURE.md),
  [mempool_pq_limits.py](MEMPOOL_PQ_LIMITS_POSTURE.md), and
  [mempool_pq_stress.py](MEMPOOL_PQ_STRESS_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded mempool
  or mining `pq_backlog` migration decision
