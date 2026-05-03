# PQBTC `feature_csv_activation.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-CSV-ACTIVATION-POSTURE-v1
## Frozen-By: track-a-phase1-20260503
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for CSV activation behavior on the current
PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_csv_activation.py](../test/functional/feature_csv_activation.py)
suite owns a narrow CSV activation slice:

- the suite activates CSV at the configured regtest activation height
- before activation, representative BIP68, BIP112, and BIP113 transactions are
  accepted in blocks
- after activation, BIP113 MedianTimePast nLockTime failures are rejected with
  `bad-txns-nonfinal`
- BIP68 relative locktime spends are rejected or accepted as height and time
  locks mature
- BIP112 CHECKSEQUENCEVERIFY failures for negative, empty-stack, and
  unsatisfied-lock cases are rejected with the expected script-failure reasons
- both transaction versions exercised by the suite follow the expected
  activation semantics

## What This Does Not Mean

This posture note does **not** mean:

- broad mempool package policy is owned here
- mining-template policy or fee-selection behavior is owned here
- wallet timelock behavior is owned here

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-03:

- `build/test/functional/test_runner.py --jobs=1 feature_csv_activation.py`
  - result: passed
  - current posture:
    - BIP68, BIP112, and BIP113 activation behavior passes under the current
      PQBTC profile
    - expected block rejection reasons are preserved after activation

## Interpretation

- `feature_csv_activation.py` is now a required PQBTC CSV activation gate
- it remains bounded to suite-local BIP68, BIP112, and BIP113 activation
  semantics
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded
  `pq_backlog` migration decision from the remaining validation, mempool, or
  mining backlog
