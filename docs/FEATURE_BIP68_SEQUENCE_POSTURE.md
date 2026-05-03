# PQBTC `feature_bip68_sequence.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-BIP68-SEQUENCE-POSTURE-v1
## Frozen-By: track-a-phase1-20260503
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for BIP68 sequence-lock behavior on the
current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_bip68_sequence.py](../test/functional/feature_bip68_sequence.py)
suite owns a narrow BIP68 sequence-lock slice:

- sequence-lock disable-flag behavior remains accepted where expected
- non-final BIP68 spends are rejected with `non-BIP68-final`
- confirmed-input sequence locks are checked across randomized input sets
- unconfirmed-input sequence locks are checked for both height and time locks
- mempool consistency is maintained when a reorg reintroduces sequence-locked
  parents
- before CSV activation, a BIP68-invalid spend can still be included in a
  block
- CSV activates at the configured regtest test height for this suite
- version-2 transaction relay remains standard

## What This Does Not Mean

This posture note does **not** mean:

- CLTV activation behavior is owned here
- full CSV activation semantics across BIP68, BIP112, and BIP113 are owned here
- mempool package, mining-template, or wallet behavior is owned here

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-03:

- `build/test/functional/test_runner.py --jobs=1 feature_bip68_sequence.py`
  - result: passed
  - current posture:
    - BIP68 sequence-lock acceptance and rejection paths pass under the current
      PQBTC profile
    - pre-activation consensus behavior, reorg cleanup, CSV activation, and
      version-2 relay standardness pass

## Interpretation

- `feature_bip68_sequence.py` is now a required PQBTC sequence-lock validation
  gate
- it remains bounded to BIP68 sequence-lock behavior and the suite-local CSV
  activation boundary
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- the adjacent CLTV validation follow-on,
  [feature_cltv.py](../test/functional/feature_cltv.py), is now covered by
  the required gate
- without prior-release assets, the next local validation follow-on is
  [feature_csv_activation.py](../test/functional/feature_csv_activation.py)
