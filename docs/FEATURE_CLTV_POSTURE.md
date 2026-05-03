# PQBTC `feature_cltv.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-CLTV-POSTURE-v1
## Frozen-By: track-a-phase1-20260503
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for CLTV activation and validation behavior
on the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_cltv.py](../test/functional/feature_cltv.py) suite owns a narrow
CLTV activation slice:

- buried BIP65 deployment metadata reports inactive, then active, at the
  configured regtest activation height
- before activation, CLTV-invalid transactions can still appear in a block
- after activation, version-3 blocks are rejected with the expected
  `bad-version(0x00000003)` marker
- all five representative CLTV failure modes are rejected by
  `testmempoolaccept` with the expected `mempool-script-verify-flag-failed`
  details
- the same invalid spends are rejected in blocks with the expected
  `block-script-verify-flag-failed` debug marker
- a version-4 block containing a valid CLTV spend is accepted after activation

## What This Does Not Mean

This posture note does **not** mean:

- full CSV activation behavior across BIP68, BIP112, and BIP113 is owned here
- broad mempool policy, mining-template, or wallet behavior is owned here
- Taproot replacement activation semantics are owned here

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-03:

- `build/test/functional/test_runner.py --jobs=1 feature_cltv.py`
  - result: passed
  - current posture:
    - CLTV activation metadata, pre-activation acceptance, post-activation
      version enforcement, invalid-spend rejection, and valid-spend acceptance
      pass under the current PQBTC profile

## Interpretation

- `feature_cltv.py` is now a required PQBTC CLTV validation gate
- it remains bounded to CLTV activation and CHECKLOCKTIMEVERIFY script
  validation
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the adjacent local validation follow-on is
  [feature_csv_activation.py](../test/functional/feature_csv_activation.py)
