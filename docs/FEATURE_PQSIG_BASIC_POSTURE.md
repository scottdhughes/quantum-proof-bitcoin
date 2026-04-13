# PQBTC `feature_pqsig_basic.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-PQSIG-BASIC-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for the minimal single-input, single-signature
PQ witness validation path on regtest.

## Current Owned Surface

The current passing
[feature_pqsig_basic.py](../test/functional/feature_pqsig_basic.py) suite owns a
bounded PQ-native signing surface:

- a wallet-funded P2WSH output using a PQ `OP_CHECKSIG` witness script can be
  constructed under the functional harness
- a valid PQ witness for that input is accepted by `testmempoolaccept`
- a truncated PQ witness is rejected at mempool admission
- a tampered-but-correct-length PQ witness is rejected at mempool admission
- the accepted transaction can be broadcast and confirmed successfully
- this suite remains protected by the required PQ-first functional gate

## What This Does Not Mean

This posture note does **not** mean:

- multisignature PQ witness behavior is covered
- wallet PSBT or descriptor-owned PQ signing behavior is covered
- relay, restart, or reorg behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_pqsig_basic.py`
  - result: passed
  - current posture:
    - the valid PQ witness is admitted and mined
    - both length corruption and content corruption are rejected before
      broadcast
    - the minimal single-signature PQ validation path remains stable

## Interpretation

- `feature_pqsig_basic.py` is now a fixed minimal PQ single-signature validation
  slice
- it is already protected by the required PQ-first functional gate
- the next clean follow-on is
  [feature_pqsig_multisig.py](../test/functional/feature_pqsig_multisig.py),
  which extends the same witness-validation surface to `OP_CHECKMULTISIG`
- the slower non-signing import/storage alternate remains
  [feature_loadblock.py](../test/functional/feature_loadblock.py)
