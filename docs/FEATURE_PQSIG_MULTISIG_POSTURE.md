# PQBTC `feature_pqsig_multisig.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-PQSIG-MULTISIG-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for the minimal 2-of-2 PQ multisignature
witness validation path on regtest.

## Current Owned Surface

The current passing
[feature_pqsig_multisig.py](../test/functional/feature_pqsig_multisig.py)
suite owns a bounded PQ-native multisignature surface:

- a wallet-funded P2WSH output using a PQ `OP_CHECKMULTISIG` witness script can
  be constructed under the functional harness
- a valid 2-of-2 PQ witness stack is accepted by `testmempoolaccept`
- a tampered second PQ witness is rejected at mempool admission
- the accepted multisignature spend can be broadcast and confirmed
  successfully
- this suite remains protected by the required PQ-first functional gate

## What This Does Not Mean

This posture note does **not** mean:

- threshold variants beyond the current 2-of-2 witness shape are covered
- wallet PSBT, descriptor, or RPC-owned multisignature semantics are covered
- relay, restart, reorg, or block-import behavior is covered

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_pqsig_multisig.py`
  - result: passed
  - current posture:
    - the valid 2-of-2 PQ multisignature witness is admitted and mined
    - a tampered multisignature witness is rejected before broadcast
    - the minimal PQ `OP_CHECKMULTISIG` validation path remains stable

## Interpretation

- `feature_pqsig_multisig.py` is now a fixed minimal PQ multisignature
  validation slice
- it is already protected by the required PQ-first functional gate
- the next clean follow-on is
  [feature_loadblock.py](../test/functional/feature_loadblock.py), which is the
  next unresolved block-import/storage bootstrap surface after the minimal
  signing gates
- broader inherited miniscript and classical multisig wallet flows remain
  deferred
