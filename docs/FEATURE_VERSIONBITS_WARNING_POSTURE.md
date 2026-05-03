# PQBTC `feature_versionbits_warning.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-VERSIONBITS-WARNING-POSTURE-v1
## Frozen-By: track-a-phase1-20260503
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for unknown versionbits warning behavior on
the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_versionbits_warning.py](../test/functional/feature_versionbits_warning.py)
suite owns a narrow warning-surface slice:

- one regtest node mines a full versionbits period using its deterministic
  address
- blocks just below the unknown-bit threshold do not emit versionbits warnings
  through `getmininginfo()` or `getnetworkinfo()`
- blocks at the unknown-bit threshold are accepted into the active warning
  path after the next period
- after restart and IBD exit, the node reports the expected unknown-rules
  warning through mining and network info
- `alertnotify` writes the unknown-rules warning to the configured alert file

## What This Does Not Mean

This posture note does **not** mean:

- new softfork deployment semantics are owned here
- Taproot replacement activation or active-boundary semantics are owned here
- mempool, mining-template, or wallet behavior is owned here

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-05-03:

- `build/test/functional/test_runner.py --jobs=1 feature_versionbits_warning.py`
  - result: passed
  - current posture:
    - warnings remain clear before the unknown-bit threshold
    - mining, network, and alertnotify warnings appear after unknown rules
      activate

## Interpretation

- `feature_versionbits_warning.py` is now a required PQBTC validation-warning
  gate
- it remains bounded to unknown versionbits warning and alert plumbing
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without those assets, the local follow-on should be another bounded
  `pq_backlog` migration decision, likely from the remaining validation,
  mempool, or mining backlog
