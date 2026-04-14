# PQBTC `feature_assumevalid.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-ASSUMEVALID-POSTURE-v1
## Frozen-By: track-a-phase1-20260414
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for `-assumevalid` signature-skipping
behavior on the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_assumevalid.py](../test/functional/feature_assumevalid.py) suite owns
a narrow validation slice:

- one handcrafted invalid-signature spend is buried just over two weeks deep in
  a custom block chain
- a node without `-assumevalid` rejects the bad block and stops at height `101`
- a node started with `-assumevalid=<bad-block-hash>` accepts the full
  `2202`-block chain once the invalid block is sufficiently buried
- the assumevalid-enabled node emits the expected debug markers for disabling
  and later re-enabling signature validation
- a second assumevalid-enabled node still rejects the same bad block when only
  `200` blocks are offered, because the invalid block is not yet buried deeply
  enough

## What This Does Not Mean

This posture note does **not** mean:

- assumeutxo snapshot loading or snapshot-chainstate behavior is owned here

That remains a separate follow-on surface.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-14:

- `python3 test/functional/feature_assumevalid.py`
  - result: passed
  - current posture:
    - the non-assumevalid node rejects the invalid block at height `102`
    - the deeply buried assumevalid path reaches height `2202`
    - the shallow assumevalid path still rejects the invalid block at height
      `102`

## Interpretation

- `feature_assumevalid.py` is now a fixed PQBTC assumevalid slice
- it is now `pq_required` as the required PQ-first assumevalid validation gate
- the adjacent snapshot-loading and wallet background-sync surfaces are now
  owned by
  [feature_assumeutxo.py](../test/functional/feature_assumeutxo.py) and
  [wallet_assumeutxo.py](../test/functional/wallet_assumeutxo.py)
- the next clean actionable follow-on is
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py),
  if the required previous-release assets are available locally
- the environment-dependent alternate remains
  broader inherited miniscript funding/finalization rehab
