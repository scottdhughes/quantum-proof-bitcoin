# PQBTC `wallet_startup.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-STARTUP-POSTURE-v1
## Updated: 2026-04-26
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_startup.py](../test/functional/wallet_startup.py) wallet startup and
load-on-startup contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_startup.py` is now a required PQ gate for restored inherited wallet
startup behavior. The owned boundary covers:

- node startup with no wallets loaded and an empty wallet directory
- default unnamed wallet auto-load after restart when no other wallets exist
- `createwallet(..., load_on_startup=true)` persistence across restart
- `createwallet(..., load_on_startup=false)` exclusion from restart loading
- `unloadwallet(..., load_on_startup=false)` removing startup persistence
- `loadwallet(..., load_on_startup=true)` adding startup persistence
- final restart state matching the configured startup wallet set

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader wallet creation, blank-wallet, or multiwallet semantics
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-26:

- `build/test/functional/test_runner.py --jobs=1 wallet_startup.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=41`, `pq_backlog=84`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet startup and
load-on-startup contract that already passes under the current PQC-compatible
legacy profile. The preferred Track A follow-on remains
`feature_coinstatsindex_compatibility.py` when real prior PQBTC release assets
exist locally. The subsequent creation/blank promotion covers the adjacent
creation surfaces; until compatibility assets exist, the repo-local wallet
alternate is now `wallet_multiwallet.py`.
