# PQBTC Address RPC Posture

## Status: ACTIVE
## Spec-ID: PQ-ADDRESS-RPC-POSTURE-v1
## Frozen-By: track-a-phase1-20260406
## Consensus-Relevant: NO

## Purpose

Define the supported address-generation RPC posture for PQ-only wallets under
the all-PQ Track A stance.

## Current Owned Address RPC Surface

The supported PQ-native address RPCs are:

- [getnewpqaddress](../src/wallet/rpc/addresses.cpp)
- [getrawpqchangeaddress](../src/wallet/rpc/addresses.cpp)

These are the owned receive/change entry points when a wallet's active state is
driven by ranged `pqpriv(...)` managers.

## Inherited RPC Boundary

The inherited address RPCs are still present:

- [getnewaddress](../src/wallet/rpc/addresses.cpp)
- [getrawchangeaddress](../src/wallet/rpc/addresses.cpp)

But for wallets whose active managers are entirely PQ-native, those inherited
RPCs are no longer part of the supported UX. They now reject immediately with a
PQ-specific instruction instead of falling through to generic keypool or
address-family errors.

Current RPC errors:

- `Active pqpriv() managers do not use inherited getnewaddress; use getnewpqaddress`
- `Active pqpriv() managers do not use inherited getrawchangeaddress; use getrawpqchangeaddress`

This applies to the inherited RPC surface itself, not only to the default
`bech32`-shaped call pattern. The goal is to keep PQ-only wallets from
silently drifting back into classical address-family semantics.

## Why This Exists

- Track A is explicitly all-PQ, not mixed-mode by default.
- Active PQ receive/change managers already have dedicated RPCs.
- Generic inherited address RPCs otherwise produce confusing failures or
  accidental classical-looking semantics when the wallet is actually PQ-only.

## What This Does Not Mean

This posture note does **not** mean:

- `wallet_address_types.py` is now an owned full PQ migration suite
- inherited legacy, P2SH-SegWit, or bech32m address-family behavior is fully
  migrated to PQ semantics
- broad mixed address-family send flows are now green

The broad inherited suite remains:

- [wallet_address_types.py](../test/functional/wallet_address_types.py)
  - current inventory posture: `dual_profile`
  - current Taproot matrix bucket: `deferred`
  - current owned boundary:
    - low-risk inherited address-shape smoke coverage that still passes
    - explicit PQ-only inherited `getnewaddress` / `getrawchangeaddress`
      rejection coverage for valid explicit address types, including `bech32m`
    - one deferred inherited classical `sendmany` negative control

As of 2026-04-12, that suite no longer fails accidentally in the inherited
classical path. Instead, it freezes the current failure explicitly:

- inherited classical `sendmany("", sends)` still fails with
  `Signing transaction failed`
- that behavior remains deferred Track A compatibility work, not a PQ-address
  RPC regression

## Confidence Snapshot

Targeted confidence on 2026-04-12:

- `python3 test/functional/wallet_address_types.py`
  - result: passed
  - covers low-risk inherited address-shape smoke checks, explicit PQ-only
    inherited address-RPC rejection for default plus `legacy` /
    `p2sh-segwit` / `bech32` / `bech32m`, and one deferred inherited
    `sendmany` negative control
- `python3 test/functional/wallet_pq_active_ranged.py`
  - result: passed
  - covers dedicated PQ setup plus the broader before/after-restore inherited
    address-RPC rejection boundary on active PQ wallets

## Interpretation

- the owned PQ wallet address UX is now explicit
- `wallet_address_types.py` now freezes a narrow inherited-address boundary,
  not a broad compatibility rehab
- broad inherited address-type send/sign rehabilitation remains separate
  deferred work
