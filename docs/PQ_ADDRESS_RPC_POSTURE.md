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

- inherited legacy, P2SH-SegWit, or bech32m address-family behavior is fully
  migrated to PQ semantics beyond the explicitly tested RPC boundary
- replacement-path Taproot or bech32m semantics are defined for wallet, RPC,
  descriptor, PSBT, policy, relay, or consensus behavior
- broad non-address-type wallet send/sign behavior is covered by this suite

The inherited address-type suite is now a required PQ gate:

- [wallet_address_types.py](../test/functional/wallet_address_types.py)
  - current inventory posture: `pq_required`
  - current Taproot matrix bucket: `deferred`
  - current owned boundary:
    - inherited address-shape smoke coverage
    - descriptor-wallet `bech32m` address-shape smoke coverage
    - inherited mixed-address `sendmany("", sends)` positive control
    - explicit PQ-only inherited `getnewaddress` / `getrawchangeaddress`
      rejection coverage for valid explicit address types, including `bech32m`
    - invalid address-type precedence

## Confidence Snapshot

Targeted confidence on 2026-04-23:

- `build/test/functional/test_runner.py --jobs=1 wallet_address_types.py`
  - result: passed
  - covers inherited address-shape smoke checks, descriptor-wallet `bech32m`
    smoke checks, inherited mixed-address `sendmany`, explicit PQ-only
    inherited address-RPC rejection for default plus `legacy` /
    `p2sh-segwit` / `bech32` / `bech32m`, and invalid address-type
    precedence
- `python3 test/functional/wallet_pq_active_ranged.py`
  - result: passed
  - covers dedicated PQ setup plus the broader before/after-restore inherited
    address-RPC rejection boundary on active PQ wallets

## Interpretation

- the owned PQ wallet address UX is now explicit
- `wallet_address_types.py` is now a required gate for the explicitly owned
  inherited address-type and PQ-only rejection boundary
- replacement-path Taproot/address semantics and broader wallet send/sign
  rehabilitation remain separate deferred work
