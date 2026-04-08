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

- `wallet_address_types.py` is now an owned PQ suite
- inherited legacy, P2SH-SegWit, or bech32m address-family behavior is fully
  migrated to PQ semantics
- broad mixed address-family send flows are now green

The broad inherited suite remains:

- [wallet_address_types.py](../test/functional/wallet_address_types.py)
  - current inventory posture: `dual_profile`
  - current Taproot matrix bucket: `deferred`

On 2026-04-06 it still failed in the inherited classical path at
`sendmany("", sends)` with `Signing transaction failed`, before the new PQ-only
address-RPC guards became the relevant question.

## Confidence Snapshot

Targeted confidence on 2026-04-06:

- `python3 test/functional/wallet_pq_active_ranged.py`
  - result: passed
  - covers dedicated PQ setup, default inherited address-RPC rejection, and
    explicit `bech32` / `legacy` / `p2sh-segwit` inherited address-RPC
    rejection before and after restore

## Interpretation

- the owned PQ wallet address UX is now explicit
- broad inherited address-type rehabilitation remains separate deferred work
- `wallet_address_types.py` should be treated as reference inventory, not as
  the current Track A wallet-address milestone
