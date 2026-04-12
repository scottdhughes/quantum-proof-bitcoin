# PQBTC `createwalletdescriptor` Posture

## Status: ACTIVE
## Spec-ID: CREATEWALLETDESCRIPTOR-POSTURE-v1
## Frozen-By: track-a-phase1-20260406
## Consensus-Relevant: NO

## Purpose

State clearly what `createwalletdescriptor` means in the repo today, and what it
does not mean under the all-PQ Track A stance.

This note exists because the inherited RPC name sounds like it should be part of
 PQ wallet-manager creation, but today it is not.

## Current Reality

The current RPC at [wallet.cpp](../src/wallet/rpc/wallet.cpp)
is still the inherited HD-xpub descriptor builder.

It currently:

- chooses an existing active HD xpub from wallet descriptors
- derives a new descriptor family from `OutputType`
- adds standard descriptor managers for inherited address families

In practice, the current functional coverage proves:

- `type="bech32"` creates `wpkh(...)` descriptors
- `type="bech32m"` creates `tr(...)` descriptors
- PQ-only wallets with active `pqpriv(...)` managers are rejected explicitly
  because this RPC remains xpub-only

The current passing suite is:

- [wallet_createwalletdescriptor.py](../test/functional/wallet_createwalletdescriptor.py)

## What It Does Not Do

`createwalletdescriptor` does **not** currently:

- create `pq(...)` descriptors
- create active ranged `pqpriv(...)` managers
- understand PQ root seeds
- drive `getnewpqaddress` or PQ change-manager setup

So under Track A, this RPC is **not** evidence that PQ-native descriptor
creation is solved.

## Current PQ Creation Path

The current PQ-native wallet-manager creation path is different:

- call the dedicated
  [createpqwalletmanagers](../src/wallet/rpc/wallet.cpp)
  RPC on a descriptor wallet with no active managers
- let the dedicated PQ manager own address generation and signing

That path is already exercised in:

- [wallet_pq_active_ranged.py](../test/functional/wallet_pq_active_ranged.py)
- [PQ_WALLET_MANAGER_SETUP.md](./PQ_WALLET_MANAGER_SETUP.md)

And the lower-level descriptor import path is still exercised in:

- [wallet_pq_psbt.py](../test/functional/wallet_pq_psbt.py)

And the fixed public watch-only side is exercised in:

- [wallet_pq_descriptors.py](../test/functional/wallet_pq_descriptors.py)

## Track A Interpretation

Under the all-PQ stance:

- the current `createwalletdescriptor` behavior is inherited and deferred
- it remains useful as reference coverage for descriptor-wallet plumbing
- it is not an owned PQ-native milestone by itself

Current UX improvement:

- when a wallet's active state is driven only by `pqpriv(...)` managers,
  `createwalletdescriptor` now says so directly instead of pretending the issue
  is generic HD-key ambiguity
- current RPC error:
  `Active pqpriv() managers do not expose HD keys; createwalletdescriptor only supports xpub-based descriptor families`

This means a green
[wallet_createwalletdescriptor.py](../test/functional/wallet_createwalletdescriptor.py)
run tells us inherited descriptor creation still works. It does **not** tell us
that PQ-native descriptor creation semantics are defined.

## Recommended Direction

Current recommendation:

- do **not** overload the inherited `createwalletdescriptor` RPC yet
- keep PQ wallet-manager creation on the dedicated PQ-RPC path
- keep raw `pqpriv(...)` import as a lower-level descriptor/test surface, not the
  primary setup UX

Reasoning:

- the inherited RPC is organized around `OutputType` and HD xpubs
- the PQ path is organized around a root seed and dedicated PQ manager state
- forcing both shapes through one API too early is likely to blur the boundary
  between inherited descriptor families and the owned PQ-native wallet model

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/wallet_createwalletdescriptor.py`
  - result: passed
  - relevant guard: inherited xpub creation still works for `bech32` /
    `bech32m`, while PQ-only active-manager wallets reject both families with
    the current PQ-specific xpub-only RPC error and without mutating
    descriptor, HD-key, or active-manager state
- `python3 test/functional/wallet_pq_active_ranged.py`
  - result: passed
  - relevant guard: dedicated PQ setup remains on
    `createpqwalletmanagers`, and restore/reload rejection coverage for active
    `pqpriv(...)` managers stays owned there

Interpretation:

- inherited descriptor creation remains healthy
- PQ-only wallets are explicitly rejected by this inherited RPC
- PQ-native setup remains explicit and test-backed on
  `createpqwalletmanagers` without overloading the inherited RPC
