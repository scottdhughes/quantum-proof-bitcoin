# PQBTC PQ Wallet Manager Setup

## Status: ACTIVE
## Spec-ID: PQ-WALLET-MANAGER-SETUP-v1
## Updated: 2026-04-08
## Consensus-Relevant: NO

## Purpose

Define the supported user-facing setup path for active PQ receive/change wallet
managers.

## Current Supported Path

The dedicated PQ-native setup RPC is:

- [createpqwalletmanagers](../src/wallet/rpc/wallet.cpp)

It creates and activates the receive/change `pqpriv(...)` manager pair from one
shared 32-byte root seed.

## Contract

Inputs:

- `root_seed`: 32-byte hex seed
- `range_end`: inclusive end index for both branches
- `next_index`: optional initial next index for both branches, default `0`

Guards:

- wallet must be a descriptor wallet
- private keys must be enabled
- wallet must have no active address managers yet
- encrypted wallets must be unlocked

Outputs:

- active receive `pqpriv(...)` descriptor metadata
- active change `pqpriv(...)` descriptor metadata
- explicit `range` and `next_index` state for both branches

## Why This Exists

This RPC keeps the PQ-native setup path separate from the inherited HD-xpub
descriptor builder:

- [createwalletdescriptor](../src/wallet/rpc/wallet.cpp)

That inherited RPC still creates `wpkh(...)` / `tr(...)` descriptor families.
It does not understand PQ root seeds and should not be overloaded early.

## Lower-Level Alternative

The lower-level path still exists:

- import active `pqpriv(...)` descriptors through `importdescriptors`

That remains useful for restore-style or descriptor-level testing, but it is no
longer the preferred initial setup UX for Track A PQ wallets.

## Keypool Maintenance

Once the active PQ managers exist, the inherited
[keypoolrefill](../src/wallet/rpc/addresses.cpp)
RPC remains a supported maintenance path.

Under PQ-only active wallets it does not create inherited address families.
Instead, it expands the active receive/change `pqpriv(...)` ranges so each
branch keeps at least the requested number of unused destinations available.

## Funding And Change Behavior

Once the active PQ managers exist, the owned funding/change posture is:

- raw-transaction funding through
  [fundrawtransaction](../src/wallet/rpc/spend.cpp)
  remains a supported wallet path
- PSBT funding through
  [walletcreatefundedpsbt](../src/wallet/rpc/spend.cpp)
  remains a supported wallet path for both explicit-input and automatic-input
  flows
- automatic change selection on PQ-only wallets must continue to consume the
  active internal `pqpriv(...)` manager, not an inherited address family
- current option-edge coverage keeps that same rule in force for
  `changePosition` and `subtractFeeFromOutputs`
- PQ-only active wallet/address RPC surfaces now expose
  `has_private_keys = true` for owned `pqpriv(...)` receive/change outputs,
  instead of relying on deprecated `iswatchonly` / `spendable` fields

This keeps the user-facing PQ setup path compatible with the wallet's existing
funding machinery without reopening inherited `getrawchangeaddress` semantics.

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_active_ranged.py`
  - result: passed
  - covers dedicated PQ setup, active receive/change generation, PQ-aware
    `keypoolrefill`, spend/change, restart, backup, restore, restored
    keypool continuity, and post-restore automatic PQ change on the restored
    internal manager
- `python3 test/functional/wallet_pq_psbt.py`
  - result: passed
  - covers the main PQ-native PSBT/signing flow starting from the dedicated
    setup RPC, including `fundrawtransaction` and automatic-input
    `walletcreatefundedpsbt` with automatic PQ change, including
    `changePosition` and `subtractFeeFromOutputs`, while keeping one lower-level
    `importdescriptors` check alive
- `python3 test/functional/wallet_createwalletdescriptor.py`
  - result: passed
  - confirms inherited descriptor creation still stays separate
