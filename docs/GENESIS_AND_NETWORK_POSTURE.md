# PQBTC Genesis And Network Posture

## Status: ACTIVE
## Spec-ID: GENESIS-NETWORK-POSTURE-v1
## Frozen-By: track-a-launch-posture-20260406
## Consensus-Relevant: YES

## Purpose

State the practical launch consequences of the Track A thesis:

- PQBTC is a new chain starting at block 0
- PQBTC owns its own network identity
- PQBTC is not a continuation of inherited Bitcoin chain history

This note exists so future engineering work does not quietly drift into
retrofit assumptions that do not match the project thesis.

## Core Launch Posture

PQBTC launches as a fresh chain with its own genesis block, its own chain
history, and its own network namespace.

That means:

- no inherited Bitcoin mainnet/testnet/regtest history
- no imported Bitcoin UTXO set as a launch prerequisite
- no assumption that Bitcoin transactions, addresses, descriptors, or wallet
  flows are preserved unless PQBTC defines them explicitly
- no obligation to maintain broad classical wallet compatibility merely because
  inherited Bitcoin Core code paths still exist in-tree

The repo may continue to use Bitcoin-derived architecture, but the product
posture is a new chain, not a live-upgrade fork.

## Frozen Network Identity

The chain identity is already frozen in:

- [GENESIS.md](GENESIS.md)
- [chainparams.cpp](../src/kernel/chainparams.cpp)
- [NAMING.md](NAMING.md)

Current public-network constants:

- mainnet:
  - message start: `0x85 0x92 0xa7 0xad`
  - p2p port: `22833`
  - rpc port: `22832`
  - bech32 HRP: `pq`
  - genesis hash: `2af71da20e6e03bfdfc2347edffbbb4087796678c8d57cacbccbd10eee7b31e4`
- testnet:
  - message start: `0xa7 0xe2 0x9c 0xf7`
  - p2p port: `23833`
  - rpc port: `23832`
  - bech32 HRP: `tq`
  - genesis hash: `2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979`
- regtest:
  - message start: `0x96 0xbd 0x87 0x9e`
  - p2p port: `24833`
  - rpc port: `24832`
  - bech32 HRP: `rq`
  - genesis hash: `36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2`

These are not cosmetic renames. They are part of the chain-separation contract.

## Practical Consequences

### 1. Chain History

PQBTC should be reasoned about as genesis-native from the first block onward.

Do not assume:

- importing Bitcoin chainstate
- preserving Bitcoin block history
- validating against inherited Bitcoin checkpoints
- treating Bitcoin transaction history as PQBTC history

### 2. Wallet Expectations

The wallet default should follow the chain thesis:

- PQ-native signing from genesis
- PQ-native receive/change flows as the owned UX
- inherited classical wallet/address surfaces treated as reference inventory
  unless PQBTC explicitly adopts them

This is why work such as:

- [PQ_WALLET_MANAGER_SETUP.md](PQ_WALLET_MANAGER_SETUP.md)
- [PQ_ADDRESS_RPC_POSTURE.md](PQ_ADDRESS_RPC_POSTURE.md)
- [CREATEWALLETDESCRIPTOR_POSTURE.md](CREATEWALLETDESCRIPTOR_POSTURE.md)

matters more than broad rehabilitation of inherited Bitcoin address families.

### 3. Address And Namespace Separation

New genesis implies new operator-facing namespace.

PQBTC should keep:

- its own binaries and datadirs
- its own network magic and ports
- its own HRPs and prefixes
- its own user-agent and branding

The goal is to prevent both technical and operator confusion with Bitcoin Core.

### 4. Replay And Compatibility Framing

Because PQBTC does not share Bitcoin chain history, launch planning should not
be framed as a chain-split replay problem.

That does **not** mean every Bitcoin-derived transaction shape is automatically
safe or meaningful on PQBTC. It means replay protection against inherited
Bitcoin history is not the central launch abstraction here. The central
abstraction is chain separation by identity, history, and consensus rules.

## Explicit Non-Goals At Launch

Unless Scott changes direction, launch does **not** require:

- importing Bitcoin mainnet UTXOs
- preserving Bitcoin address-family parity as a product goal
- preserving classical ECDSA/Schnorr signing flows
- broad legacy wallet test rehabilitation for its own sake
- presenting PQBTC as a live migration of existing Bitcoin chain history

## What Still Matters From Bitcoin

Starting at block 0 does **not** mean discarding Bitcoin-derived value where it
still helps:

- UTXO model
- Script execution model
- PoW schedule and monetary schedule defaults
- node, wallet, and operational architecture
- selected inherited test coverage where it still meaningfully exercises PQBTC

The rule is: inherit architecture intentionally, not identity accidentally.

## Current Engineering Interpretation

Under this posture:

- `wallet_address_types.py` staying red in classical send flow is not a launch
  blocker by itself
- inherited descriptor/address RPCs should earn their place explicitly rather
  than by historical inertia
- the highest-value work remains PQ-native wallet maturity, replacement-path
  clarity, CI confidence, and operator hardening

## References

- [Spec.md](Spec.md)
- [GENESIS.md](GENESIS.md)
- [NAMING.md](NAMING.md)
- [TRACK_A_NATIVE_PQ_BITCOIN.md](TRACK_A_NATIVE_PQ_BITCOIN.md)
- [TRACK_A_STATUS.md](TRACK_A_STATUS.md)
