# Wallet Plan for PQBTC

## Status: FROZEN
## Spec-ID: WALLET-v1-frozen
## Updated-By: freeze-gate-prereq-20260408
## Frozen-By: gatekeeper-prereq-20260408
## Consensus-Relevant: NO

## Current v1 Wallet Surface

The wallet surface is no longer deferred in the repo. Current `main` includes:

- descriptor-native `pqpriv(...)` wallet managers for receive and change flows
- deterministic PQ destination derivation with persisted `next_index`
- PQ signing and PQ PSBT proprietary partial-signature handling under the current fixed `SIGHASH_ALL` rule
- backup, restore, and ranged-descriptor recovery coverage
- active PQ manager restore continuity for persisted `next_index`, keypool
  state, and post-restore automatic PQ change
- default PQ-native unit coverage for wallet bookkeeping and PSBT role/error handling

Important boundary:

- inherited `createwalletdescriptor` support is still separate from the PQ-native
  wallet-manager path
- inherited `getnewaddress` and `getrawchangeaddress` are still separate from
  the PQ-native address path and are explicitly rejected on PQ-only active
  wallets in favor of `getnewpqaddress` and `getrawpqchangeaddress`
- PQ wallet-manager creation now has a dedicated setup RPC,
  `createpqwalletmanagers`, rather than entering through the inherited
  xpub-based descriptor builder
- inherited `keypoolrefill` remains a supported maintenance RPC for active
  PQ managers; on PQ-only wallets it expands the receive/change `pqpriv(...)`
  ranges instead of creating inherited address families
- raw `importdescriptors` with `pqpriv(...)` remains available as a lower-level
  descriptor/test path

## Confidence Closure In This Tranche

This tranche closes the remaining wallet confidence gap by:

- promoting the existing PQ wallet functional suites into the required PQ CI gate
- adding PQ-native wallet bookkeeping tests to the default `test_pqbtc` profile
- adding PQ-native PSBT negative/interoperability tests to the default `test_pqbtc` profile

## Remaining Out Of Scope

- broad rehabilitation of inherited legacy wallet tests under PQ mode
- Taproot replacement behavior and migration work, which remains tracked separately under `#23`
- broader CI completeness work outside the wallet-confidence surface

## Tooling Note

Reference tooling such as `contrib/pqsign/pqsign.py` remains useful for external
workflows, but it is no longer the only exercised signing path in-tree.
