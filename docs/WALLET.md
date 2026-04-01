# Wallet Plan for PQBTC

## Status: IMPLEMENTED
## Spec-ID: WALLET-v1-implemented
## Updated-By: issue-12-wallet-confidence-20260401
## Consensus-Relevant: NO

## Current v1 Wallet Surface

The wallet surface is no longer deferred in the repo. Current `main` includes:

- descriptor-native `pqpriv(...)` wallet managers for receive and change flows
- deterministic PQ destination derivation with persisted `next_index`
- PQ signing and PQ PSBT proprietary partial-signature handling under the current fixed `SIGHASH_ALL` rule
- backup, restore, and ranged-descriptor recovery coverage
- default PQ-native unit coverage for wallet bookkeeping and PSBT role/error handling

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
