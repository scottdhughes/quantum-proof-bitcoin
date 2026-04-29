# PQBTC Wallet Cross-Chain And Descriptor-Creation Posture

## Status: ACTIVE
## Spec-ID: WALLET-CROSSCHAIN-DESCRIPTOR-CREATION-POSTURE-v1
## Updated: 2026-04-29
## Consensus-Relevant: NO

## Purpose

Freeze the inherited cross-chain wallet-file safety boundary and inherited
xpub descriptor-creation boundary under the current legacy-compatible PQC
profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_createwalletdescriptor.py](../test/functional/wallet_createwalletdescriptor.py)
- [wallet_crosschain.py](../test/functional/wallet_crosschain.py)

The owned boundary covers:

- `createwalletdescriptor` xpub-based `bech32`/`wpkh(...)` and
  `bech32m`/`tr(...)` descriptor creation
- active descriptor key selection, duplicate and invalid HD-key validation,
  and encrypted-wallet unlock behavior
- explicit PQ-only active-manager rejection without mutating wallet state
- rejection of wallets and backups from a different genesis/network by
  `loadwallet` and `restorewallet`

## Non-Goals In This Tranche

This promotion does not define:

- PQ-native descriptor creation
- replacement descriptor semantics
- wallet migration or backwards-compatibility release-asset behavior
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-29:

- `build/test/functional/test_runner.py --jobs=1 wallet_crosschain.py wallet_createwalletdescriptor.py`
  - result: passed
- `build/test/functional/test_runner.py --jobs=1 wallet_crosschain.py wallet_createwalletdescriptor.py wallet_backwards_compatibility.py`
  - result: promoted suites passed; `wallet_backwards_compatibility.py`
    skipped because previous releases are unavailable locally
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=80`, `pq_backlog=45`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes these inherited wallet surfaces.

`wallet_migration.py` and `wallet_backwards_compatibility.py` remain blocked
locally because previous-release fixtures are unavailable. The preferred Track
A follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
PQBTC release assets exist locally.
