# PQBTC `wallet_blank.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-BLANK-POSTURE-v1
## Updated: 2026-04-26
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_blank.py](../test/functional/wallet_blank.py) blank descriptor-wallet
contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_blank.py` is now a required PQ gate for restored inherited blank-wallet
lifecycle behavior. The owned boundary covers:

- blank descriptor wallets created with private keys disabled
- blank flag preservation after `importdescriptors`
- blank descriptor wallets created with private keys enabled
- blank flag preservation after `encryptwallet`
- descriptor metadata stability across blank-wallet encryption

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader `createwallet` argument behavior beyond `wallet_createwallet.py`
- broader multiwallet path, load/unload, backup, or locking behavior
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-26:

- `build/test/functional/test_runner.py --jobs=1 wallet_blank.py wallet_createwallet.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=43`, `pq_backlog=82`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited blank descriptor-wallet
lifecycle contract that already passes under the current PQC-compatible legacy
profile. The preferred Track A follow-on remains
`feature_coinstatsindex_compatibility.py` when real prior PQBTC release assets
exist locally. The subsequent multiwallet promotion covers the adjacent
multiwallet lifecycle surface. Until compatibility assets exist, the repo-local
wallet alternate is broader inherited wallet lifecycle breadth beyond
`wallet_multiwallet.py`.
