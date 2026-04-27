# PQBTC `wallet_createwallet.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-CREATEWALLET-POSTURE-v1
## Updated: 2026-04-26
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_createwallet.py](../test/functional/wallet_createwallet.py)
`createwallet` argument and lifecycle contract under the current
legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_createwallet.py` is now a required PQ gate for restored inherited wallet
creation behavior. The owned boundary covers:

- invalid `createwallet` argument combinations
- disabled-private-key wallets and expected key-unavailability failures
- blank wallets with private keys disabled and enabled
- descriptor import behavior for watch-only and private-key material
- blank-wallet encryption before descriptor seed import
- born-encrypted wallets, unlock flow, signing, and keypool refill behavior
- empty-passphrase warning behavior
- `avoid_reuse` wallet creation
- legacy-wallet creation rejection
- wallet version logging across unload/load

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader multiwallet path, load/unload, backup, or locking behavior
- wallet migration or backwards-compatibility release-asset behavior
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

The canonical PQ gate now includes the inherited `createwallet` lifecycle
contract that already passes under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. The subsequent multiwallet
promotion covers the adjacent multiwallet lifecycle surface. Until
compatibility assets exist, the repo-local wallet alternate is broader
inherited wallet lifecycle breadth beyond `wallet_multiwallet.py`.
