# PQBTC Wallet Key-Management Posture

## Status: ACTIVE
## Spec-ID: WALLET-KEYMANAGEMENT-POSTURE-v1
## Updated: 2026-04-27
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet key-management, descriptor-maintenance, and
no-wallet runtime contracts under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_descriptor.py](../test/functional/wallet_descriptor.py)
- [wallet_disable.py](../test/functional/wallet_disable.py)
- [wallet_encryption.py](../test/functional/wallet_encryption.py)
- [wallet_gethdkeys.py](../test/functional/wallet_gethdkeys.py)
- [wallet_hd.py](../test/functional/wallet_hd.py)
- [wallet_keypool.py](../test/functional/wallet_keypool.py)
- [wallet_keypool_topup.py](../test/functional/wallet_keypool_topup.py)
- [wallet_listdescriptors.py](../test/functional/wallet_listdescriptors.py)

The owned boundary covers:

- descriptor wallet info, receive/change derivation, send/receive behavior,
  descriptor exports/imports, and legacy-key-type load rejection
- `-disablewallet` behavior that hides wallet RPCs while keeping non-wallet
  address validation available
- wallet encryption, passphrase timeout limits, signing lock/unlock behavior,
  passphrase changes, and no-private-key wallet encryption rejection
- `gethdkeys` public/private key listing, encrypted-wallet access controls,
  imported ranged descriptor keys, non-HD exclusion, and multisig HD-key
  reporting
- HD seed backup/restore, keypool refill, and receive/change recovery
- keypool exhaustion/refill, locked/encrypted wallet behavior, change-key use,
  address reuse constraints, and unlock/refill controls
- wallet backup, address generation across output types, restore from backup,
  keypool top-up, rescan, and restored balance detection
- empty/default descriptor listing, sorted descriptor output, hardened
  derivation export, private descriptor visibility, encrypted/watch-only wallet
  behavior, and non-active combo descriptors

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- broad wallet accounting, label, transaction-listing, or conflict semantics
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-27:

- `build/test/functional/test_runner.py --jobs=1 wallet_descriptor.py wallet_disable.py wallet_encryption.py wallet_gethdkeys.py wallet_hd.py wallet_keypool.py wallet_keypool_topup.py wallet_listdescriptors.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=52`, `pq_backlog=73`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited descriptor wallet,
no-wallet runtime, encryption, HD key, keypool, and descriptor listing
contracts that already pass under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. The subsequent accounting
and listing promotion covers the adjacent balance, label, received-by,
since-block, and transaction-listing surfaces. Until compatibility assets exist,
the repo-local wallet alternate is coin-selection grouping and adjacent
spend-policy surfaces beyond that accounting/listing gate.
