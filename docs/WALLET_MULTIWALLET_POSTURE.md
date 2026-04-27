# PQBTC `wallet_multiwallet.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-MULTIWALLET-POSTURE-v1
## Updated: 2026-04-27
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_multiwallet.py](../test/functional/wallet_multiwallet.py) multiwallet
lifecycle contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_multiwallet.py` is now a required PQ gate for restored inherited
multiwallet lifecycle behavior. The owned boundary covers:

- wallet directory scanning and listwalletdir warnings
- wallet file creation under the default wallet directory
- wallet path validation, duplicate wallet arguments, and invalid walletdir
  startup failures
- symlinked wallet path rejection
- external wallet path creation and loading
- dynamic wallet loading, creation, and unloading
- concurrent load/unload rejection for a wallet that is already loading
- per-wallet balance, endpoint selection, and `settxfee` isolation
- multiple-wallet RPC endpoint error behavior
- multiwallet backup and restore round trips
- exclusive database locking across two nodes

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- broader wallet lifecycle breadth outside the multiwallet contract
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-26:

- `build/test/functional/test_runner.py --jobs=1 wallet_multiwallet.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=44`, `pq_backlog=81`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited multiwallet lifecycle contract
that already passes under the current PQC-compatible legacy profile. The
preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. The subsequent
key-management promotion covers the adjacent descriptor, encryption, HD,
keypool, and descriptor-listing surfaces. Until compatibility assets exist, the
repo-local wallet alternate is wallet accounting, labels, and
transaction-listing surfaces beyond that key-management gate.
