# PQBTC Wallet Accounting And Listing Posture

## Status: ACTIVE
## Spec-ID: WALLET-ACCOUNTING-LISTING-POSTURE-v1
## Updated: 2026-04-27
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet accounting, label, received-by, since-block, and
transaction-listing contracts under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_balance.py](../test/functional/wallet_balance.py)
- [wallet_coinbase_category.py](../test/functional/wallet_coinbase_category.py)
- [wallet_labels.py](../test/functional/wallet_labels.py)
- [wallet_listreceivedby.py](../test/functional/wallet_listreceivedby.py)
- [wallet_listsinceblock.py](../test/functional/wallet_listsinceblock.py)
- [wallet_listtransactions.py](../test/functional/wallet_listtransactions.py)

The owned boundary covers:

- mined, immature, trusted, untrusted, conflicted, and imported-output balance
  accounting
- `getbalance`, `getbalances`, `getwalletinfo`, and `gettransaction`
  last-processed-block reporting
- coinbase transaction category reporting across immature, generated,
  orphaned, and mature states
- label RPC validation, label assignment, address grouping, send persistence,
  and watch-only label handling
- `listreceivedbyaddress`, `listreceivedbylabel`, `getreceivedbyaddress`, and
  `getreceivedbylabel` behavior for labels, immature coinbase inclusion,
  matured rewards, and invalidated blocks
- `listsinceblock` behavior for no block hash, invalid block hashes,
  target confirmations, reorgs, disk-read errors, double spends, double sends,
  spend filtering, descriptor lookup, change inclusion, OP_RETURN output, and
  label filtering
- `listtransactions` and `gettransaction` behavior for simple sends,
  confirmation updates, send-to-self, `sendmany`, BIP125 replaceability,
  external-address receives, labels, coin-join-style transactions, parameter
  validation, OP_RETURN output, and from-me status changes

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- generic transaction construction, transaction simulation, or broad basic
  wallet behavior outside these listing/accounting contracts
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-27:

- `build/test/functional/test_runner.py --jobs=1 wallet_balance.py wallet_coinbase_category.py wallet_labels.py wallet_listreceivedby.py wallet_listsinceblock.py wallet_listtransactions.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=58`, `pq_backlog=67`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet balance, coinbase
category, label, received-by, since-block, and transaction-listing contracts
that already pass under the current PQC-compatible legacy profile. The
preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. The subsequent spend-policy
promotion covers the adjacent coin-selection grouping, change selection,
avoid-reuse, fallback-fee, and unconfirmed-input surfaces. The subsequent
bumpfee/conflict promotion covers adjacent fee-bump, abandoned-conflict, clone,
double-spend, and conflict-tracking surfaces. Until compatibility assets exist,
the repo-local wallet alternate is transaction construction, transaction
simulation, and remaining wallet transaction breadth beyond those gates.
