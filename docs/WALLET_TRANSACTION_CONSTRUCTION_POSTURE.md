# PQBTC Wallet Transaction Construction Posture

## Status: ACTIVE
## Spec-ID: WALLET-TRANSACTION-CONSTRUCTION-POSTURE-v1
## Updated: 2026-04-28
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet basic behavior, transaction creation, and raw
transaction simulation contracts under the current legacy-compatible PQC
profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_basic.py](../test/functional/wallet_basic.py)
- [wallet_create_tx.py](../test/functional/wallet_create_tx.py)
- [wallet_simulaterawtx.py](../test/functional/wallet_simulaterawtx.py)

The owned boundary covers:

- basic wallet balances, UTXO visibility, `gettxout` mempool interactions,
  `lockunspent` persistence and validation, fee-setting behavior, descriptor
  imports, watch-only visibility, mature and immature coinbase handling, and
  address/accounting edge cases
- inherited wallet transaction creation with anti-fee-sniping locktime
  behavior, transaction-size `maxtxfee` rejection, too-long mempool chain
  rejection, and current wallet transaction version behavior
- `simulaterawtransaction` multiwallet balance deltas, watch-only descriptor
  visibility, funded raw transaction fee/payment accounting, duplicate-spend
  rejection, missing-input rejection, chained simulated transactions, and
  mined-input rejection

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- import-pruned-funds, timelock, orphaned reward, v3 transaction, or signer
  behavior outside these construction and simulation contracts
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-28:

- `build/test/functional/test_runner.py --jobs=1 wallet_create_tx.py wallet_simulaterawtx.py wallet_basic.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=72`, `pq_backlog=53`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet transaction creation,
raw transaction simulation, and broad basic wallet behavior that already pass
under the current PQC-compatible legacy profile.

The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moved to inherited raw transaction signing and descriptor
import beyond this construction and simulation gate; that adjacent surface is
now covered by `WALLET_RAW_SIGNING_IMPORT_POSTURE.md`. `wallet_migration.py`
remains blocked locally because previous-release fixtures are unavailable, so
the current local alternate is remaining wallet transaction breadth beyond
these gates.
