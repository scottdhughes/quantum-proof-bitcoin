# PQBTC Wallet Spend Policy Posture

## Status: ACTIVE
## Spec-ID: WALLET-SPEND-POLICY-POSTURE-v1
## Updated: 2026-04-27
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet coin-selection grouping, change selection,
avoid-reuse, fallback-fee, and unconfirmed-input spend-policy contracts under
the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_avoid_mixing_output_types.py](../test/functional/wallet_avoid_mixing_output_types.py)
- [wallet_avoidreuse.py](../test/functional/wallet_avoidreuse.py)
- [wallet_change_address.py](../test/functional/wallet_change_address.py)
- [wallet_fallbackfee.py](../test/functional/wallet_fallbackfee.py)
- [wallet_groups.py](../test/functional/wallet_groups.py)
- [wallet_spend_unconfirmed.py](../test/functional/wallet_spend_unconfirmed.py)

The owned boundary covers:

- output-type grouping during coin selection across mixed wallet UTXOs
- `avoid_reuse` flag persistence, immutable flag handling, reused-address
  spend rejection, used balance reporting, and destination-group selection
- change destination selection, change detection, and explicit change-address
  behavior
- RBF transaction creation with configured `fallbackfee` when fee estimation is
  unavailable
- grouped UTXO spending, `avoidpartialspends`, `maxapsfee` thresholds, and
  large same-scriptPubKey UTXO selection limits
- confirmed versus unconfirmed input feerate selection, ancestor and sibling
  feerate handling, subtract-fee behavior, preset low-fee unconfirmed inputs,
  RBF parent bumping, overlapping ancestry, and external-input package bumping

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- broad `bumpfee`, abandoned-conflict, transaction clone, or double-spend
  semantics outside these spend-policy contracts
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-27:

- `build/test/functional/test_runner.py --jobs=1 wallet_avoid_mixing_output_types.py wallet_avoidreuse.py wallet_change_address.py wallet_fallbackfee.py wallet_groups.py wallet_spend_unconfirmed.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=64`, `pq_backlog=61`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited coin-selection grouping,
avoid-reuse, change selection, fallback-fee, and unconfirmed-input spend-policy
contracts that already pass under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moves to `wallet_bumpfee.py` and adjacent transaction-conflict
surfaces beyond this spend-policy gate.
