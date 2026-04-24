# PQBTC `wallet_fundrawtransaction.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-FUNDRAWTRANSACTION-POSTURE-v1
## Updated: 2026-04-23
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_fundrawtransaction.py](../test/functional/wallet_fundrawtransaction.py)
funding contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_fundrawtransaction.py` is now a required PQ gate for the restored
pre-taproot funding surface. The owned boundary covers:

- default `add_inputs` behavior and preset-input selection
- fee, feerate, change-position, and subtract-fee-from-output behavior
- valid and invalid change address handling
- current inherited address/change-type behavior exercised by the suite
- coin selection across single-input, multi-input, and multi-output funding
- locked-wallet change handling
- watch-only funding and all-watched-funds handling
- external-input funding with `solving_data` and explicit input weights
- transaction-size and input-weight limit errors
- unsafe-input and input-confirmation controls
- duplicate-output funding and broadcast

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader send-path ownership for `wallet_send.py`, `wallet_sendall.py`, or
  `wallet_sendmany.py`
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-23:

- `build/test/functional/test_runner.py --jobs=1 wallet_fundrawtransaction.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=30`, `pq_backlog=95`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited raw transaction funding
contract that already passes under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains
`feature_coinstatsindex_compatibility.py` when real prior PQBTC release assets
exist locally. Until then, the repo-local wallet alternate is the broader
inherited send path beyond this funding gate.
