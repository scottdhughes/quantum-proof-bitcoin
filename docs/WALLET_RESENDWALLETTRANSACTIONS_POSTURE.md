# PQBTC `wallet_resendwallettransactions.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-RESENDWALLETTRANSACTIONS-POSTURE-v1
## Updated: 2026-04-24
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_resendwallettransactions.py](../test/functional/wallet_resendwallettransactions.py)
rebroadcast contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_resendwallettransactions.py` is now a required PQ gate for restored
wallet rebroadcast behavior. The owned boundary covers:

- initial wallet transaction announcement to peers
- delayed rebroadcast timing after a sufficiently later block
- scheduler-triggered `MaybeResendWalletTxs` resubmission
- no early rebroadcast inside the first twelve-hour window
- rebroadcast after the upper resend timer bound
- parent-before-child rebroadcast for unconfirmed wallet transaction chains
- resubmission after wallet transactions are evicted from the mempool

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet reindex, rescan, or reorg restore semantics
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-24:

- `build/test/functional/test_runner.py --jobs=1 wallet_resendwallettransactions.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=34`, `pq_backlog=91`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet rebroadcast contract
that already passes under the current PQC-compatible legacy profile. The
preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moves to the adjacent inherited wallet lifecycle surfaces:
reindex, rescan-unconfirmed, and reorg restore behavior.
