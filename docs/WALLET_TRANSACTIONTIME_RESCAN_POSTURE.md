# PQBTC `wallet_transactiontime_rescan.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-TRANSACTIONTIME-RESCAN-POSTURE-v1
## Updated: 2026-04-26
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_transactiontime_rescan.py](../test/functional/wallet_transactiontime_rescan.py)
wallet transaction-time rescan contract under the current legacy-compatible
PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_transactiontime_rescan.py` is now a required PQ gate for restored
inherited wallet transaction-time rescan behavior. The owned boundary covers:

- watch-only descriptor imports for three received transactions separated by
  mock-time intervals
- original transaction `blocktime` and wallet `time` matching the block times
  at initial detection
- wallet restoration with `timestamp=now` descriptors that intentionally starts
  with no detected historical transactions
- idle `abortrescan` returning `false`
- partial-history rescan followed by full-history rescan
- restored balance and transaction count after the full rescan
- restored transaction `blocktime` and wallet `time` matching the original
  detected times
- invalid `rescanblockchain` start and stop height rejection
- locked encrypted wallet rescan rejection until the wallet is unlocked

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader wallet backup/restore compatibility
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-26:

- `build/test/functional/test_runner.py --jobs=1 wallet_transactiontime_rescan.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=39`, `pq_backlog=86`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet transaction-time
rescan contract that already passes under the current PQC-compatible legacy
profile. The preferred Track A follow-on remains
`feature_coinstatsindex_compatibility.py` when real prior PQBTC release assets
exist locally. Until then, the repo-local wallet alternate moves to broader
inherited wallet backup/restore coverage.
