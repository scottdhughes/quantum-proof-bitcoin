# PQBTC `wallet_backup.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-BACKUP-POSTURE-v1
## Updated: 2026-04-26
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_backup.py](../test/functional/wallet_backup.py) wallet backup/restore
contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_backup.py` is now a required PQ gate for restored inherited wallet
backup/restore behavior. The owned boundary covers:

- multi-wallet transaction churn before and after `backupwallet`
- restored wallet balances matching the pre-restore balances after more
  transactions and fee-maturity mining
- invalid wallet backup rejection without creating the target wallet
- missing backup-file rejection without creating the target wallet
- existing wallet-name restore rejection without overwriting the destination
- restore into an existing empty directory
- restore into a directory containing non-wallet files without deleting them
- restore rejection when the destination wallet database already exists
- restore into an unnamed default wallet
- backup-to-source-path failure for file, directory, and equivalent path forms
- pruned-node restore success when the backup is near the prune height
- pruned-node restore failure when backup synchronization goes beyond pruned
  data

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader wallet backwards-compatibility or migration semantics
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-26:

- `build/test/functional/test_runner.py --jobs=1 wallet_backup.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=40`, `pq_backlog=85`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet backup/restore
contract that already passes under the current PQC-compatible legacy profile.
The preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moves to broader inherited wallet lifecycle coverage beyond
the current backup/restore gate.
