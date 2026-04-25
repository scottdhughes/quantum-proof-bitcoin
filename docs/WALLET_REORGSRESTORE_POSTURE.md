# PQBTC `wallet_reorgsrestore.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-REORGSRESTORE-POSTURE-v1
## Updated: 2026-04-25
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_reorgsrestore.py](../test/functional/wallet_reorgsrestore.py)
wallet reorg-restore contract under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_reorgsrestore.py` is now a required PQ gate for restored inherited
wallet reorg-restore behavior. The owned boundary covers:

- confirmed wallet transaction status restoration after a wallet file is loaded
  on a longer chain
- restored confirmation state with a different block hash after reorg
- conflicted wallet transaction recovery when the formerly conflicted
  transaction becomes confirmed on the longer chain
- startup abandonment of orphaned coinbase transactions when their block is no
  longer on the best chain
- startup abandonment of descendants of orphaned coinbase transactions
- trusted-balance reset after orphaned coinbase abandonment
- unclean-shutdown restart rescan after an invalidated block was not flushed to
  disk
- un-abandoning a coinbase transaction when the restarted node again sees it in
  the active chain
- duplicate block-disconnection tolerance across a follow-up reorg
- abandon/un-abandon consistency across `invalidateblock` and `reconsiderblock`

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader wallet backup/restore compatibility
- wallet transaction-time rescan behavior
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-25:

- `build/test/functional/test_runner.py --jobs=1 wallet_reorgsrestore.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=38`, `pq_backlog=87`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet reorg-restore contract
that already passes under the current PQC-compatible legacy profile. The
preferred Track A follow-on remains `feature_coinstatsindex_compatibility.py`
when real prior PQBTC release assets exist locally. Until then, the repo-local
wallet alternate moves to broader inherited wallet backup/restore and
transaction-time rescan surfaces.
