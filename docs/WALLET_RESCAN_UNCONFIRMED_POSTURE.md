# PQBTC `wallet_rescan_unconfirmed.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-RESCAN-UNCONFIRMED-POSTURE-v1
## Updated: 2026-04-25
## Consensus-Relevant: NO

## Purpose

Freeze the inherited
[wallet_rescan_unconfirmed.py](../test/functional/wallet_rescan_unconfirmed.py)
descriptor-wallet unconfirmed-rescan contract under the current
legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

`wallet_rescan_unconfirmed.py` is now a required PQ gate for restored inherited
descriptor-wallet unconfirmed-rescan behavior. The owned boundary covers:

- parent transaction creation and confirmation in a block that is later
  disconnected
- child `sendall` sweep creation from the parent output without a wallet change
  output
- mocked reorg that returns the parent transaction to the mempool after its
  child
- descriptor import into a watch-only wallet after the parent and child are
  both in the mempool
- watched parent address recognition as solvable and `ismine`
- rescan detection of the re-entered unconfirmed parent
- rescan detection of the unconfirmed child through input processing order

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- broader wallet reorg-restore semantics
- wallet backup/restore compatibility beyond existing PQ-owned backup coverage
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-25:

- `build/test/functional/test_runner.py --jobs=1 wallet_rescan_unconfirmed.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=37`, `pq_backlog=88`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited descriptor-wallet
unconfirmed-rescan contract that already passes under the current
PQC-compatible legacy profile. The preferred Track A follow-on remains
`feature_coinstatsindex_compatibility.py` when real prior PQBTC release assets
exist locally. Until then, the repo-local wallet alternate moves to the
adjacent inherited wallet reorg-restore surface.
