# PQBTC Wallet Remaining Transaction Breadth Posture

## Status: ACTIVE
## Spec-ID: WALLET-REMAINING-TRANSACTION-BREADTH-POSTURE-v1
## Updated: 2026-04-29
## Consensus-Relevant: NO

## Purpose

Freeze the inherited wallet import-pruned-funds, timelock, orphaned reward, and
v3/TRUC transaction contracts under the current legacy-compatible PQC profile.

This tranche is a gate promotion only. It does not change RPC, wallet,
descriptor, policy, relay, or consensus behavior.

## Owned Surface

The following suites are now required PQ gates:

- [wallet_importprunedfunds.py](../test/functional/wallet_importprunedfunds.py)
- [wallet_orphanedreward.py](../test/functional/wallet_orphanedreward.py)
- [wallet_timelock.py](../test/functional/wallet_timelock.py)
- [wallet_v3_txs.py](../test/functional/wallet_v3_txs.py)

The owned boundary covers:

- `importprunedfunds` and `removeprunedfunds` proof import rejection for
  unaffiliated addresses, watch-only descriptor import, private-key import,
  balance/listing updates, removal behavior, transaction decode errors, proof
  mismatch errors, malformed merkleblock rejection, and missing-block rejection
- confirmed timelocked send accounting stability across received-by-address,
  received-by-label, listreceived, trusted balance, and unspent coin state when
  mock time changes finality
- orphaned block reward handling, descendant abandonment, reload persistence,
  and preserving abandoned descendants when the reward returns to the active
  chain
- wallet v3/TRUC behavior for version-mixing spend availability, v3 UTXO
  visibility, conflicting sibling handling, mempool conflict removal, parent
  and child weight checks, user input weight preservation, `createpsbt`,
  `send`, `sendall`, funded-PSBT v3 flows, TRUC weight-limit errors,
  non-TRUC mixing rejection, multiple unconfirmed TRUC output rejection, and
  third-generation spend rejection

## Non-Goals In This Tranche

This promotion does not define:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- wallet migration or backwards-compatibility release-asset behavior
- inherited wallet backwards-compatibility behavior outside these
  transaction-breadth contracts
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

## Confidence Snapshot

Targeted confidence on 2026-04-29:

- `build/test/functional/test_runner.py --jobs=1 wallet_importprunedfunds.py wallet_timelock.py wallet_orphanedreward.py wallet_v3_txs.py`
  - result: passed
- `python3 ci/test/check_ci_inventory.py`
  - result: passed
  - counts after this promotion: `pq_required=78`, `pq_backlog=47`,
    `dual_profile=142`, `legacy_only=9`

## Interpretation

The canonical PQ gate now includes the inherited wallet import-pruned-funds,
timelock, orphaned reward, and v3/TRUC wallet behavior that already passes
under the current PQC-compatible legacy profile.

The repo-local wallet alternate moved to `wallet_crosschain.py` and
`wallet_createwalletdescriptor.py`; those surfaces are now covered by
[WALLET_CROSSCHAIN_DESCRIPTOR_CREATION_POSTURE.md](./WALLET_CROSSCHAIN_DESCRIPTOR_CREATION_POSTURE.md).

`wallet_migration.py` and `wallet_backwards_compatibility.py` remain blocked
locally because previous-release fixtures are unavailable. The preferred Track
A follow-on remains `feature_coinstatsindex_compatibility.py` when real prior
PQBTC release assets exist locally.
