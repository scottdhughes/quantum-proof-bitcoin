# PQBTC `mining_template_verification.py` Posture

## Status: ACTIVE
## Spec-ID: MINING-TEMPLATE-VERIFICATION-POSTURE-v1
## Updated: 2026-06-11
## Frozen-By: track-a-phase3-20260611
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for inherited `getblocktemplate`
proposal-mode verification behavior under the current legacy-compatible PQC
profile.

## Current Owned Surface

The current passing
[mining_template_verification.py](../test/functional/mining_template_verification.py)
suite owns the proposal-verification boundary:

- valid block proposals return `None` from `getblocktemplate` proposal mode
  without submitting the block until the suite explicitly calls `submitblock`
- malformed and invalid block proposals preserve expected reject behavior for
  missing coinbase inputs, empty blocks, truncated payloads, duplicate
  transactions, missing or spent inputs, non-final transactions, and malformed
  transaction counts
- difficulty, proof-of-work, merkle-root, timestamp, and best-prevblk
  boundaries preserve their expected proposal-mode outcomes
- transaction-bearing block proposals validate without updating the UTXO set
- overspending and double-spend proposal cases preserve the expected reject
  reasons and package diagnostics
- concurrent proposal checks through multiple RPC clients stay stable

## What This Does Not Mean

This posture note does **not** mean:

- broad mining RPC, longpoll, alternate-mainnet retarget, or transaction
  prioritisation behavior is owned by this tranche
- orphan transaction or prior-release mempool/mining compatibility behavior is
  covered without real prior PQBTC release assets
- PQ-native block-size stress replaces this inherited proposal-verification
  surface
- this tranche changes consensus, RPC, wallet, P2P, descriptor, or policy
  behavior

Those remain separate required gates or backlog decisions.

## Confidence Snapshot

Targeted confidence pass run on 2026-06-11:

- `build/test/functional/test_runner.py --jobs=1 mining_template_verification.py`
  - result: passed
  - current posture:
    - proposal-mode valid and invalid block checks remain stable
    - transaction-bearing proposals do not mutate the UTXO set
    - overspend, double-spend, and concurrent proposal checks remain green
      under the current legacy-compatible PQC profile

## Interpretation

- `mining_template_verification.py` is now a required inherited
  getblocktemplate proposal-verification gate
- it complements, but does not replace,
  [mining_basic.py](MINING_BASIC_POSTURE.md),
  [mining_getblocktemplate_longpoll.py](MINING_GETBLOCKTEMPLATE_LONGPOLL_POSTURE.md),
  [mining_mainnet.py](MINING_MAINNET_POSTURE.md), and
  [mining_prioritisetransaction.py](MINING_PRIORITISETRANSACTION_POSTURE.md)
- the preferred asset-dependent follow-on remains
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py)
- without prior-release assets, the remaining backlog is asset-dependent rather
  than another local mining-template promotion
