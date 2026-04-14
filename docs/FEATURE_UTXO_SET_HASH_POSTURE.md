# PQBTC `feature_utxo_set_hash.py` Posture

## Status: ACTIVE
## Spec-ID: FEATURE-UTXO-SET-HASH-POSTURE-v1
## Frozen-By: track-a-phase1-20260413
## Consensus-Relevant: YES

## Purpose

Define the owned Track A contract for deterministic UTXO set hash and MuHash
calculation on the current PQBTC regtest profile.

## Current Owned Surface

The current passing
[feature_utxo_set_hash.py](../test/functional/feature_utxo_set_hash.py) suite
owns a narrow chainstate slice:

- one raw `OP_TRUE` MiniWallet descriptor seeds the first post-genesis coinbase
  output without relying on the inherited Taproot-shaped MiniWallet path
- the first mined coinbase is spent through one real raw `OP_TRUE`
  self-transfer that is included directly by `generateblock(...)`
- manual MuHash accumulation over the live block-derived UTXO set still matches
  `gettxoutsetinfo("muhash")`
- deterministic PQBTC values for `hash_serialized_3` and `muhash` are frozen
  for this exact chainstate sequence

## What This Does Not Mean

This posture note does **not** mean:

- the inherited default `MiniWalletMode.ADDRESS_OP_TRUE` send path is owned
- adjacent coinstats index behavior is owned
- this suite is promoted into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-13:

- `python3 test/functional/feature_utxo_set_hash.py`
  - result: passed
  - current posture:
    - the raw `OP_TRUE` chainstate path preserves manual MuHash equality
    - the deterministic PQBTC UTXO-set hash constants are stable
- pre-slice baseline:
  - the inherited default MiniWallet self-transfer path failed with
    `scriptpubkey (-26)` and remains deferred rather than owned here

## Interpretation

- `feature_utxo_set_hash.py` is now a fixed PQBTC txoutset-hash slice
- it remains `pq_backlog`, not a required PQ-first gate
- the next clean follow-on is
  [feature_coinstatsindex.py](../test/functional/feature_coinstatsindex.py),
  which currently fails on the same inherited MiniWallet path and is the
  nearest adjacent txoutset/index boundary
- the lower-risk alternate is
  [feature_reindex.py](../test/functional/feature_reindex.py), which is
  already green under the current harness
