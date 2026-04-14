# PQBTC `wallet_assumeutxo.py` Posture

## Status: ACTIVE
## Spec-ID: WALLET-ASSUMEUTXO-POSTURE-v1
## Frozen-By: track-a-phase1-20260414
## Consensus-Relevant: NO

## Purpose

Define the owned Track A contract for wallet behavior while an assumeutxo
snapshot is active and background validation has not yet completed.

## Current Owned Surface

The current passing
[wallet_assumeutxo.py](../test/functional/wallet_assumeutxo.py) suite owns a
narrow wallet-side assumeutxo slice:

- the pre-snapshot chain stays aligned with the current regtest assumeutxo
  anchors while replacing inherited MiniWallet mempool sends with direct-mined
  transactions
- post-snapshot wallet funding for the backup/restore checks is also performed
  by direct-mined MiniWallet transactions, so the suite no longer depends on
  the deferred inherited `scriptpubkey (-26)` mempool path
- a wallet backup created exactly at the snapshot height can be restored during
  background sync
- a wallet backup created before the snapshot height is still rejected during
  background sync with the current bounded wallet-loading error
- descriptor import and `rescanblockchain` still fail with the current
  background-sync rescan errors while historical blocks remain unavailable
- once background validation completes, the older backup can be restored, the
  snapshot-height wallet balance resolves correctly, the wallet active during
  snapshot completion resolves correctly, and descriptor import succeeds

## What This Does Not Mean

This posture note does **not** mean:

- broad inherited MiniWallet mempool acceptance is owned here
- generic wallet behavior across all assumeutxo permutations is owned here
- this suite is promoted into `pq_required`

Those remain separate follow-on surfaces.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-14:

- `python3 test/functional/wallet_assumeutxo.py`
  - result: passed
  - current posture:
    - the snapshot-height backup loads during background sync
    - the pre-snapshot backup remains blocked until background validation
      finishes
    - final wallet balances still settle to `34` and `340` on the owned path

## Interpretation

- `wallet_assumeutxo.py` is now a fixed PQBTC wallet-side assumeutxo slice
- it remains `pq_backlog`, not a required PQ-first gate
- the next clean actionable follow-on is
  [feature_coinstatsindex_compatibility.py](../test/functional/feature_coinstatsindex_compatibility.py),
  if the required previous-release assets are available locally
- the local wallet alternate remains broader inherited miniscript
  funding/finalization rehab
