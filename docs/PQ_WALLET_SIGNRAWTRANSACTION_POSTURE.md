# PQBTC PQ Wallet Raw-Signing Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SIGNRAWTRANSACTION-POSTURE-v1
## Updated: 2026-04-11
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[signrawtransactionwithwallet](../src/wallet/rpc/spend.cpp)
contract without reopening the broad inherited
[wallet_signrawtransactionwithwallet.py](../test/functional/wallet_signrawtransactionwithwallet.py)
matrix.

## Owned Surface

The current owned PQ-native raw-signing path is:

- [wallet_pq_signrawtransaction.py](../test/functional/wallet_pq_signrawtransaction.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

## Contract

On PQ-only active wallets:

- direct raw spends of wallet-owned PQ UTXOs through
  `signrawtransactionwithwallet` are supported
- the default omitted sighash path and explicit `"ALL"` must produce the same
  fully signed transaction
- explicit non-`ALL` sighash modes remain unsupported on this PQ path and must
  leave the transaction incomplete rather than silently producing a different
  signature contract
- the signed witness stack is the current PQ witness shape:
  `[pq_signature, witness_script]`
- the PQ signature payload remains the current fixed `4480`-byte signature
- caller-chosen transaction fields such as version, locktime, and explicit
  sequence numbers remain intact

## Why This Slice Exists

Track A already owns the PQ-native setup path, change/funding path, PSBT path,
and operator-facing send family. This slice closes the remaining direct
wallet-owned raw-signing gap without reopening inherited classical signing
compatibility or the full historical `wallet_signrawtransactionwithwallet.py`
matrix.

## Non-Goals In This Tranche

This tranche does not own:

- broad inherited `wallet_signrawtransactionwithwallet.py` behavior
- mixed classical/PQ signing compatibility
- `prevtxs` matrix coverage for legacy descriptor families
- broad `wallet_fundrawtransaction.py` rehabilitation
- inherited classical PSBT finalize/decode compatibility in `rpc_psbt.py`

## Confidence

Minimum validation for this slice:

- `python3 test/functional/wallet_pq_signrawtransaction.py`
- `python3 ci/test/check_ci_inventory.py`
