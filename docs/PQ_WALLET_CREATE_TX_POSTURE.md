# PQBTC PQ Wallet Create-Tx Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-CREATE-TX-v1
## Updated: 2026-04-08
## Consensus-Relevant: NO

## Purpose

Freeze the owned direct wallet transaction-creation contract for PQ-only active
wallets. The full inherited
[wallet_create_tx.py](../test/functional/wallet_create_tx.py)
surface is now frozen separately in
[WALLET_TRANSACTION_CONSTRUCTION_POSTURE.md](./WALLET_TRANSACTION_CONSTRUCTION_POSTURE.md).

## Owned Surface

The current owned PQ-native direct create-tx path is:

- [wallet_pq_create_tx.py](../test/functional/wallet_pq_create_tx.py)

It covers direct send-style wallet creation on a PQ-only active wallet created
through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

## Contract

On PQ-only active wallets:

- direct send RPCs like `sendtoaddress` remain supported
- inherited anti-fee-sniping behavior remains in force
- old tips still disable anti-fee-sniping and keep `locktime = 0`
- recent tips still enable anti-fee-sniping and keep `0 < locktime <= height`
- the current wallet transaction version remains `2`

This owned surface is about the transaction-creation posture itself. PQ change
manager selection and PSBT funding behavior are frozen separately in
[PQ_WALLET_MANAGER_SETUP.md](./PQ_WALLET_MANAGER_SETUP.md).
The higher-level `send` RPC contract is frozen separately in
[PQ_WALLET_SEND_POSTURE.md](./PQ_WALLET_SEND_POSTURE.md).

## Non-Goals In This Tranche

This tranche does not own the full inherited transaction-construction surface.
That broader surface is now frozen separately in
[WALLET_TRANSACTION_CONSTRUCTION_POSTURE.md](./WALLET_TRANSACTION_CONSTRUCTION_POSTURE.md).
This PQ-only posture note does not take on:

- `maxtxfee` coverage
- too-long mempool chain handling
- broad inherited dual-profile wallet rehabilitation outside the promoted
  construction and simulation gate

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_create_tx.py`
  - result: passed
  - covers the PQ-only direct create-tx path for anti-fee-sniping posture and
    current tx version `2`
