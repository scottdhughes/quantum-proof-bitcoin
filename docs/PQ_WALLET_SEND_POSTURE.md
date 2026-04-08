# PQBTC PQ Wallet Send Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SEND-v1
## Updated: 2026-04-08
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[send](/Users/scott/quantum-proof-bitcoin/test/functional/wallet_send.py)
RPC posture without reopening the broad inherited `wallet_send.py` matrix.

## Owned Surface

The current owned PQ-native `send` RPC path is:

- [wallet_pq_send.py](/Users/scott/quantum-proof-bitcoin/test/functional/wallet_pq_send.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](/Users/scott/quantum-proof-bitcoin/src/wallet/rpc/wallet.cpp).

## Contract

On PQ-only active wallets:

- the `send` RPC remains supported for ordinary destination outputs
- when no explicit `locktime` is supplied, the inherited anti-fee-sniping
  heuristic remains in force
- the default recent-tip `send` path must keep `locktime >= height - 100`
- an explicit `locktime = 0` override must disable that heuristic
- the current wallet transaction version remains `2`

This surface is about the operator-facing `send` RPC contract itself. Direct
`sendtoaddress` create-tx posture stays frozen separately in
[PQ_WALLET_CREATE_TX_POSTURE.md](/Users/scott/quantum-proof-bitcoin/docs/PQ_WALLET_CREATE_TX_POSTURE.md).
The owned `sendall` RPC contract is frozen separately in
[PQ_WALLET_SENDALL_POSTURE.md](/Users/scott/quantum-proof-bitcoin/docs/PQ_WALLET_SENDALL_POSTURE.md).

## Non-Goals In This Tranche

This tranche does not own the full inherited
[wallet_send.py](/Users/scott/quantum-proof-bitcoin/test/functional/wallet_send.py)
matrix. It explicitly does not take on:

- watch-only `send` behavior
- fee-rate argument matrix coverage
- change-address and change-type rehab
- external input solving or dual-profile wallet semantics

Those remain separate backlog or compatibility decisions.

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_send.py`
  - result: passed
  - covers the PQ-only `send` RPC posture for default anti-fee-sniping,
    explicit `locktime = 0`, and current tx version `2`
