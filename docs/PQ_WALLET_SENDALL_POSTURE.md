# PQBTC PQ Wallet Sendall Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SENDALL-v1
## Updated: 2026-04-08
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[sendall](../test/functional/wallet_sendall.py)
RPC posture without reopening the broad inherited `wallet_sendall.py` matrix.

## Owned Surface

The current owned PQ-native `sendall` RPC path is:

- [wallet_pq_sendall.py](../test/functional/wallet_pq_sendall.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

## Contract

On PQ-only active wallets:

- the `sendall` RPC remains supported for ordinary sweep destinations
- when no explicit `locktime` is supplied, the inherited anti-fee-sniping
  heuristic remains in force
- the default recent-tip `sendall` path must keep `locktime >= height - 100`
- an explicit `locktime = 0` override must disable that heuristic
- the current wallet transaction version remains `2`

This surface is about the operator-facing `sendall` RPC contract itself. The
owned `send` RPC contract is frozen separately in
[PQ_WALLET_SEND_POSTURE.md](./PQ_WALLET_SEND_POSTURE.md).
The owned `sendmany` RPC contract is frozen separately in
[PQ_WALLET_SENDMANY_POSTURE.md](./PQ_WALLET_SENDMANY_POSTURE.md).

## Non-Goals In This Tranche

This tranche does not own the full inherited
[wallet_sendall.py](../test/functional/wallet_sendall.py)
matrix. It explicitly does not take on:

- `send_max` and dust-handling behavior
- specific-input and watch-only `sendall` semantics
- minconf/maxconf and ancestor-aware funding coverage
- too-large-transaction behavior

Those remain separate backlog or compatibility decisions.

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_sendall.py`
  - result: passed
  - covers the PQ-only `sendall` RPC posture for default anti-fee-sniping,
    explicit `locktime = 0`, and current tx version `2`
