# PQBTC PQ Wallet Sendmany Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SENDMANY-v1
## Updated: 2026-04-08
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[sendmany](../test/functional/wallet_sendmany.py)
RPC posture without reopening the broad inherited `sendmany` and generic wallet
behavior matrix.

## Owned Surface

The current owned PQ-native `sendmany` RPC path is:

- [wallet_pq_sendmany.py](../test/functional/wallet_pq_sendmany.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

## Contract

On PQ-only active wallets:

- the `sendmany` RPC remains supported for ordinary multi-recipient sends
- the default anti-fee-sniping heuristic remains in force
- the default recent-tip `sendmany` path must keep `locktime >= height - 100`
- the current wallet transaction version remains `2`
- `subtractfeefrom` must keep working for multi-recipient sends

This surface is about the operator-facing `sendmany` RPC contract itself. The
owned `send` and `sendall` RPC contracts are frozen separately in
[PQ_WALLET_SEND_POSTURE.md](./PQ_WALLET_SEND_POSTURE.md)
and
[PQ_WALLET_SENDALL_POSTURE.md](./PQ_WALLET_SENDALL_POSTURE.md).

## Non-Goals In This Tranche

This tranche does not own the full inherited
[wallet_sendmany.py](../test/functional/wallet_sendmany.py)
surface. It explicitly does not take on:

- exhaustive `subtractfeefrom` validation edge cases
- fee-rate matrix coverage
- comment and verbose-return behavior
- dual-profile or legacy address-family semantics

Those remain separate backlog or compatibility decisions.

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_sendmany.py`
  - result: passed
  - covers the PQ-only `sendmany` RPC posture for default anti-fee-sniping,
    current tx version `2`, and one multi-recipient `subtractfeefrom` edge
