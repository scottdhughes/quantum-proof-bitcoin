# PQBTC PQ Wallet Sendmany Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SENDMANY-v1
## Updated: 2026-04-24
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[sendmany](../test/functional/wallet_sendmany.py)
RPC posture and the restored inherited `wallet_sendmany.py` subtract-fee
validation surface under the current legacy-compatible PQC profile.

## Owned Surface

The current owned PQ-native `sendmany` RPC path is:

- [wallet_pq_sendmany.py](../test/functional/wallet_pq_sendmany.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

The inherited compatibility path is:

- [wallet_sendmany.py](../test/functional/wallet_sendmany.py)

It is now part of the required PQ gate because it passes unchanged under the
restored legacy-compatible PQC profile.

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

This tranche does not define behavior outside the existing inherited and
PQ-only test surfaces. It explicitly does not take on:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

Those remain separate backlog or compatibility decisions.

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_sendmany.py`
  - result: passed
  - covers the PQ-only `sendmany` RPC posture for default anti-fee-sniping,
    current tx version `2`, and one multi-recipient `subtractfeefrom` edge

Inherited send-path promotion on 2026-04-24:

- `build/test/functional/test_runner.py --jobs=1 wallet_sendmany.py`
  - result: passed
  - covers inherited `subtractfeefrom` validation for duplicate, missing,
    negative, out-of-bounds, invalid-type, and mixed destination/index cases
    under the current legacy-compatible PQC profile
