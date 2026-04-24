# PQBTC PQ Wallet Sendall Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SENDALL-v1
## Updated: 2026-04-24
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[sendall](../test/functional/wallet_sendall.py)
RPC posture and the restored inherited `wallet_sendall.py` matrix under the
current legacy-compatible PQC profile.

## Owned Surface

The current owned PQ-native `sendall` RPC path is:

- [wallet_pq_sendall.py](../test/functional/wallet_pq_sendall.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

The inherited compatibility path is:

- [wallet_sendall.py](../test/functional/wallet_sendall.py)

It is now part of the required PQ gate because it passes unchanged under the
restored legacy-compatible PQC profile.

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

This tranche does not define behavior outside the existing inherited and
PQ-only test surfaces. It explicitly does not take on:

- replacement-path Taproot or bech32m wallet semantics beyond existing tests
- new PQ-only active-manager RPC behavior
- prior-release compatibility for `feature_coinstatsindex_compatibility.py`

Those remain separate backlog or compatibility decisions.

## Confidence

Targeted confidence pass on 2026-04-08:

- `python3 test/functional/wallet_pq_sendall.py`
  - result: passed
  - covers the PQ-only `sendall` RPC posture for default anti-fee-sniping,
    explicit `locktime = 0`, and current tx version `2`

Inherited send-path promotion on 2026-04-24:

- `build/test/functional/test_runner.py --jobs=1 wallet_sendall.py`
  - result: passed
  - covers the inherited full-balance sweep, split-recipient, specified-output,
    invalid recipient/amount, send_max, specific-input, watch-only PSBT,
    minconf/maxconf, anti-fee-sniping, unconfirmed input/change,
    ancestor-aware funding, and too-large transaction surfaces under the
    current legacy-compatible PQC profile
