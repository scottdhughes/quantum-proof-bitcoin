# PQBTC PQ Wallet Send Posture

## Status: ACTIVE
## Spec-ID: PQ-WALLET-SEND-v1
## Updated: 2026-04-24
## Consensus-Relevant: NO

## Purpose

Freeze the owned PQ-only
[send](../test/functional/wallet_send.py)
RPC posture and the restored inherited `wallet_send.py` matrix under the
current legacy-compatible PQC profile.

## Owned Surface

The current owned PQ-native `send` RPC path is:

- [wallet_pq_send.py](../test/functional/wallet_pq_send.py)

It covers a PQ-only active wallet created through
[createpqwalletmanagers](../src/wallet/rpc/wallet.cpp).

The inherited compatibility path is:

- [wallet_send.py](../test/functional/wallet_send.py)

It is now part of the required PQ gate because it passes unchanged under the
restored legacy-compatible PQC profile.

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
[PQ_WALLET_CREATE_TX_POSTURE.md](./PQ_WALLET_CREATE_TX_POSTURE.md).
The owned `sendall` RPC contract is frozen separately in
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

- `python3 test/functional/wallet_pq_send.py`
  - result: passed
  - covers the PQ-only `send` RPC posture for default anti-fee-sniping,
    explicit `locktime = 0`, and current tx version `2`

Inherited send-path promotion on 2026-04-24:

- `build/test/functional/test_runner.py --jobs=1 wallet_send.py`
  - result: passed
  - covers the inherited destination send, no-broadcast and PSBT creation,
    fee/feerate and confirmation-target options, watch-only PSBT signing,
    OP_RETURN outputs, manual inputs and change controls, locktime, RBF,
    subtract-fee-from-output, unsafe and minconf handling, external-input
    solving data, and transaction weight limits under the current
    legacy-compatible PQC profile
