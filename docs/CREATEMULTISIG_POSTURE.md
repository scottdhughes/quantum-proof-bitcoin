# PQBTC `createmultisig` Posture

## Status: ACTIVE
## Spec-ID: CREATEMULTISIG-POSTURE-v1
## Frozen-By: track-a-phase1-20260412
## Consensus-Relevant: NO

## Purpose

Define what the inherited `createmultisig` RPC still owns under the all-PQ
Track A stance, and where that ownership stops.

## Current Owned Surface

The current passing
[rpc_createmultisig.py](../test/functional/rpc_createmultisig.py) suite now
owns an output-shape contract only.

It currently proves:

- `createmultisig` still returns coherent descriptors and addresses for:
  - `legacy`
  - `p2sh-segwit`
  - `bech32`
- the returned address matches `deriveaddresses(descriptor)` on the current
  PQBTC network, rather than assuming inherited `bcrt...` regtest prefixes
- 16-of-20 multisig creation is still accepted as an RPC/output-construction
  surface for all three inherited address families
- creation with more than 20 keys remains rejected
- `bech32m` creation is still explicitly rejected
- mixed compressed/uncompressed key sets still fall back to the legacy address
  with warnings
- `sortedmulti(...)` still matches the corresponding `multi(...)` descriptor
  over the BIP67-sorted key order
- redeemScript encoding for `n` from 1 to 20 still matches the expected
  multisig script bytes

## Deferred Boundary

This file no longer claims broad inherited classical multisig funding or
signing compatibility.

The first representative negative control is now explicit:

- attempting to fund a classical multisig output under the functional harness
  fails at `scriptpubkey`

That failure is now treated as deferred Track A compatibility work, not as an
accidental test break inside `rpc_createmultisig.py`.

## What This Does Not Mean

This posture note does **not** mean:

- classical multisig spending is rehabilitated
- `signrawtransactionwithkey` plus `combinerawtransaction` is an owned Track A
  surface for inherited multisig scripts
- `bech32m` multisig creation has replacement semantics
- this suite should move into `pq_required`

Those broader spend-path and replacement-path questions remain follow-on work.

## Confidence Snapshot

Targeted confidence pass run on 2026-04-12:

- `python3 test/functional/rpc_createmultisig.py`
  - result: passed
  - current posture:
    - inherited `createmultisig` descriptor/address output construction still
      works for `legacy` / `p2sh-segwit` / `bech32`
    - address expectations are grounded on descriptor derivation under the
      current PQBTC network identity
    - one representative classical funding attempt is frozen as a deferred
      `scriptpubkey` negative control

## Interpretation

- `createmultisig` is still useful as an inherited RPC/output-shape reference
  surface
- the current repo does not own broad classical multisig funding/signing
  compatibility
- the next cleaner wallet-adjacent follow-on is
  [wallet_multisig_descriptor_psbt.py](../test/functional/wallet_multisig_descriptor_psbt.py),
  not reopening old raw-signing rehab inside this RPC suite
