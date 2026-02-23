# PQSig Wire Format

## Status: FROZEN
## Spec-ID: PQSIG-WIRE-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## Script-Layer Public Key
- `PK_script` length is exactly 33 bytes.
- Layout: `ALG_ID(1 byte) || PK_core(32 bytes)`.
- For v1: `ALG_ID = 0x00`.
- Any other length or unknown algorithm id is invalid.

## Signature Encoding
- Signature length is exactly 4480 bytes.
- Script engine treats signature as opaque fixed-size payload after outer checks.
- Any other size is invalid.

## Message Binding
- Signature verification binds to existing Bitcoin-style sighash digesting.
- v1 pre-taproot paths evaluate signatures against fixed `SIGHASH_ALL`.

## Failure Semantics
- Encoding failures return deterministic script failure.
- No fallback to legacy secp/DER parsing is allowed in PQ consensus path.
