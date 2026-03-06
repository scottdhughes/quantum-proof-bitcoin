# PQSig Wire Format

## Status: TRACKED
## Spec-ID: PQSIG-WIRE-rc2
## Frozen-By: issue-48-rc2-reprofile-20260306
## Consensus-Relevant: YES

## Script-Layer Public Key
- `PK_script` length is exactly 33 bytes.
- Layout: `ALG_ID(1 byte) || PK_core(32 bytes)`.
- For rc2: `ALG_ID = 0x01`.
- Any other length or unknown algorithm id is invalid.

## Signature Encoding
- Signature length is exactly 4480 bytes.
- Script engine treats signature as fixed-size payload after outer checks.
- The 4-byte count field in each hypertree layer is reserved and MUST be zero.
- Any other size is invalid.

## Message Binding
- Signature verification binds to existing Bitcoin-style sighash digesting.
- rc2 pre-taproot paths evaluate signatures against fixed `SIGHASH_ALL`.

## Failure Semantics
- Encoding failures return deterministic script failure.
- No fallback to legacy secp/DER parsing is allowed in PQ consensus path.
