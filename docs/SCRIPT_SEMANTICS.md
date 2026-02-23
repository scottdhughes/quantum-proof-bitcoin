# Script Semantics for PQBTC v1

## Status: FROZEN
## Spec-ID: SCRIPT-SEM-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## Signature Opcodes
- `OP_CHECKSIG` verifies PQSig for a 33-byte `PK_script` and 4480-byte signature.
- `OP_CHECKMULTISIG` verifies multiple PQSig signatures under existing stack mechanics.

## Validation Rules
- Unknown `ALG_ID` fails.
- Wrong public key size fails.
- Wrong signature size fails.
- Failed PQSig verification fails.
- Pre-taproot opcode hashing uses fixed `SIGHASH_ALL` in v1.

## Legacy Behavior
- Active PQ consensus paths do not accept DER/secp legacy signature encodings.
