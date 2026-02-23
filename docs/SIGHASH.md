# Sighash Policy for PQBTC v1

## Status: FROZEN
## Spec-ID: SIGHASH-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## Rule
PQSig verification consumes the existing Bitcoin-style sighash digesting logic.
For pre-taproot CHECKSIG/CHECKMULTISIG in v1, hash type is fixed to `SIGHASH_ALL`.

## Rationale
Reusing the existing sighash construction minimizes migration risk and preserves transaction digest semantics while replacing only the authorization primitive.

## Constraints
- Digest computation must remain byte-for-byte stable for equivalent transaction contexts.
- Any future sighash redesign requires a new Spec-ID version and explicit consensus activation process.
