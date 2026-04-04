# Consensus Surface

## Status: FROZEN
## Spec-ID: CONSENSUS-SURFACE-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## In-Scope Consensus Areas
- Chain identity and genesis constants.
- Script opcode signature semantics.
- Block weight and script element bounds.
- Signature encoding and algorithm id checks.

## Locked v1 Choices
- New genesis chain with deterministic identity constants.
- `OP_CHECKSIG` and `OP_CHECKMULTISIG` map to PQSig verification.
- Pre-taproot signature hash type is fixed `SIGHASH_ALL` in v1.
- Taproot deployment remains disabled in v1.
- Max block weight is 16,000,000 WU.
- Max script element size is at least 10,000 bytes.

## Post-v1 Boundary
- Future witness-v1 posture is frozen in `TAPROOT_POSTURE.md`.
- Activation/deployment/rollback model and concrete dormant replacement deployment values are frozen in `TAPROOT_ACTIVATION.md`.
- Inherited Taproot semantics are not the future activation target as-is.
- The first positive post-v1 seam is now frozen as a block-validation-only
  witness-v1 / 32-byte / non-P2SH replacement-script-hash path with
  `SHA256(revealed_script) == program`, fixed `SIGHASH_ALL`, and no generic
  witness-v1, mempool, relay, or policy meaning.

## Out of Scope for v1
- Wallet UX for keypool batching and recovery flows.
- New RPCs for legacy-compatible signing surfaces.
