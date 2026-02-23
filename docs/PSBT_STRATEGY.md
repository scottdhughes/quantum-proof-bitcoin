# PSBT Strategy for PQBTC

## Status: FROZEN
## Spec-ID: PSBT-STRAT-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: NO

## Scope
Planning document for external signer and PSBT flow adaptations for PQ signatures.

## v1 Position
- No expanded production PSBT signer interface is required for node+consensus v1.
- External signer integration follows after core consensus and policy stabilization.

## Future Constraints
- PSBT fields carrying PQ key/signature data must preserve deterministic serialization.
- Backward-incompatible PSBT field semantics require a new spec revision.
