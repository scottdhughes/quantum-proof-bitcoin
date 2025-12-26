# Quantum Proof Bitcoin — Consensus Notes (v1.0m, 2025-12-26)

**Scope:** Consensus-facing parameters for the current prototype. INTERNAL; not an audit, not legal/compliance advice.

## Algorithm registry @ genesis
- **Active:** alg_id `0x11` — ML-DSA-65 (Dilithium3), NIST Cat 3
  - PK bytes: 1952
  - Sig bytes: 3309
  - PQSigCheck cost: 1
- **Reserved / Inactive:**
  - alg_id `0x21` — SLH-DSA-SHA2-192s (reserved)
  - alg_id `0x30` — SHRINCS (dev-only; consensus rejects)
- All other alg_id values: rejected.

## Consensus enforcement (summary)
- AlgorithmId parser accepts only `0x11`; anything else -> `InactiveAlgorithm`.
- Signature verification enforces `msg32` length 32, pk/sig lengths exact, and uses Dilithium3 verify.
- SHRINCS helpers exist behind `shrincs-dev` feature only and are never consensus-active.

## PQSigCheck
- Cost units: MLDSA65 = 1. Block/tx budgets unchanged (500/block, 40/tx).

## Vectors
- Deterministic ML-DSA vectors live in `vectors/` and are regenerated with `cargo run --bin gen_vectors`.

## Activation stance
- SHRINCS and SLH-DSA remain reserved until a future hard fork and published, audited implementations.

