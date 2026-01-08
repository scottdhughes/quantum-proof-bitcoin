# Quantum Proof Bitcoin — Consensus Notes (v1.1, 2025-01)

**Scope:** Consensus-facing parameters for the current prototype. INTERNAL; not an audit, not legal/compliance advice.

## Algorithm registry @ genesis
- **Active:** alg_id `0x30` — SHRINCS (stateful hash-based), NIST Level 1
  - PK bytes: 16 (composite hash)
  - Sig bytes: ~308-340 (stateful), ~7,856 (SPHINCS+ fallback)
  - PQSigCheck cost: 2
- **Reserved / Inactive:**
  - alg_id `0x11` — ML-DSA-65 (deprecated, removed from consensus)
  - alg_id `0x21` — SLH-DSA-SHA2-192s (reserved for future use)
- All other alg_id values: rejected.
- Crypto provenance and validation invariants: see `docs/crypto/SHRINCS.md`.

## Consensus enforcement (summary)
- AlgorithmId parser accepts only `0x30`; anything else -> `InactiveAlgorithm`.
- Signature verification:
  - Validates 16-byte composite public key
  - Accepts both stateful (~308-340 bytes) and SPHINCS+ fallback (~7,856 bytes) signatures
  - Verifies against appropriate algorithm based on signature length
- SHRINCS is consensus-active on all networks (Devnet, Testnet, Mainnet).

## PQSigCheck
- Cost units: SHRINCS = 2. Block/tx budgets unchanged (500/block, 40/tx).

## Vectors
- Deterministic SHRINCS vectors live in `vectors/` and are regenerated with `cargo run --bin gen_vectors`.
- Size metadata in `vectors/metadata/shrincs_sizes.json`.

## Known Limitations
- Wallet import (`dumpwallet`/`importwallet`) does not export signing state
- See README.md "Known Limitations" section for details
