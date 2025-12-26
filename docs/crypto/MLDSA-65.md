# ML-DSA-65 (alg_id 0x11) — Consensus-Active PQ Signature

## Status at genesis
- **Consensus-active:** alg_id = 0x11 (ML-DSA-65 / Dilithium3).
- **Reserved / consensus-rejected:** alg_id 0x21 (SLH-DSA) and alg_id 0x30 (SHRINCS).
- Consensus rejects any alg_id other than 0x11 unconditionally.

## Sizes (bytes)
- Public key: 1952
- Signature: 3309
- Serialized pk_ser: 1 (alg_id) + 1952 = 1953
- Serialized sig_ser: 3309 + 1 (sighash byte) = 3310

## Implementation provenance
| Component | Crate | Version | Upstream origin |
|-----------|-------|---------|-----------------|
| Dilithium3 verify | `pqcrypto-dilithium` | 0.5.0 | PQClean-derived implementation shipped in the crate |
| Traits | `pqcrypto-traits` | 0.3.5 | PQClean-derived common traits |

Provenance source: `Cargo.lock` in this repo. The `pqcrypto-*` crates vendor Dilithium code based on PQClean; no external system libraries are required.

## Determinism and vectors
- Consensus only **verifies** signatures; signing randomness is not consensus-critical.
- Test vectors in `vectors/` are generated deterministically via `cargo run --bin gen_vectors` using fixed key material, which is safe for testing and does not affect consensus rules.

## Validation invariants (enforced by consensus + tests)
- Unknown `alg_id` is rejected.
- Public key length must be exactly 1952 bytes (pk_ser = 1953 with alg_id prefix).
- Signature length must be exactly 3309 bytes (sig_ser = 3310 with sighash byte).
- Message binding: verification is over the computed `msg32` (sighash); tests/vectors mutate msg/sig and must fail.

## Cross-implementation verification (optional, dev-only)
A future **dev-only** feature can add a secondary verifier (e.g., liboqs Dilithium3) to cross-check `(msg32, pk, sig)` during testing. This must remain feature-gated and non-consensus so nodes without the extra library remain compatible.

## Security and operational notes
- Verifiers are expected to run in constant time for secret-dependent operations (as provided by the upstream PQClean-derived code).
- Dependencies are pinned in `Cargo.lock`; upgrading the signature scheme or enabling additional algorithms would require a deliberate hard fork and code/spec updates.
