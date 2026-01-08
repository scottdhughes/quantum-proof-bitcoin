# ML-DSA-65 (alg_id 0x11) — DEPRECATED

> **DEPRECATION NOTICE**: ML-DSA-65 has been removed from QPB consensus. This document is retained for historical reference only. SHRINCS (alg_id 0x30) is now the sole post-quantum signature algorithm.

## Status
- **DEPRECATED:** alg_id = 0x11 has been removed from consensus.
- **Active:** alg_id 0x30 (SHRINCS) is the sole active algorithm.
- Consensus rejects alg_id 0x11 unconditionally.

## Historical Sizes (bytes)
- Public key: 1952
- Signature: 3309
- Serialized pk_ser: 1 (alg_id) + 1952 = 1953
- Serialized sig_ser: 3309 + 1 (sighash byte) = 3310

## Migration Notes

ML-DSA-65 was the initial genesis algorithm during early development. It has been replaced by SHRINCS, which provides:

1. **Smaller signatures**: ~308-340 bytes vs 3,309 bytes
2. **Hash-only security**: No lattice assumptions
3. **Stateful efficiency**: First signatures are smallest

See [SHRINCS Spec](SHRINCS.md) for the current algorithm specification.

## Historical Implementation provenance
| Component | Crate | Version | Upstream origin |
|-----------|-------|---------|-----------------|
| Dilithium3 verify | `pqcrypto-dilithium` | 0.5.0 | PQClean-derived implementation |
| Traits | `pqcrypto-traits` | 0.3.5 | PQClean-derived common traits |

## Security notes
This algorithm is no longer used in QPB. The code has been removed from the consensus path.
