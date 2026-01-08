# SHRINCS Implementation Plan: COMPLETE

> **STATUS: COMPLETE** — All tasks implemented and tested. This document is retained for historical reference.

## Overview

SHRINCS has been implemented as the **sole post-quantum signature scheme**. ML-DSA-65 has been removed.

Aligned with the [Delving Bitcoin proposal](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158):

| Component | Security | Signature Size | Public Key |
|-----------|----------|----------------|------------|
| **SHRINCS stateful** | Level 1 | 292 + q×16 bytes | 16 bytes |
| **SPHINCS+ fallback** | Level 1 | ~7,856 bytes | (included in composite) |

References:
- [SHRINCS Proposal](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158) (Delving Bitcoin)
- "Hash-based Signature Schemes for Bitcoin" (Kudinov & Nick, Blockstream Research, 2025-12-05)

---

## Completed Tasks

### 0. Remove ML-DSA-65 ✅

**Files modified:**
- `/src/pq.rs` - Removed ML-DSA-65 functions, SHRINCS-only verification
- `/src/constants.rs` - Removed MLDSA65_* constants
- `/src/activation.rs` - SHRINCS active from genesis on all networks
- `Cargo.toml` - Removed pqcrypto-dilithium dependency (still needed for some FFI)
- `/tests/` - Removed ML-DSA specific tests, updated expectations
- `/vectors/` - Regenerated for SHRINCS-only

### 1. Switch SHRINCS to Level 1 Parameters ✅

- n = 16 bytes, 16 chains
- Signature: 292 + q×16 bytes (~308-340 base)

### 2. Public Key Size Reduction (64 → 16 bytes) ✅

- `ShrincsPublicKey` = 16 bytes (composite hash of stateful + stateless keys)
- Verification accepts full keys, checks against composite hash

### 3. SPHINCS+ Fallback at Level 1 ✅

- SPHINCS+-SHA2-128s (7,856 bytes)

---

## Verification Results ✅

- [x] SHRINCS signature q=1: ~308 bytes
- [x] SHRINCS signature q=2: ~324 bytes (matches proposal title!)
- [x] Public key: 16 bytes
- [x] SPHINCS+ fallback: ~7,856 bytes
- [x] All 128 unit tests pass
- [x] All ~180 integration tests pass
- [x] Roundtrip sign/verify works

---

## Known Limitations

1. **Wallet import**: `dumpwallet`/`importwallet` do not export signing state
   - 2 tests ignored: `importwallet_imports_keys`, `importwallet_skips_existing_keys`
   - SHRINCS is stateful — importing keys without state is unsafe
   - See README.md "Known Limitations" section

---

## Final Test Command

```bash
cargo test --features shrincs-dev
# Expected: All pass, 2 ignored (wallet import tests)
```
