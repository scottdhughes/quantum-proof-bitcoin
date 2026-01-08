# SHRINCS Implementation Plan

> **STATUS: COMPLETE** — SHRINCS is now the sole active signature algorithm.
>
> Reference: Jonas Nick & Mikhail Kudinov paper (2025-2203.pdf, Blockstream Research, Rev 2025-12-05)

---

## Current State Summary

### Consensus Mechanism
- **Argon2id Proof-of-Work**: Memory-hard, quantum-resistant
- **Adaptive weight system**: 500 PQSigCheck units/block, 40 units/tx
- **Block size**: 8MB max
- **Coinbase maturity**: 100 confirmations
- BIP68/113 locktime support integrated

### Active Signature Scheme
- **SHRINCS** (alg_id 0x30) - hybrid stateful/stateless hash-based
- Public key: 16 bytes (composite hash)
- Signature: ~308-340 bytes (stateful) or ~7,856 bytes (fallback)
- Verification cost: 2 PQSigCheck units

### Deprecated / Reserved
- `ML-DSA-65 (0x11)` - DEPRECATED, removed from consensus
- `SLH-DSA (0x21)` - RESERVED (for future activation)

---

## Jonas Nick Paper Key Findings

**Paper**: "Hash-based Signature Schemes for Bitcoin"
**Authors**: Mikhail Kudinov, Jonas Nick (Blockstream Research)
**Reference Code**: https://github.com/BlockstreamResearch/SPHINCS-Parameters

### Key Innovations
1. **SPHINCS+C ("compact")** - optimized SPHINCS+ variant
2. **WOTS+C** - Winternitz OTS with counter grinding (replaces checksum chain)
3. **FORS+C** - Few-time signature with counter grinding
4. **PORS+FP** - Fixed positions variant for further optimization
5. **NIST Level 1** (128-bit security) deemed sufficient for Bitcoin

### Target Parameters (2^30 signatures)

| Parameter | Value | Description |
|-----------|-------|-------------|
| h | 32 | Total tree height |
| d | 4 | Number of subtrees |
| a | 14 | FORS tree height |
| k | 10 | Number of FORS trees |
| w | 256 | Winternitz parameter |
| **Signature** | **3,440 bytes** | Only ~130B larger than ML-DSA-65 |

### Alternative Parameters

**For 2^20 signatures** (lighter use):
- h=20, d=4, a=12, k=14, w=256
- Signature: ~2,960 bytes

**For 2^40 signatures** (heavy use):
- h=40, d=8, a=14, k=11, w=256
- Signature: ~3,720 bytes

---

## Implementation Phases

### Phase 1: Core Primitives (Foundation) ✅ COMPLETE

**Goal**: Implement base cryptographic building blocks

1. ✅ **Port WOTS+C** from paper Section 3.4
   - Counter grinding replaces checksum chain
   - Implemented in `src/shrincs/wots.rs`

2. ✅ **Implement PORS+FP** (Section 4.4)
   - Fixed positions variant with octopus auth
   - Implemented in `src/shrincs/pors.rs`

3. ✅ **Hash function abstraction**
   - SHA-256 with domain separation
   - Consistent prefix patterns across modules

**Deliverables**:
- ✅ `src/shrincs/wots.rs` - WOTS+C implementation (w=256, counter grinding)
- ✅ `src/shrincs/pors.rs` - PORS+FP implementation (octopus auth paths)
- ✅ Unit tests for both modules

---

### Phase 2: Tree Construction ✅ COMPLETE

**Goal**: Build Merkle tree infrastructure

4. ✅ **XMSS^MT layer** using hypertree structure
   - Implemented in `src/shrincs/tree.rs`
   - Configurable d layers, h_prime height per subtree

5. ✅ **State management** (CRITICAL)
   - v1/v2 serialization formats
   - Layer-level tracking for monitoring
   - `StateExhausted`/`StateCorrupted` error handling

6. ✅ **Tree caching**
   - Pre-computed PORS tree levels
   - XMSS layers built at keygen

**Deliverables**:
- ✅ `src/shrincs/tree.rs` - XMSS^MT hypertree implementation
- ✅ `src/shrincs/state.rs` - State management with layer tracking
- ✅ `tests/shrincs_phase2.rs` - Integration tests

---

### Phase 3: SPHINCS+C Integration ✅ COMPLETE

**Goal**: Assemble full signature scheme

7. ✅ **Full SPHINCS+C assembly** (paper Section 5)
   - Orchestrator in `src/shrincs/shrincs.rs`
   - Integrates WOTS+C, PORS+FP, XMSS^MT
   - Level 1 security, 2^30 signature capacity

8. ✅ **Signature serialization**
   - `to_bytes()`/`from_bytes()` on all types
   - Type prefix for unified signatures (0x00 stateful, 0x01 fallback)

9. ✅ **Key generation**
   - `keygen()` with secure randomness
   - `keygen_from_seeds()` for deterministic testing
   - `keygen_with_fallback()` includes SPHINCS+ keys

**Bonus**: SPHINCS+ Stateless Fallback
- ✅ `src/shrincs/sphincs_fallback.rs` - SPHINCS+-SHA2-128s wrapper
- ✅ `sign_auto()` with automatic fallback on state exhaustion
- ✅ `ShrincsUnifiedSignature` enum for both signature types

**Deliverables**:
- ✅ `src/shrincs/shrincs.rs` - Main orchestrator (keygen, sign, verify)
- ✅ `src/shrincs/sphincs_fallback.rs` - Stateless fallback
- ✅ 230+ tests passing with `--features shrincs-dev`

---

### Phase 4: Consensus Integration ✅ COMPLETE

**Goal**: Wire into QPB validation pipeline

10. ✅ **PQ module integration** (`src/pq.rs`)
    - Added `AlgorithmId::SHRINCS` variant (feature-gated)
    - Added `verify_shrincs()` dispatch with type prefix parsing
    - Added `shrincs_keypair()` and `shrincs_sign()` wrappers
    - Algorithm ID `0x30` proper handling

11. ✅ **PQSigCheck cost calculation**
    - SHRINCS costs 2 units (vs ML-DSA-65's 1 unit)
    - Hash-based verification ~2x slower than lattice

12. ✅ **Script integration**
    - OP_CHECKPQSIG support for algorithm 0x30 via `verify_pq()` dispatch
    - P2QPKH integration test passing

**Deliverables**:
- ✅ Updated `src/pq.rs` with SHRINCS support
- ✅ Updated `src/constants.rs` with correct sizes
- ✅ Integration tests in `tests/basic.rs` and `tests/shrincs_roundtrip.rs`

---

### Phase 5: Production Readiness ✅ COMPLETE

**Goal**: Fallback witness format and state persistence

13. ✅ **Fallback witness format** (`src/pq.rs`, `src/validation.rs`)
    - Extended pk format: `[alg_id(1) || base_pk(64) || sphincs_pk(32)]` = 97 bytes
    - Signature type prefix: 0x00 stateful, 0x01 fallback
    - P2QPKH validation handles variable pk length
    - qpkh32 computed from base pk only (address compatibility)

14. ✅ **File-based state persistence** (`src/shrincs/state.rs`)
    - `FileStateManager` with atomic temp-file + rename
    - Cross-platform file locking via `fs2` crate
    - `LockGuard` RAII pattern for safe lock release
    - `load_with_lock()` / `save_with_lock()` for explicit locking
    - Parent directory auto-creation

15. ✅ **Wrapper functions** (`src/pq.rs`)
    - `shrincs_keypair_with_fallback()` - Extended keys with SPHINCS+
    - `shrincs_sign_fallback()` - Direct SPHINCS+ signing

**Deliverables**:
- ✅ Updated `src/pq.rs` with fallback verification and wrappers
- ✅ Updated `src/validation.rs` for extended pk handling
- ✅ Enhanced `src/shrincs/state.rs` with FileStateManager
- ✅ P2QPKH fallback integration test

---

### Phase 6: Activation & Deployment

**Goal**: Safe production rollout

16. **Security audit**
    - Third-party review of SHRINCS implementation
    - Formal verification where possible

17. **Hard fork activation planning**
    - Define activation height
    - Grace period for node upgrades

18. **Testnet deployment**
    - Extended soak period
    - Stress testing with mixed algorithm transactions

19. **Documentation**
    - Update whitepaper
    - Wallet integration guide
    - Migration documentation

**Deliverables**:
- Activation parameters in constants
- Audit report
- Updated documentation

---

## Immediate Next Steps

1. [x] Clone `BlockstreamResearch/SPHINCS-Parameters` for reference scripts
2. [x] Deep study of paper Sections 3.4 (WOTS+C) and 4.4 (PORS+FP)
3. [x] Implement WOTS+C in `src/shrincs/` as foundational primitive
4. [x] Implement PORS+FP with octopus auth
5. [x] Build XMSS^MT hypertree with state management
6. [x] Add SPHINCS+ stateless fallback

**Phase 4 Complete:**
- [x] Wire SHRINCS into `src/pq.rs` (Algorithm ID 0x30)
- [x] Set PQSigCheck cost to 2 units (hash-based ~2x slower)
- [x] Verification via `verify_pq()` dispatch (no validation.rs changes needed)
- [x] P2QPKH integration test with actual transaction

**Phase 5 Complete:**
- [x] Define fallback witness format (extended 97-byte pk)
- [x] Update validation.rs to handle variable SHRINCS pk length
- [x] Implement FileStateManager with atomic writes and file locking
- [x] Add fallback P2QPKH integration test

**Wallet Integration Complete (PR #63):**
- [x] Extended WalletKey with alg_id and signing_state_hex fields
- [x] Added generate_key_shrincs() for SHRINCS keypair generation
- [x] Added sign_shrincs() with stateful signing state management
- [x] Wallet version 3 migration support

**Consensus Activation Wiring Complete (PR #63):**
- [x] Thread height/network through validation call chain
- [x] QScriptCtx extended with height and network fields
- [x] AlgorithmId::from_byte_at_height() used throughout
- [x] Mempool validation includes activation context

**Phase 6 Next Steps:**
- [ ] Security audit before activation height
- [ ] Define hard fork activation parameters
- [ ] Testnet deployment and stress testing

---

## Security Considerations

### Why Hybrid (ML-DSA-65 + SHRINCS)?
- **Defense in depth**: If lattice assumptions break, hash-based remains secure
- **Algorithm agility**: Users choose based on their threat model
- **Minimal overhead**: SHRINCS signature only ~130 bytes larger than ML-DSA-65

### State Management Risks
- **Key reuse is catastrophic** for stateful component
- Must implement robust state persistence
- ✅ Stateless fallback mode implemented (`sign_auto()` with SPHINCS+-128s)

### HD Wallet Limitations (Paper Section 7)
- No non-hardened derivation for hash-based signatures
- Each derived key needs independent state
- Document wallet integration requirements clearly

---

## References

- Jonas Nick paper: `/Users/scott/Downloads/2025-2203.pdf`
- Blockstream scripts: https://github.com/BlockstreamResearch/SPHINCS-Parameters
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- Existing SHRINCS spec: `docs/crypto/SHRINCS.md`
- ML-DSA-65 spec: `docs/crypto/MLDSA-65.md`
