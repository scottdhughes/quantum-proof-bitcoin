# SHRINCS Implementation Plan

> Generated: 2026-01-04
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
- **ML-DSA-65** (FIPS 204 / Dilithium3) - lattice-based
- Algorithm ID: `0x11`
- Public key: 1,952 bytes
- Signature: 3,309 bytes
- Verification cost: 5 PQSigCheck units

### Reserved (Consensus-Rejected Until Activation)
- `SLH-DSA (0x21)` - FIPS 205 hash-based
- `SHRINCS (0x30)` - Hybrid stateful/stateless (this plan)

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

### Phase 5: Activation & Deployment

**Goal**: Safe production rollout

13. **Hard fork activation planning**
    - Define activation height
    - Grace period for node upgrades

14. **Security audit**
    - Third-party review of SHRINCS implementation
    - Formal verification where possible

15. **Testnet deployment**
    - Extended soak period
    - Stress testing with mixed algorithm transactions

16. **Documentation**
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

**Phase 5 Next Steps:**
- [ ] Define fallback witness format for SPHINCS+ verification
- [ ] Implement file-based state persistence with atomic updates
- [ ] Security audit before activation height
- [ ] Define hard fork activation parameters

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
