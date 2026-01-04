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

### Phase 1: Core Primitives (Foundation)

**Goal**: Implement base cryptographic building blocks

1. **Port WOTS+C** from paper Section 3.4
   - Counter grinding replaces checksum chain
   - Use existing scaffold: `src/shrincs_proto/wots_c.rs`

2. **Implement PORS+FP** (Section 4.4)
   - Fixed positions variant for few-time signatures
   - Use existing scaffold: `src/shrincs_proto/fors.rs`

3. **Hash function abstraction**
   - SHAKE256 for extensible output
   - Domain separation for different uses

**Deliverables**:
- `src/shrincs/wots.rs` - WOTS+C implementation
- `src/shrincs/fors.rs` - PORS+FP implementation
- Test vectors from Blockstream repo

---

### Phase 2: Tree Construction

**Goal**: Build Merkle tree infrastructure

4. **XMSS^MT layer** using unbalanced tree structure
   - Use existing scaffold: `src/shrincs_proto/xmss_unbalanced.rs`
   - Implement hypertree with d=4 subtrees, h=32 total height

5. **State management** (CRITICAL)
   - Prevent key reuse - stateful component vulnerability
   - Persistent state tracking per keypair
   - Recovery mechanisms for interrupted signing

6. **Tree caching**
   - Pre-compute authentication paths where possible
   - Balance memory vs computation trade-offs

**Deliverables**:
- `src/shrincs/xmss.rs` - XMSS^MT implementation
- `src/shrincs/state.rs` - State management
- `src/shrincs/tree.rs` - Merkle tree utilities

---

### Phase 3: SPHINCS+C Integration

**Goal**: Assemble full signature scheme

7. **Full SPHINCS+C assembly** (paper Section 5)
   - Integrate WOTS+C, PORS+FP, XMSS^MT
   - Target: Level 1 security, 2^30 signature capacity

8. **Signature serialization**
   - Compact encoding format
   - Version byte for future parameter changes

9. **Key generation**
   - Secure randomness requirements
   - HD wallet considerations (hardened derivation only - see paper Section 7)

**Deliverables**:
- `src/shrincs/sphincs.rs` - Main SPHINCS+C implementation
- `src/shrincs/keygen.rs` - Key generation
- `src/shrincs/serialize.rs` - Wire format

---

### Phase 4: Consensus Integration

**Goal**: Wire into QPB validation pipeline

10. **PQ module integration** (`src/pq.rs`)
    - Add SHRINCS verify/sign/keypair functions
    - Algorithm ID `0x30` proper handling

11. **PQSigCheck cost calculation**
    - Hash-based sigs have different cost profile than lattice
    - Benchmark and tune verification cost units

12. **Script integration**
    - OP_CHECKPQSIG support for algorithm 0x30
    - P2QPKH/P2QTSH address format compatibility

**Deliverables**:
- Updated `src/pq.rs` with SHRINCS support
- Updated `src/validation.rs` for new algorithm
- Integration tests in `tests/`

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

1. [ ] Clone `BlockstreamResearch/SPHINCS-Parameters` for reference scripts
2. [ ] Deep study of paper Sections 3.4 (WOTS+C) and 4.4 (PORS+FP)
3. [ ] Implement WOTS+C in `src/shrincs/` as foundational primitive
4. [ ] Generate/obtain test vectors from Blockstream repo
5. [ ] Benchmark verification times vs ML-DSA-65

---

## Security Considerations

### Why Hybrid (ML-DSA-65 + SHRINCS)?
- **Defense in depth**: If lattice assumptions break, hash-based remains secure
- **Algorithm agility**: Users choose based on their threat model
- **Minimal overhead**: SHRINCS signature only ~130 bytes larger than ML-DSA-65

### State Management Risks
- **Key reuse is catastrophic** for stateful component
- Must implement robust state persistence
- Consider stateless-only fallback mode

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
