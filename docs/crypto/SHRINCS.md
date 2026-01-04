# SHRINCS: Stateful Hash-based Signatures for QPB

## Overview

SHRINCS is a **hybrid stateful + stateless** post-quantum signature scheme designed for Bitcoin by Jonas Nick (Blockstream Research). It combines:

- **Stateful path**: Unbalanced XMSS tree with WOTS+C one-time signatures (small, efficient)
- **Stateless fallback**: SPHINCS+ variant for emergency recovery (larger, unlimited)

## Status

| Aspect | Status |
|--------|--------|
| **Consensus** | Reserved (alg_id 0x30), **inactive** at genesis |
| **Implementation** | Phase 1-3 complete (WOTS+C, PORS+FP, XMSS^MT, SPHINCS+ fallback) |
| **Target Security** | NIST Level 1 (128-bit) dev, Level 3 (192-bit) production |
| **Activation** | Requires hard fork + security audit |

## Implementation Status

### Completed Phases

| Phase | Components | Status |
|-------|------------|--------|
| **Phase 1** | WOTS+C (counter grinding), basic XMSS tree | ✅ Complete |
| **Phase 2** | PORS+FP (octopus auth), XMSS^MT hypertree | ✅ Complete |
| **Phase 3** | SPHINCS+-128s fallback, unified signature type | ✅ Complete |
| **Phase 4** | Consensus integration, AlgorithmId 0x30 wiring | Pending |

### Remaining Work

1. **Wire into consensus** (`src/pq.rs`, `src/validation.rs`)
2. **State persistence** (file-based with atomic updates)
3. **Security audit** before activation

### Monitoring

Track these resources for updates:

- **Delving Bitcoin**: [SHRINCS thread](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158)
- **ePrint**: [Hash-based Signatures for Bitcoin (2025/2203)](https://eprint.iacr.org/2025/2203)
- **GitHub**: [jonasnick](https://github.com/jonasnick)
- **Blockstream Research**: Watch for SHRINCS-related repos

## Level 3 (192-bit) Parameters

Based on the Delving Bitcoin specification:

```
NIST Level 3 (192-bit security)
├── Hash: SHA-256 (truncated to n bytes)
├── n = 24 bytes (hash output size)
├── w = 256 (Winternitz parameter)
├── l = 24 chains (192/8 = 24)
├── WOTS+C signature: 24 chains × 24 bytes = 576 bytes
├── Overhead: 32-byte randomness + 4-byte counter = 36 bytes
├── Auth path: q × 24 bytes (grows with signature count)
├── Total signature: 612 + q × 24 bytes
│   └── q=1 (first sig): 636 bytes
│   └── q=10: 852 bytes
└── Public key: 64 bytes (32B XMSS root + 32B SPHINCS+ hash)
```

## Unbalanced XMSS Tree Structure

Unlike balanced XMSS, SHRINCS uses an **unbalanced tree** optimized for few signatures:

```
        Root
       /    \
      *      OTS₁ (depth 1) ← First signature: 612 + 24 = 636 bytes
     / \
    *   OTS₂ (depth 2) ← Second signature: 612 + 48 = 660 bytes
   / \
  *   OTS₃ (depth 3) ← Third signature: 612 + 72 = 684 bytes
 / \
...

Auth path size = depth × n = depth × 24 bytes
```

**Key insight**: Most Bitcoin UTXOs are spent 1-3 times. The unbalanced tree optimizes for this case - first signatures are smallest.

## Hybrid Fallback Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                    SHRINCS Public Key                       │
│  [32 bytes: XMSS root] || [32 bytes: SPHINCS+ pk hash]      │
└─────────────────────────────────────────────────────────────┘

Normal signing (stateful):
1. Check state file for next available leaf index
2. Generate WOTS+C signature at that leaf
3. Compute authentication path
4. Update state file atomically
5. Return compact signature

Emergency fallback (stateless):
1. State file corrupted/lost OR explicitly requested
2. Sign with SPHINCS+ using stateless key
3. Return larger signature (but unlimited uses)
4. Funds recoverable even without state
```

## Signature Wire Format

```
Stateful signature:
┌──────────┬───────────┬─────────────────┬──────────────────┐
│ Flag (1B)│ Index (4B)│ WOTS+C sig (var)│ Auth path (var)  │
│   0x00   │  leaf_idx │   576 bytes     │  depth × 24B     │
└──────────┴───────────┴─────────────────┴──────────────────┘

Fallback signature:
┌──────────┬───────────┬─────────────────────────────────────┐
│ Flag (1B)│ Reserved  │ SPHINCS+ signature (larger)         │
│   0x01   │   (4B)    │   ~7KB-17KB depending on params     │
└──────────┴───────────┴─────────────────────────────────────┘
```

## Current Implementation vs Target

| Aspect | Current (Phase 3) | Target (Production) |
|--------|-------------------|---------------------|
| PK size | 64 bytes | 64 bytes ✓ |
| Stateful sig | ~3.4 KB | ~3.4 KB ✓ |
| Fallback sig | ~7.8 KB (SPHINCS+-128s) | ~7.8 KB ✓ |
| WOTS w | 256 | 256 ✓ |
| Tree | XMSS^MT hypertree | XMSS^MT ✓ |
| Security | 128-bit PQ (Level 1) | 192-bit PQ (Level 3) |
| Fallback | SPHINCS+-SHA2-128s | SPHINCS+-SHA2-192s |
| State | In-memory | File-based + atomic |

## Codebase Structure

```
src/shrincs/               # Production SHRINCS implementation
├── mod.rs                 # Module entry, re-exports
├── params.rs              # Level 1/3 parameter definitions
├── types.rs               # Key and signature types
├── error.rs               # Error types
├── api.rs                 # Trait definitions (keygen, sign, verify)
├── state.rs               # State management (v1/v2 formats, layer tracking)
├── wots.rs                # WOTS+C implementation (counter grinding)
├── pors.rs                # PORS+FP (octopus auth, few-time signatures)
├── tree.rs                # XMSS^MT hypertree (d-layer structure)
├── shrincs.rs             # Full orchestrator (keygen, sign, verify, fallback)
└── sphincs_fallback.rs    # SPHINCS+-128s stateless fallback

tests/
├── shrincs_phase2.rs      # Integration tests for PORS, hypertree, state
└── shrincs_roundtrip.rs   # End-to-end signature roundtrip tests
```

### Key Types

| Type | Purpose |
|------|---------|
| `ShrincsKeyMaterial` | Stateful PORS+XMSS keys |
| `ShrincsExtendedKeyMaterial` | Stateful + SPHINCS+ fallback keys |
| `ShrincsUnifiedSignature` | Enum: `Stateful` or `Fallback` |
| `SigningState` | Leaf allocation, v2 layer tracking |

## Consensus Integration Path

When reference implementation is available:

1. **Phase 4**: Port/wrap reference into `src/shrincs/`
2. **Phase 5**: Update `src/pq.rs` to accept AlgorithmId 0x30
3. **Phase 5**: Update `src/constants.rs` with final sizes
4. **Phase 5**: Wire into `src/validation.rs`
5. **Hard Fork**: Define activation height, coordinate upgrade
6. **Audit**: External cryptographic security review

## Open Questions

1. **State Storage**: File-based with atomic updates? Database? Hardware wallet?
2. ~~**Fallback Trigger**~~: ✅ Implemented - auto on `StateExhausted`/`StateCorrupted`, or via `force_fallback` flag
3. **MPC Compatibility**: How to handle N-of-N multisig with stateful scheme?

## References

- [SHRINCS Delving Bitcoin Thread](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158) (Dec 11, 2025)
- [Hash-based Signatures for Bitcoin (ePrint 2025/2203)](https://eprint.iacr.org/2025/2203)
- [XMSS RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
- [SPHINCS+ Specification](https://sphincs.org/)
- [Jonas Nick GitHub](https://github.com/jonasnick)
