# SHRINCS: Stateful Hash-based Signatures for QPB

## Overview

SHRINCS is a **hybrid stateful + stateless** post-quantum signature scheme designed for Bitcoin by Jonas Nick (Blockstream Research). It combines:

- **Stateful path**: Unbalanced XMSS tree with WOTS+C one-time signatures (small, efficient)
- **Stateless fallback**: SPHINCS+ variant for emergency recovery (larger, unlimited)

## Status

| Aspect | Status |
|--------|--------|
| **Consensus** | Reserved (alg_id 0x30), **inactive** at genesis |
| **Implementation** | Awaiting reference implementation |
| **Target Security** | NIST Level 3 (192-bit) |
| **Activation** | Requires hard fork + security audit |

## Implementation Plan

### Strategy: Wait for Reference Implementation

Given the production-path goal, we are **not** implementing SHRINCS cryptography from scratch. Instead:

1. **Monitor** Jonas Nick's GitHub and Delving Bitcoin thread
2. **Prepare** codebase architecture for integration
3. **Port/Wrap** when reference implementation becomes available
4. **Audit** before consensus activation

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

## Comparison to Current Implementation

| Aspect | Current Stub (`shrincs_proto/`) | Target (Level 3) |
|--------|--------------------------------|------------------|
| PK size | 64 bytes | 64 bytes ✓ |
| Sig size | 324 bytes (toy) | 636+ bytes |
| WOTS w | 16 (toy) | 256 |
| Tree | Height=1 (toy) | Unbalanced |
| Security | None | 192-bit PQ |
| Fallback | Fake FORS | Real SPHINCS+ |

## Codebase Structure

```
src/shrincs/           # New production module (in progress)
├── mod.rs             # Module entry, re-exports
├── params.rs          # Level 1/3 parameter definitions
├── types.rs           # Key and signature types
├── error.rs           # Error types
├── api.rs             # Trait definitions (keygen, sign, verify)
└── state.rs           # State management interface

src/shrincs_proto/     # Legacy stubs (deprecated)
├── wots_c.rs          # Toy WOTS+ implementation
├── xmss_unbalanced.rs # Fake Merkle tree
├── fors.rs            # Fake FORS
└── hybrid.rs          # Integration stub
```

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
2. **Fallback Trigger**: Auto-detect corruption? Explicit user request? Leaf exhaustion?
3. **MPC Compatibility**: How to handle N-of-N multisig with stateful scheme?

## References

- [SHRINCS Delving Bitcoin Thread](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158) (Dec 11, 2025)
- [Hash-based Signatures for Bitcoin (ePrint 2025/2203)](https://eprint.iacr.org/2025/2203)
- [XMSS RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
- [SPHINCS+ Specification](https://sphincs.org/)
- [Jonas Nick GitHub](https://github.com/jonasnick)
