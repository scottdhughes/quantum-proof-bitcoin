# SHRINCS: Stateful Hash-based Signatures for QPB

## Overview

SHRINCS is a **hybrid stateful + stateless** post-quantum signature scheme designed for Bitcoin by Jonas Nick (Blockstream Research). It combines:

- **Stateful path**: Unbalanced XMSS tree with WOTS+C one-time signatures (small, efficient)
- **Stateless fallback**: SPHINCS+ variant for emergency recovery (larger, unlimited)

## Status

| Aspect | Status |
|--------|--------|
| **Consensus** | **ACTIVE** (alg_id 0x30) — sole post-quantum algorithm |
| **Implementation** | All phases complete (full consensus integration) |
| **Security Level** | NIST Level 1 (128-bit) |
| **Networks** | Active on Devnet, Testnet, Mainnet |

## Implementation Status

### Completed Phases

| Phase | Components | Status |
|-------|------------|--------|
| **Phase 1** | WOTS+C (counter grinding), basic XMSS tree | ✅ Complete |
| **Phase 2** | PORS+FP (octopus auth), XMSS^MT hypertree | ✅ Complete |
| **Phase 3** | SPHINCS+-128s fallback, unified signature type | ✅ Complete |
| **Phase 4** | Consensus integration, AlgorithmId 0x30 wiring | ✅ Complete |
| **Phase 5** | Fallback witness format, state persistence | ✅ Complete |

### Phase 4 Details

- `AlgorithmId::SHRINCS` variant (feature-gated)
- `verify_shrincs()` dispatch in `verify_pq()`
- `shrincs_keypair()` and `shrincs_sign()` wrapper functions
- PQSigCheck cost: 2 units (vs ML-DSA-65's 1 unit)
- P2QPKH integration test passing

### Phase 5 Details

- Extended pk format: `[alg_id(1) || base_pk(64) || sphincs_pk(32)]` = 97 bytes
- Signature type prefix: 0x00 stateful, 0x01 fallback
- P2QPKH validation handles variable pk length via `validation.rs`
- `FileStateManager` with atomic writes and cross-platform file locking
- `shrincs_keypair_with_fallback()` and `shrincs_sign_fallback()` wrappers

### Known Limitations

1. **Wallet import**: `dumpwallet`/`importwallet` do not export signing state (see README.md)
2. **MPC compatibility**: Multi-party signing with stateful schemes is an open research area

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

## Current Implementation

| Aspect | Value |
|--------|-------|
| PK size | 16 bytes (composite hash) |
| Stateful sig | ~308-340 bytes |
| Fallback sig | ~7,856 bytes (SPHINCS+-128s) |
| WOTS w | 256 |
| n (hash size) | 16 bytes |
| Chains | 16 |
| Tree | XMSS^MT hypertree |
| Security | NIST Level 1 (128-bit PQ) |
| Fallback | SPHINCS+-SHA2-128s |
| Consensus | **Active on all networks** |
| State | File-based + atomic + locking |

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

## Consensus Integration

SHRINCS is fully integrated as the sole post-quantum signature algorithm:

1. ✅ `src/pq.rs`: `AlgorithmId::SHRINCS` only (0x11 ML-DSA removed)
2. ✅ `src/shrincs/params.rs`: Level 1 parameters (n=16, 16 chains)
3. ✅ `src/shrincs/types.rs`: 16-byte composite public key
4. ✅ Active on all networks (Devnet, Testnet, Mainnet)
5. ✅ Full test suite passing (128 unit + ~180 integration tests)

## Open Research Areas

1. **MPC Compatibility**: How to handle N-of-N multisig with stateful scheme?
2. **Hardware wallet support**: State management in constrained environments
3. **Stateful key export**: Export signing state with keys for wallet migration

## References

- [SHRINCS Delving Bitcoin Thread](https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158) (Dec 11, 2025)
- [Hash-based Signatures for Bitcoin (ePrint 2025/2203)](https://eprint.iacr.org/2025/2203)
- [XMSS RFC 8391](https://datatracker.ietf.org/doc/html/rfc8391)
- [SPHINCS+ Specification](https://sphincs.org/)
- [Jonas Nick GitHub](https://github.com/jonasnick)
