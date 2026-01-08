# SHRINCS Internal Security Audit Report

> **Note**: SHRINCS (alg_id 0x30) is now the **sole active** post-quantum signature algorithm in QPB. ML-DSA-65 has been removed.

## Audit Scope

| Field | Value |
|-------|-------|
| **Commit** | `40c4ed202b12098ea22ae771f78e72b5f53ed570` |
| **Date** | 2026-01-05 |
| **Auditor** | Internal (pre-external audit) |
| **Scope** | `src/shrincs/` module |

## Executive Summary

This internal audit reviews the SHRINCS (Stateful Hash-based Signature) implementation for quantum-proof-bitcoin. SHRINCS combines WOTS+C (Winternitz OTS with Counter grinding), PORS+FP (Probabilistic ORS with Fixed Positions), and XMSS^MT (Multi-Tree Extended Merkle Signature Scheme).

### Security Improvements Applied

| ID | Category | Status |
|----|----------|--------|
| SEC-01 | Constant-time verification | **FIXED** (PR #60) |
| SEC-02 | Secret key zeroization | **FIXED** (PR #60) |
| SEC-03 | Cryptographic constants | **VERIFIED** |
| SEC-04 | State management | **VERIFIED** |
| SEC-05 | Edge case handling | **TESTED** |

---

## Findings Summary

| ID | Severity | Component | Status |
|----|----------|-----------|--------|
| SHRINCS-001 | Medium | `wots.rs:verify()` | **FIXED** |
| SHRINCS-002 | Medium | `tree.rs:verify_hypertree()` | **FIXED** |
| SHRINCS-003 | Low | All secret key types | **FIXED** |
| SHRINCS-004 | Info | Parameter verification | **VERIFIED** |
| SHRINCS-005 | Info | `state.rs` state management | **VERIFIED** |

---

## Detailed Findings

### SHRINCS-001: Non-Constant-Time Signature Verification

- **Severity:** Medium
- **Location:** `src/shrincs/wots.rs:verify()`
- **Description:** Original implementation used early-return on chain tip mismatch, leaking timing information about where verification failed.
- **Attack Vector:** An attacker could measure verification time to determine which chain tips match, potentially revealing information about valid signatures.
- **Fix:** Updated to use `subtle::Choice` accumulator with `ct_eq()` for all chain tip comparisons. Verification now runs in constant time regardless of mismatch position.
- **Status:** **FIXED** in PR #60

```rust
// Before (timing leak)
if tip != pk.chain_tips[i] {
    return false;
}

// After (constant-time)
valid &= tip.ct_eq(&pk.chain_tips[i]);
```

### SHRINCS-002: Non-Constant-Time Hypertree Root Comparison

- **Severity:** Medium
- **Location:** `src/shrincs/tree.rs:verify_hypertree()`
- **Description:** Final root comparison used `==` operator, which may short-circuit.
- **Fix:** Updated to use `subtle::ConstantTimeEq::ct_eq()`.
- **Status:** **FIXED** in PR #60

### SHRINCS-003: Secret Keys Not Zeroized on Drop

- **Severity:** Low
- **Location:** All secret key structs
- **Description:** Secret key material was not explicitly cleared from memory when structs were dropped. This could leave secrets recoverable from deallocated memory.
- **Fix:** Added `#[derive(Zeroize, ZeroizeOnDrop)]` to:
  - `ShrincsSecretKey` (`types.rs`)
  - `WotsCSecretKey` (`wots.rs`)
  - `PorsSecretKey` (`pors.rs`)
  - `ShrincsFullSecretKey` (`shrincs.rs`)
- **Status:** **FIXED** in PR #60

### SHRINCS-004: Cryptographic Parameter Verification

- **Severity:** Info
- **Location:** `wots.rs`, `pors.rs`, `tree.rs`, `params.rs`
- **Description:** Verified all cryptographic constants match the Jonas Nick paper (ePrint 2025/2203).
- **Verification Results:**

| Parameter | Paper | Implementation | Match |
|-----------|-------|----------------|-------|
| WOTS+C L1 target_sum | 2040 | 2040 | YES |
| WOTS+C L3 target_sum | 3060 | 3060 | YES |
| PORS+FP k | 10 | 10 | YES |
| PORS+FP a | 14 | 14 | YES |
| PORS+FP mmax | ~120 | 120 | YES |
| Hypertree h | 32 | 32 | YES |
| Hypertree d | 4 | 4 | YES |
| Hypertree h' | 8 | 8 | YES |
| Message digest | H(R‖pk_root‖M‖ctr) | Matches | YES |

- **Status:** **VERIFIED**

### SHRINCS-005: State Management Security

- **Severity:** Info
- **Location:** `src/shrincs/state.rs`
- **Description:** Reviewed state management implementation for concurrent access protection, crash safety, and leaf index monotonicity.
- **Verification Results:**

| Property | Implementation | Verdict |
|----------|----------------|---------|
| File locking | `fs2::FileExt::lock_exclusive()` with RAII `LockGuard` | ✅ SECURE |
| Atomic writes | Write to `.tmp` + `std::fs::rename()` | ✅ SECURE |
| Crash recovery | State persisted before signing (lines 350-360) | ✅ SECURE |
| Version migration | v1→v2 preserves `next_leaf` and `used_leaves` | ✅ SECURE |

**Detailed Analysis:**

1. **Concurrent Access Prevention:**
   - `lock()` (line 387): Blocking exclusive lock using POSIX `flock()`
   - `try_lock()` (line 406): Non-blocking variant returns `None` if held
   - `LockGuard` RAII ensures automatic unlock on drop (even during panics)

2. **Atomic State Persistence:**
   - `save_with_lock()` (line 433): Writes to temp file, then atomic rename
   - On POSIX, `rename()` within same filesystem is atomic
   - No partial state files possible

3. **Leaf Index Safety:**
   - Workflow ensures state saved *before* signing
   - Worst case on crash: leaf "wasted" (marked used but not signed)
   - Never possible to reuse a leaf index
   - `allocate_leaf()` double-checks `used_leaves` HashSet (line 133)

4. **State Format Versioning:**
   - v1 (basic): `next_leaf`, `used_leaves`, `max_leaves`
   - v2 (extended): Adds layer tracking without altering monotonicity fields
   - Both formats preserve critical state invariants

**Minor Observations (non-security):**
- Stale `.tmp` files may remain after mid-write crash (cosmetic issue)
- Test coverage exists: `file_state_manager_locking`, `file_state_manager_atomic_update`

- **Status:** **VERIFIED**

---

## Pending Review Items

### State Management Security (SEC-04) ✅ COMPLETED

- [x] File locking prevents concurrent signature generation
- [x] Atomic rename prevents partial state writes
- [x] Leaf index never reused after crash recovery
- [x] State version migration preserves monotonicity

### Test Coverage Gaps (SEC-05) ✅ COMPLETED

New tests added in `tests/shrincs_stress.rs`:

- [x] `sec05_state_exhaustion_at_boundary` - State exhaustion at exact boundary
- [x] `sec05_state_corruption_recovery` - Corrupted/truncated state rejection
- [x] `sec05_leaf_reuse_prevention` - Double-allocation prevention
- [x] `sec05_force_fallback_blocks_allocation` - Fallback mode blocks allocation
- [x] `sec05_file_manager_concurrent_lock` - Concurrent lock prevention
- [x] `sec05_state_serialization_roundtrip_after_allocations` - State integrity
- [x] `sec05_layer_state_preservation` - V2 layer tracking preservation

**Note:** Counter grinding failure test is not included because counter grinding is designed to always succeed within bounds (the `mmax` parameter limits iterations).

---

## Recommendations for External Audit

1. **Priority Areas:**
   - State management for leaf index monotonicity
   - Counter grinding bounds and DoS resistance
   - Hypertree verification algorithm correctness

2. **Test Vectors:**
   - Generate and document test vectors for interoperability
   - Include edge cases (first/last signatures, tree boundaries)

3. **Formal Verification:**
   - Consider formal verification of constant-time properties
   - Verify counter grinding probability calculations

---

## Changelog

| Date | Change |
|------|--------|
| 2026-01-05 | Initial internal audit; SEC-01, SEC-02, SEC-03 fixed |
| 2026-01-06 | SEC-04 state management review completed; SHRINCS-005 verified |
| 2026-01-06 | SEC-05 edge case tests added; 7 new tests in shrincs_stress.rs |
