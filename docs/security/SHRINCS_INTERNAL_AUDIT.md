# SHRINCS Internal Security Audit Report

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
| SEC-04 | State management | Pending review |
| SEC-05 | Edge case handling | Pending tests |

---

## Findings Summary

| ID | Severity | Component | Status |
|----|----------|-----------|--------|
| SHRINCS-001 | Medium | `wots.rs:verify()` | **FIXED** |
| SHRINCS-002 | Medium | `tree.rs:verify_hypertree()` | **FIXED** |
| SHRINCS-003 | Low | All secret key types | **FIXED** |
| SHRINCS-004 | Info | Parameter verification | **VERIFIED** |

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

---

## Pending Review Items

### State Management Security (SEC-04)

- [ ] File locking prevents concurrent signature generation
- [ ] Atomic rename prevents partial state writes
- [ ] Leaf index never reused after crash recovery
- [ ] State version migration preserves monotonicity

### Test Coverage Gaps (SEC-05)

- [ ] Counter grinding failure (max_attempts exceeded)
- [ ] State corruption recovery
- [ ] Concurrent signing attempts (should fail with lock)
- [ ] Signature size bounds at edge cases (q=1, q=max)

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
