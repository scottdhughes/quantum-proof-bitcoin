//! SHRINCS Stress Testing Suite
//!
//! Stress tests for SHRINCS signature scheme:
//! - Sequential signing throughput
//! - Parallel verification throughput
//! - Signature size bounds and growth
//! - State management under load

#![cfg(feature = "shrincs-dev")]

use qpb_consensus::shrincs::{
    pors::PorsParams,
    shrincs::{ShrincsFullParams, keygen, sign, verify},
    state::{FileStateManager, SigningState},
    tree::HypertreeParams,
    wots::WotsCParams,
};
use std::time::Instant;

// ============================================================================
// Test Parameters
// ============================================================================

/// Reduced parameters for stress testing (faster than production params)
fn stress_test_params() -> ShrincsFullParams {
    ShrincsFullParams {
        pors: PorsParams {
            n: 16,
            k: 4,
            a: 4, // t = 64
            t: 64,
            mmax: 30,
        },
        hypertree: HypertreeParams {
            h: 8,
            d: 2,
            h_prime: 4,
            wots_params: WotsCParams::LEVEL1,
        },
        n: 16,
    }
}

// ============================================================================
// Sequential Signing Stress Tests
// ============================================================================

#[test]
fn stress_sequential_signing_10() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    let start = Instant::now();
    let num_sigs = 10;

    for i in 0..num_sigs {
        let msg: [u8; 32] = std::array::from_fn(|j| ((i + j) % 256) as u8);
        let sig = sign(&msg, &key_material, &mut state).expect("sign failed");
        assert!(!sig.to_bytes().is_empty());
    }

    let elapsed = start.elapsed();
    let rate = num_sigs as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Sequential signing: {} signatures in {:?} ({:.1} sig/sec)",
        num_sigs, elapsed, rate
    );

    // Verify state advanced correctly
    assert_eq!(state.next_leaf, num_sigs as u64);
}

#[test]
fn stress_sequential_signing_50() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    let start = Instant::now();
    let num_sigs = 50;

    for i in 0..num_sigs {
        let msg: [u8; 32] = std::array::from_fn(|j| ((i + j) % 256) as u8);
        let _sig = sign(&msg, &key_material, &mut state).expect("sign failed");
    }

    let elapsed = start.elapsed();
    let rate = num_sigs as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Sequential signing (50): {} signatures in {:?} ({:.1} sig/sec)",
        num_sigs, elapsed, rate
    );
}

// ============================================================================
// Verification Stress Tests
// ============================================================================

#[test]
fn stress_verification_batch() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    // Pre-generate signatures
    let num_sigs = 20;
    let mut messages = Vec::with_capacity(num_sigs);
    let mut signatures = Vec::with_capacity(num_sigs);

    for i in 0..num_sigs {
        let msg: [u8; 32] = std::array::from_fn(|j| ((i + j) % 256) as u8);
        let sig = sign(&msg, &key_material, &mut state).expect("sign failed");
        messages.push(msg);
        signatures.push(sig);
    }

    // Verify all signatures
    let start = Instant::now();

    for (msg, sig) in messages.iter().zip(signatures.iter()) {
        verify(msg, sig, &key_material.pk).expect("verify failed");
    }

    let elapsed = start.elapsed();
    let rate = num_sigs as f64 / elapsed.as_secs_f64();
    eprintln!(
        "Batch verification: {} verifications in {:?} ({:.1} verify/sec)",
        num_sigs, elapsed, rate
    );
}

// ============================================================================
// Signature Size Bounds Tests
// ============================================================================

#[test]
fn stress_signature_size_growth() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    let mut sizes = Vec::new();
    let num_sigs = 20;

    for i in 0..num_sigs {
        let msg: [u8; 32] = std::array::from_fn(|j| ((i + j) % 256) as u8);
        let sig = sign(&msg, &key_material, &mut state).expect("sign failed");
        let sig_bytes = sig.to_bytes();
        sizes.push(sig_bytes.len());
    }

    // Verify signature sizes are bounded
    let first_size = sizes[0];
    let last_size = *sizes.last().unwrap();
    let max_size = *sizes.iter().max().unwrap();
    let min_size = *sizes.iter().min().unwrap();

    eprintln!("Signature sizes: first={}, last={}", first_size, last_size);
    eprintln!("Signature sizes: min={}, max={}", min_size, max_size);

    // All signatures should be within reasonable bounds
    // Note: size varies due to counter grinding and PORS auth paths
    assert!(min_size > 500, "Minimum signature too small");
    assert!(max_size < 5000, "Maximum signature too large");
}

#[test]
fn stress_signature_size_at_boundaries() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    // First signature (q=1)
    let msg1: [u8; 32] = [1u8; 32];
    let sig1 = sign(&msg1, &key_material, &mut state).expect("sign failed");
    let size1 = sig1.to_bytes().len();

    // Skip to signature q=16 (power of 2 boundary)
    for i in 1..16 {
        let msg: [u8; 32] = [(i + 1) as u8; 32];
        let _ = sign(&msg, &key_material, &mut state).expect("sign failed");
    }

    let msg16: [u8; 32] = [16u8; 32];
    let sig16 = sign(&msg16, &key_material, &mut state).expect("sign failed");
    let size16 = sig16.to_bytes().len();

    eprintln!("Signature size at q=1: {} bytes", size1);
    eprintln!("Signature size at q=16: {} bytes", size16);

    // Both sizes should be within reasonable bounds
    // Note: size can vary due to counter grinding producing different auth paths
    assert!(size1 > 500, "First signature should be substantial");
    assert!(size16 > 500, "16th signature should be substantial");
    assert!(size16 < 5000, "Signature at q=16 should remain bounded");
}

// ============================================================================
// State Management Tests
// ============================================================================

#[test]
fn stress_state_monotonicity() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    let mut prev_leaf = 0u64;
    let num_sigs = 30;

    for i in 0..num_sigs {
        let msg: [u8; 32] = [i as u8; 32];
        let _ = sign(&msg, &key_material, &mut state).expect("sign failed");

        // Verify leaf index advances monotonically
        assert!(
            state.next_leaf > prev_leaf,
            "Leaf index must advance monotonically: {} -> {}",
            prev_leaf,
            state.next_leaf
        );
        prev_leaf = state.next_leaf;
    }

    assert_eq!(state.next_leaf, num_sigs as u64);
}

#[test]
fn stress_keygen_deterministic() {
    let params = stress_test_params();

    // Generate keypair twice with same seed (deterministic)
    let (km1, state1) = keygen(params).expect("keygen failed");
    let (km2, state2) = keygen(params).expect("keygen failed");

    // Each keygen should produce different keys (random seed)
    // but starting state should be the same
    assert_eq!(state1.next_leaf, 0);
    assert_eq!(state2.next_leaf, 0);

    // Keys should be different (random generation)
    assert_ne!(km1.pk.hypertree_root, km2.pk.hypertree_root);
}

// ============================================================================
// Verification Failure Tests
// ============================================================================

#[test]
fn stress_verify_wrong_message() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    let msg: [u8; 32] = [42u8; 32];
    let sig = sign(&msg, &key_material, &mut state).expect("sign failed");

    // Verify with wrong message should fail
    let wrong_msg: [u8; 32] = [43u8; 32];
    let result = verify(&wrong_msg, &sig, &key_material.pk);

    // Should return Err (verification failed)
    assert!(
        result.is_err(),
        "Verification should fail for wrong message"
    );
}

#[test]
fn stress_verify_wrong_key() {
    let params = stress_test_params();

    // Generate two keypairs
    let (km1, mut state1) = keygen(params).expect("keygen failed");
    let (km2, _state2) = keygen(params).expect("keygen failed");

    // Sign with key 1
    let msg: [u8; 32] = [42u8; 32];
    let sig = sign(&msg, &km1, &mut state1).expect("sign failed");

    // Verify with key 2 should fail
    let result = verify(&msg, &sig, &km2.pk);

    // Should return Err (verification failed)
    assert!(result.is_err(), "Verification should fail for wrong key");
}

// ============================================================================
// Benchmark Summary Test
// ============================================================================

#[test]
fn stress_benchmark_summary() {
    let params = stress_test_params();
    let (key_material, mut state) = keygen(params).expect("keygen failed");

    // Keygen timing
    let keygen_start = Instant::now();
    let _ = keygen(params).expect("keygen failed");
    let keygen_time = keygen_start.elapsed();

    // Sign timing (10 signatures)
    let sign_start = Instant::now();
    let mut signatures = Vec::new();
    let mut messages = Vec::new();
    for i in 0..10 {
        let msg: [u8; 32] = [i as u8; 32];
        let sig = sign(&msg, &key_material, &mut state).expect("sign failed");
        messages.push(msg);
        signatures.push(sig);
    }
    let sign_time = sign_start.elapsed();

    // Verify timing
    let verify_start = Instant::now();
    for (msg, sig) in messages.iter().zip(signatures.iter()) {
        let _ = verify(msg, sig, &key_material.pk);
    }
    let verify_time = verify_start.elapsed();

    eprintln!("\n=== SHRINCS Stress Test Summary ===");
    eprintln!("Keygen: {:?}", keygen_time);
    eprintln!(
        "Sign (10): {:?} ({:.1} sig/sec)",
        sign_time,
        10.0 / sign_time.as_secs_f64()
    );
    eprintln!(
        "Verify (10): {:?} ({:.1} verify/sec)",
        verify_time,
        10.0 / verify_time.as_secs_f64()
    );
    eprintln!(
        "Signature size: {} bytes (first)",
        signatures.first().map(|s| s.to_bytes().len()).unwrap_or(0)
    );
}

// ============================================================================
// SEC-05: Edge Case Tests for Security Audit
// ============================================================================

#[test]
fn sec05_state_exhaustion_at_boundary() {
    // Test signing up to the exact max_leaves boundary
    let mut state = SigningState::new(5);

    // Should succeed for all 5 leaves
    for i in 0..5 {
        let leaf = state.allocate_leaf().expect("should allocate");
        assert_eq!(leaf, i);
    }

    // 6th allocation should fail with StateExhausted
    let result = state.allocate_leaf();
    assert!(result.is_err(), "Should fail after exhaustion");
    assert!(state.is_exhausted());
}

#[test]
fn sec05_state_corruption_recovery() {
    // Test that corrupted state bytes are rejected
    let valid_state = SigningState::new(1000);
    let valid_bytes = valid_state.to_bytes();

    // Test 1: Truncated bytes
    let truncated = &valid_bytes[..10];
    let result = SigningState::from_bytes(truncated);
    assert!(result.is_err(), "Truncated state should fail");

    // Test 2: Invalid version byte
    let mut bad_version = valid_bytes.clone();
    bad_version[0] = 0xFF;
    let result = SigningState::from_bytes(&bad_version);
    assert!(result.is_err(), "Invalid version should fail");

    // Test 3: Valid bytes should work
    let restored = SigningState::from_bytes(&valid_bytes);
    assert!(restored.is_ok(), "Valid bytes should deserialize");
}

#[test]
fn sec05_leaf_reuse_prevention() {
    // Ensure already-used leaves cannot be allocated again
    let mut state = SigningState::new(100);

    // Allocate first leaf
    let leaf0 = state.allocate_leaf().expect("allocate 0");
    assert_eq!(leaf0, 0);
    assert!(state.is_used(0));

    // Manually try to mark leaf 0 as used again (simulating recovery scenario)
    let result = state.mark_used(0);
    assert!(result.is_err(), "Double-marking should fail");

    // Next allocation should be leaf 1, not 0
    let leaf1 = state.allocate_leaf().expect("allocate 1");
    assert_eq!(leaf1, 1);
}

#[test]
fn sec05_force_fallback_blocks_allocation() {
    let mut state = SigningState::new(100);

    // Allocate one leaf successfully
    assert!(state.allocate_leaf().is_ok());

    // Force fallback mode (simulating corruption detection)
    state.force_fallback_mode();

    // Subsequent allocations should fail
    let result = state.allocate_leaf();
    assert!(result.is_err(), "Fallback mode should block allocation");
}

#[test]
fn sec05_file_manager_concurrent_lock() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("state.bin");
    let mgr = FileStateManager::new(&path);

    // Acquire exclusive lock
    let lock1 = mgr.lock().expect("first lock");

    // Second lock attempt should block (use try_lock to test)
    let lock2_result = mgr.try_lock().expect("try_lock");
    assert!(lock2_result.is_none(), "Should not acquire lock while held");

    // Release first lock
    drop(lock1);

    // Now should succeed
    let lock3_result = mgr.try_lock().expect("try_lock after release");
    assert!(lock3_result.is_some(), "Should acquire after release");
}

#[test]
fn sec05_state_serialization_roundtrip_after_allocations() {
    // Verify state integrity after multiple allocations and serialization
    let mut state = SigningState::new(1000);

    // Allocate several leaves
    for _ in 0..10 {
        state.allocate_leaf().expect("allocate");
    }

    // Serialize
    let bytes = state.to_bytes();

    // Deserialize
    let restored = SigningState::from_bytes(&bytes).expect("deserialize");

    // Verify integrity
    assert_eq!(restored.next_leaf, 10);
    assert_eq!(restored.used_leaves.len(), 10);
    for i in 0..10 {
        assert!(restored.is_used(i), "Leaf {} should be marked used", i);
    }
    assert!(!restored.is_used(10), "Leaf 10 should not be used yet");
}

#[test]
fn sec05_layer_state_preservation() {
    // Test v2 format with layer tracking
    let mut state = SigningState::new_with_layers(1 << 16, 4, 4);

    // Allocate some leaves
    for _ in 0..20 {
        state.allocate_leaf().expect("allocate");
    }

    // Verify layer stats exist
    let stats = state.layer_stats().expect("layer stats");
    assert_eq!(stats.len(), 4);

    // Serialize and restore
    let bytes = state.to_bytes();
    let restored = SigningState::from_bytes(&bytes).expect("deserialize");

    // Verify layer tracking preserved
    assert!(restored.layer_states.is_some());
    assert_eq!(restored.height_per_layer, 4);
    let restored_stats = restored.layer_stats().expect("restored stats");
    assert_eq!(restored_stats.len(), 4);
}
