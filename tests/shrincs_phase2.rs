//! Phase 2 SHRINCS Integration Tests
//!
//! Tests for the complete SHRINCS implementation including:
//! - PORS+FP (Probabilistic OTS with Fixed Positions)
//! - XMSS^MT hypertree (d=4 layers)
//! - Full sign/verify roundtrip

use qpb_consensus::shrincs::{
    pors::{self, PorsParams},
    shrincs::{self, ShrincsFullParams},
    state::SigningState,
    tree::{HypertreeParams, build_xmss_layer},
    wots::WotsCParams,
};

// ============================================================================
// Test Parameters
// ============================================================================

fn test_params() -> ShrincsFullParams {
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
// PORS+FP Integration Tests
// ============================================================================

#[test]
fn pors_fp_integration() {
    let params = PorsParams {
        n: 16,
        k: 4,
        a: 4, // t = 64
        t: 64,
        mmax: 30,
    };

    let sk_seed = [1u8; 32];
    let pk_seed = [2u8; 32];
    let msg = [3u8; 32];
    let randomness = [4u8; 32];

    // Keygen
    let (sk, pk, tree_levels) = pors::keygen(sk_seed, pk_seed, params);
    assert!(!pk.root.is_empty());

    // Sign
    let sig = pors::sign(&msg, &sk, &tree_levels, &pk.root, &randomness);
    assert!(sig.is_some());

    let sig = sig.unwrap();
    assert_eq!(sig.revealed_leaves.len(), params.k);
    assert!(sig.auth_set.len() <= params.mmax);

    // Verify
    assert!(pors::verify(&msg, &sig, &pk, &pk_seed, &randomness));

    // Wrong message should fail
    let mut bad_msg = msg;
    bad_msg[0] ^= 1;
    assert!(!pors::verify(&bad_msg, &sig, &pk, &pk_seed, &randomness));
}

#[test]
fn pors_octopus_auth_size() {
    // Test that octopus auth produces minimal auth sets
    let params = PorsParams {
        n: 16,
        k: 8, // More leaves = more opportunity for sibling sharing
        a: 6, // t = 512
        t: 512,
        mmax: 50,
    };

    let sk_seed = [1u8; 32];
    let pk_seed = [2u8; 32];
    let msg = [0xCDu8; 32];
    let randomness = [0xEFu8; 32];

    let (sk, pk, tree_levels) = pors::keygen(sk_seed, pk_seed, params);
    let sig = pors::sign(&msg, &sk, &tree_levels, &pk.root, &randomness);
    assert!(sig.is_some());

    let sig = sig.unwrap();
    // Auth set should be significantly smaller than k * height
    let height = params.tree_height();
    let naive_auth_size = params.k * height as usize;
    assert!(
        sig.auth_set.len() < naive_auth_size,
        "Octopus auth {} should be smaller than naive {}",
        sig.auth_set.len(),
        naive_auth_size
    );
}

// ============================================================================
// Full SHRINCS Integration Tests
// ============================================================================

#[test]
fn shrincs_full_keygen() {
    let params = test_params();

    // Keygen with random seeds
    let result = shrincs::keygen(params);
    assert!(result.is_ok(), "Keygen should succeed");

    let (key_material, state) = result.unwrap();
    assert!(!key_material.pk.pors_root.is_empty());
    assert!(!key_material.pk.hypertree_root.is_empty());
    assert_eq!(state.next_leaf, 0);
}

#[test]
fn shrincs_deterministic_keygen() {
    let params = test_params();
    let sk_seed = [1u8; 32];
    let pk_seed = [2u8; 32];
    let prf_key = [3u8; 32];

    // Generate keys twice with same seeds
    let (km1, _) = shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();
    let (km2, _) = shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    // Public keys should be identical
    assert_eq!(
        km1.pk.pors_root, km2.pk.pors_root,
        "PORS roots should match"
    );
    assert_eq!(
        km1.pk.hypertree_root, km2.pk.hypertree_root,
        "Hypertree roots should match"
    );
}

#[test]
fn shrincs_full_sign_verify() {
    let params = test_params();
    let sk_seed = [1u8; 32];
    let pk_seed = [2u8; 32];
    let prf_key = [3u8; 32];

    let (key_material, mut state) =
        shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    // Sign a message
    let msg = [0xABu8; 32];
    let sig = shrincs::sign(&msg, &key_material, &mut state);
    assert!(sig.is_ok(), "Sign should succeed");

    let sig = sig.unwrap();

    // Verify the signature
    let result = shrincs::verify(&msg, &sig, &key_material.pk);
    assert!(result.is_ok(), "Verify should succeed");
}

#[test]
fn shrincs_multiple_signatures() {
    let params = test_params();
    let sk_seed = [10u8; 32];
    let pk_seed = [20u8; 32];
    let prf_key = [30u8; 32];

    let (key_material, mut state) =
        shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    // Sign multiple messages
    for i in 0..5 {
        let msg: [u8; 32] = (0..32)
            .map(|j| (i as u8).wrapping_add(j as u8))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let sig = shrincs::sign(&msg, &key_material, &mut state);
        assert!(sig.is_ok(), "Sign #{} should succeed", i);

        let sig = sig.unwrap();
        assert!(shrincs::verify(&msg, &sig, &key_material.pk).is_ok());
    }

    // State should have advanced
    assert_eq!(state.next_leaf, 5);
}

#[test]
fn shrincs_wrong_message_fails() {
    let params = test_params();
    let sk_seed = [5u8; 32];
    let pk_seed = [6u8; 32];
    let prf_key = [7u8; 32];

    let (key_material, mut state) =
        shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    let msg = [0xAAu8; 32];
    let sig = shrincs::sign(&msg, &key_material, &mut state).unwrap();

    // Correct message verifies
    assert!(shrincs::verify(&msg, &sig, &key_material.pk).is_ok());

    // Tampered message fails
    let mut bad_msg = msg;
    bad_msg[15] ^= 0xFF;
    assert!(shrincs::verify(&bad_msg, &sig, &key_material.pk).is_err());
}

#[test]
fn shrincs_state_progression() {
    let params = test_params();
    let sk_seed = [11u8; 32];
    let pk_seed = [22u8; 32];
    let prf_key = [33u8; 32];

    let (key_material, mut state) =
        shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    // Initial state should be at leaf 0
    assert_eq!(state.next_leaf, 0);

    // Sign messages and verify state advances
    for i in 0..5 {
        let msg = [i as u8; 32];
        let sig = shrincs::sign(&msg, &key_material, &mut state);
        assert!(sig.is_ok());
        assert_eq!(state.next_leaf, i + 1, "State should advance after signing");
    }
}

// ============================================================================
// State Persistence Tests
// ============================================================================

#[test]
fn state_v2_roundtrip() {
    let mut state = SigningState::new_with_layers(1 << 16, 4, 4);

    // Allocate some leaves
    for _ in 0..100 {
        state.allocate_leaf().unwrap();
    }

    // Serialize
    let bytes = state.to_bytes();
    assert_eq!(bytes[0], 0x02, "Should be v2 format");

    // Deserialize
    let restored = SigningState::from_bytes(&bytes).unwrap();
    assert_eq!(restored.next_leaf, 100);
    assert!(restored.layer_states.is_some());
    assert_eq!(restored.layer_states.as_ref().unwrap().len(), 4);

    // Layer stats should reflect allocations
    let stats = restored.layer_stats().unwrap();
    assert_eq!(stats[0].1, 100, "Layer 0 should have 100 signatures");
}

#[test]
fn state_backward_compatibility() {
    // V1 format (no layers)
    let state_v1 = SigningState::new(1000);
    let bytes_v1 = state_v1.to_bytes();

    // Should deserialize correctly
    let restored = SigningState::from_bytes(&bytes_v1).unwrap();
    assert!(restored.layer_states.is_none());
    assert_eq!(restored.height_per_layer, 8); // Default
}

// ============================================================================
// Hypertree Structure Tests
// ============================================================================

#[test]
fn hypertree_layer_build() {
    let params = HypertreeParams {
        h: 8,
        d: 2,
        h_prime: 4,
        wots_params: WotsCParams::LEVEL1,
    };

    let sk_seed = [1u8; 32];
    let pk_seed = [2u8; 32];

    let layer = build_xmss_layer(&sk_seed, &pk_seed, 0, 0, &params);
    assert!(!layer.root.is_empty());
    assert_eq!(layer.root.len(), params.wots_params.n);
}

#[test]
fn hypertree_params_consistency() {
    let params = HypertreeParams {
        h: 32,
        d: 4,
        h_prime: 8,
        wots_params: WotsCParams::LEVEL1,
    };

    assert_eq!(params.max_signatures(), 1u64 << 32);
}

// ============================================================================
// Signature Size Tests
// ============================================================================

#[test]
fn signature_size_bounds() {
    let params = test_params();
    let sk_seed = [1u8; 32];
    let pk_seed = [2u8; 32];
    let prf_key = [3u8; 32];

    let (key_material, mut state) =
        shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    let msg = [0u8; 32];
    let sig = shrincs::sign(&msg, &key_material, &mut state).unwrap();

    // Serialize and check size
    let bytes = sig.to_bytes();

    // Signature should be less than 10KB for test params
    assert!(
        bytes.len() < 10_000,
        "Signature too large: {} bytes",
        bytes.len()
    );

    // Should deserialize correctly
    let parsed = shrincs::ShrincsFullSignature::from_bytes(&bytes, params);
    assert!(parsed.is_some(), "Signature should parse");
}

#[test]
fn signature_serialization_roundtrip() {
    let params = test_params();
    let sk_seed = [42u8; 32];
    let pk_seed = [43u8; 32];
    let prf_key = [44u8; 32];

    let (key_material, mut state) =
        shrincs::keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

    let msg = [0x55u8; 32];
    let sig = shrincs::sign(&msg, &key_material, &mut state).unwrap();

    // Serialize
    let bytes = sig.to_bytes();

    // Deserialize
    let parsed = shrincs::ShrincsFullSignature::from_bytes(&bytes, params).unwrap();

    // Verify both signatures produce same result
    assert!(shrincs::verify(&msg, &sig, &key_material.pk).is_ok());
    assert!(shrincs::verify(&msg, &parsed, &key_material.pk).is_ok());
}
