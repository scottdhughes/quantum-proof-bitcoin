//! SHRINCS signature roundtrip tests.
//!
//! These tests verify the real SHRINCS implementation (PORS+FP + XMSS^MT)
//! rather than the old deterministic stub.

#![cfg(feature = "shrincs-dev")]

use qpb_consensus::pq::{shrincs_keypair, shrincs_sign, verify_pq, AlgorithmId};

#[test]
fn shrincs_sign_verify_roundtrip() {
    // Generate real SHRINCS keypair
    let (pk_ser, key_material, mut state) = shrincs_keypair().expect("shrincs keygen");

    // Sign a message
    let msg = [0u8; 32];
    let sig_ser = shrincs_sign(&key_material, &mut state, &msg, 0x01).expect("shrincs sign");

    // Remove sighash byte for raw verification
    let sig_raw = &sig_ser[..sig_ser.len() - 1];

    // Verify via verify_pq dispatch (pk_ser[0] is alg_id, rest is pk)
    let pk = &pk_ser[1..];
    verify_pq(AlgorithmId::SHRINCS, pk, &msg, sig_raw).expect("verification should succeed");
}

#[test]
fn shrincs_wrong_message_fails() {
    // Generate keypair
    let (pk_ser, key_material, mut state) = shrincs_keypair().expect("shrincs keygen");

    // Sign original message
    let msg = [0xABu8; 32];
    let sig_ser = shrincs_sign(&key_material, &mut state, &msg, 0x01).expect("shrincs sign");

    // Remove sighash byte
    let sig_raw = &sig_ser[..sig_ser.len() - 1];
    let pk = &pk_ser[1..];

    // Try to verify with different message
    let wrong_msg = [0xCDu8; 32];
    let res = verify_pq(AlgorithmId::SHRINCS, pk, &wrong_msg, sig_raw);
    assert!(res.is_err(), "wrong message should fail verification");
}

#[test]
fn shrincs_state_advances_on_each_sign() {
    // Generate keypair
    let (_pk_ser, key_material, mut state) = shrincs_keypair().expect("shrincs keygen");

    // Get initial state
    let initial_idx = state.next_leaf;

    // Sign 3 messages
    for i in 0..3 {
        let msg = [i as u8; 32];
        shrincs_sign(&key_material, &mut state, &msg, 0x01).expect("shrincs sign");
    }

    // State should have advanced by 3
    let final_idx = state.next_leaf;
    assert_eq!(
        final_idx,
        initial_idx + 3,
        "state should advance by one for each signature"
    );
}
