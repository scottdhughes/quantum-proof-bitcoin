//! Wallet signature smoke tests.
//!
//! Requires the `shrincs-dev` feature for SHRINCS signing functionality.

#[cfg(feature = "shrincs-dev")]
use qpb_consensus::pq::{AlgorithmId, shrincs_keypair, shrincs_sign, verify_pq};

#[test]
#[cfg(feature = "shrincs-dev")]
fn shrincs_sign_verify_smoke() {
    let msg = [0u8; 32];

    // Generate SHRINCS keypair
    let (pk_ser, key_material, mut signing_state) =
        shrincs_keypair().expect("SHRINCS keygen failed");

    // Sign the message
    let sig =
        shrincs_sign(&key_material, &mut signing_state, &msg, 0x01).expect("SHRINCS sign failed");

    // Extract pk without algorithm prefix and sig without sighash byte
    let pk_bytes = &pk_ser[1..];
    let sig_for_verify = &sig[..sig.len() - 1];

    // Verify the signature
    verify_pq(AlgorithmId::SHRINCS, pk_bytes, &msg, sig_for_verify).expect("SHRINCS verify failed");
}

#[test]
#[cfg(not(feature = "shrincs-dev"))]
fn shrincs_smoke_requires_feature() {
    // This test just ensures the test file compiles without shrincs-dev
    // The actual signature tests require the feature
}
