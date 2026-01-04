//! SHRINCS FFI test - for external C library integration.
//!
//! This test requires both shrincs-dev and shrincs-ffi features.
//! It validates that an external SHRINCS C library (e.g., Jonas Nick's
//! reference implementation) can be loaded and used for verification.

#![cfg(all(feature = "shrincs-dev", feature = "shrincs-ffi"))]

use qpb_consensus::pq::{shrincs_keypair, shrincs_sign, verify_pq, AlgorithmId};
use std::env;
use std::fs;

/// Test that FFI library can be loaded and used for verification.
///
/// This test is skipped unless SHRINCS_LIB_PATH points to an existing file.
/// The FFI path is intended for Jonas Nick's reference C implementation.
#[test]
fn shrincs_ffi_loads_and_verifies() {
    let path = match env::var("SHRINCS_LIB_PATH") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("SHRINCS_LIB_PATH not set; skipping shrincs_ffi test");
            return;
        }
    };
    if fs::metadata(&path).is_err() {
        eprintln!("SHRINCS_LIB_PATH not found; skipping shrincs_ffi test");
        return;
    }

    // Generate real keypair and signature for FFI verification
    let (pk_ser, key_material, mut state) = shrincs_keypair().expect("shrincs keygen");
    let msg = [0xFFu8; 32];
    let sig_ser = shrincs_sign(&key_material, &mut state, &msg, 0x01).expect("shrincs sign");

    // Remove sighash byte
    let sig_raw = &sig_ser[..sig_ser.len() - 1];
    let pk = &pk_ser[1..];

    // Verify through the verify_pq dispatch (which may use FFI if available)
    verify_pq(AlgorithmId::SHRINCS, pk, &msg, sig_raw).expect("FFI verify failed");
}
