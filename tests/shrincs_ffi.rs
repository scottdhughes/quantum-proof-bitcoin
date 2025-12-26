#![cfg(all(feature = "shrincs-dev", feature = "shrincs-ffi"))]

use qpb_consensus::pq::verify_shrincs_dev;
use std::env;
use std::fs;

// This test is skipped unless SHRINCS_LIB_PATH points to an existing file.
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

    let pk = vec![0u8; 64];
    let sig = vec![0u8; 324];
    let msg = vec![0u8; 32];

    // Should succeed via FFI (stub returns 1 on correct lengths).
    verify_shrincs_dev(&pk, &msg, &sig).expect("ffi verify failed");
}
