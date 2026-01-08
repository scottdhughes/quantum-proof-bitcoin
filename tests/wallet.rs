use pqcrypto_dilithium::dilithium3::{detached_sign, keypair, verify_detached_signature};

#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn mldsa_sign_verify_smoke() {
    let msg = [0u8; 32];
    let (pk, sk) = keypair();
    let sig = detached_sign(&msg, &sk);
    verify_detached_signature(&sig, &msg, &pk).expect("verify");
}
