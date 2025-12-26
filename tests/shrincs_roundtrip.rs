#![cfg(feature = "shrincs-dev")]

use qpb_consensus::pq::{shrincs_keygen, shrincs_sign, verify_shrincs_dev};

#[test]
fn shrincs_sign_verify_roundtrip() {
    let pk = shrincs_keygen();
    let msg = [0u8; 32];
    let sig = shrincs_sign(&pk, &msg);

    // Should pass via FFI if present, otherwise via the stub verifier.
    verify_shrincs_dev(&pk, &msg, &sig).expect("shrincs sign/verify roundtrip must succeed");
}

#[test]
fn shrincs_high_state_index_uses_fallback() {
    let pk = shrincs_keygen();
    let msg = [1u8; 32];
    let mut sig = shrincs_sign(&pk, &msg);

    // Force the stub LMS path to fail (index >= MAX_INDEX in shrincs.c) so SLH fallback is used.
    sig[0] = 0xFF;
    sig[1] = 0xFF;
    sig[2] = 0xFF;
    sig[3] = 0xFF;

    verify_shrincs_dev(&pk, &msg, &sig)
        .expect("shrincs fallback path should accept high state index signature");
}

#[test]
fn shrincs_msg_binding_rejects_tamper() {
    let pk = shrincs_keygen();
    let msg = [2u8; 32];
    let mut sig = shrincs_sign(&pk, &msg);
    // Tamper with message-binding section
    sig[10] ^= 0xFF;
    let res = verify_shrincs_dev(&pk, &msg, &sig);
    assert!(res.is_err(), "tampered sig must be rejected");

    // Tamper with msg32 (mismatch to sig pattern)
    let mut msg_bad = msg;
    msg_bad[5] ^= 0xAA;
    let sig_good = shrincs_sign(&pk, &msg);
    let res = verify_shrincs_dev(&pk, &msg_bad, &sig_good);
    assert!(
        res.is_err(),
        "sig bound to original msg should fail on mutated msg"
    );
}
