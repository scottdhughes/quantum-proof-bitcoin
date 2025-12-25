use qpb_consensus::pq::{AlgorithmId, shrincs_keygen, shrincs_sign, verify_pq};

#[test]
fn shrincs_sign_verify_roundtrip() {
    let pk = shrincs_keygen();
    let msg = [0u8; 32];
    let sig = shrincs_sign(&pk, &msg);

    // Should pass via FFI if present, otherwise via the stub verifier.
    verify_pq(AlgorithmId::Shrincs, &pk, &msg, &sig)
        .expect("shrincs sign/verify roundtrip must succeed");
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

    verify_pq(AlgorithmId::Shrincs, &pk, &msg, &sig)
        .expect("shrincs fallback path should accept high state index signature");
}
