//! Miri-only smoke coverage for the exact portable libcrux ML-DSA-44 crate.

use libcrux_ml_dsa::ml_dsa_44::{portable, MLDSA44Signature};

const MESSAGE: &[u8] = b"PQBTC libcrux portable Miri smoke";
const CONTEXT: &[u8] = b"PQBTC/tx-signature/v1";

fn fill_increasing(target: &mut [u8]) {
    for (index, value) in target.iter_mut().enumerate() {
        *value = (index + 1) as u8;
    }
}

fn main() {
    let key_pair = portable::generate_key_pair([0x42; 32]);
    let signature = portable::sign(&key_pair.signing_key, MESSAGE, CONTEXT, [0x24; 32])
        .expect("fixed ML-DSA-44 signing input must succeed");
    portable::verify(&key_pair.verification_key, MESSAGE, CONTEXT, &signature)
        .expect("fresh portable signature must verify");

    let mut bit_flipped = signature.clone();
    bit_flipped.as_mut_slice()[0] ^= 1;
    assert!(
        portable::verify(&key_pair.verification_key, MESSAGE, CONTEXT, &bit_flipped,).is_err(),
        "commitment-hash mutation must be rejected",
    );

    let mut malformed_hint = MLDSA44Signature::zero();
    let hint_offset = 32 + 4 * 576;
    fill_increasing(&mut malformed_hint.as_mut_slice()[hint_offset..hint_offset + 21]);
    fill_increasing(&mut malformed_hint.as_mut_slice()[hint_offset + 21..hint_offset + 42]);
    fill_increasing(&mut malformed_hint.as_mut_slice()[hint_offset + 42..hint_offset + 63]);
    fill_increasing(&mut malformed_hint.as_mut_slice()[hint_offset + 63..hint_offset + 80]);
    malformed_hint.as_mut_slice()[hint_offset + 80..hint_offset + 84]
        .copy_from_slice(&[21, 42, 63, 85]);
    assert!(
        portable::verify(
            &key_pair.verification_key,
            MESSAGE,
            CONTEXT,
            &malformed_hint,
        )
        .is_err(),
        "out-of-bounds final hint counter must be rejected without panic",
    );
}
