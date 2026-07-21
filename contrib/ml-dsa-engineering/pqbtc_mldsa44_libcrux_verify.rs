// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

use libcrux_ml_dsa::ml_dsa_44::{portable, MLDSA44Signature, MLDSA44VerificationKey};
use std::slice;

const ORACLE_REJECT: i32 = 0;
const ORACLE_ACCEPT: i32 = 1;
const PUBLIC_KEY_SIZE: usize = 1312;
const SIGNATURE_SIZE: usize = 2420;
const MAX_CONTEXT_SIZE: usize = 255;

unsafe fn byte_slice<'a>(value: *const u8, size: usize) -> Option<&'a [u8]> {
    if size == 0 {
        Some(&[])
    } else if value.is_null() {
        None
    } else {
        Some(unsafe { slice::from_raw_parts(value, size) })
    }
}

/// Return a normalized accept/reject result for one binary ML-DSA-44 tuple.
///
/// # Safety
///
/// Every non-null pointer must remain readable for its associated size for the
/// duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqbtc_mldsa44_libcrux_verify(
    signature: *const u8,
    signature_size: usize,
    public_key: *const u8,
    public_key_size: usize,
    message: *const u8,
    message_size: usize,
    context: *const u8,
    context_size: usize,
) -> i32 {
    if signature.is_null()
        || signature_size != SIGNATURE_SIZE
        || public_key.is_null()
        || public_key_size != PUBLIC_KEY_SIZE
        || (message.is_null() && message_size != 0)
        || (context.is_null() && context_size != 0)
        || context_size > MAX_CONTEXT_SIZE
    {
        return ORACLE_REJECT;
    }

    let signature = match unsafe { byte_slice(signature, signature_size) }
        .and_then(|value| <[u8; SIGNATURE_SIZE]>::try_from(value).ok())
    {
        Some(value) => MLDSA44Signature::new(value),
        None => return ORACLE_REJECT,
    };
    let public_key = match unsafe { byte_slice(public_key, public_key_size) }
        .and_then(|value| <[u8; PUBLIC_KEY_SIZE]>::try_from(value).ok())
    {
        Some(value) => MLDSA44VerificationKey::new(value),
        None => return ORACLE_REJECT,
    };
    let message = match unsafe { byte_slice(message, message_size) } {
        Some(value) => value,
        None => return ORACLE_REJECT,
    };
    let context = match unsafe { byte_slice(context, context_size) } {
        Some(value) => value,
        None => return ORACLE_REJECT,
    };

    if portable::verify(&public_key, message, context, &signature).is_ok() {
        ORACLE_ACCEPT
    } else {
        ORACLE_REJECT
    }
}
