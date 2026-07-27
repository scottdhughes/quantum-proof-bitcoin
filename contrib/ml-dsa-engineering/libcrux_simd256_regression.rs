// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

use libcrux_ml_dsa::ml_dsa_44::{avx2, portable, MLDSA44Signature, MLDSA44VerificationKey};
use std::env;
use std::process::ExitCode;

const PUBLIC_KEY_SIZE: usize = 1312;
const SIGNATURE_SIZE: usize = 2420;
const MAX_MESSAGE_SIZE: usize = 8192;
const MAX_CONTEXT_SIZE: usize = 255;

fn decode_hex(value: &str, maximum_size: usize, label: &str) -> Result<Vec<u8>, String> {
    if value.len() > maximum_size * 2 {
        return Err(format!("{label} exceeds {maximum_size} bytes"));
    }
    if !value.len().is_multiple_of(2) {
        return Err(format!("{label} hex input has odd length"));
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| format!("{label} is not ASCII hex"))?;
        decoded.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| format!("{label} contains a non-hex digit"))?,
        );
    }
    Ok(decoded)
}

fn decode_array<const SIZE: usize>(value: &str, label: &str) -> Result<[u8; SIZE], String> {
    decode_hex(value, SIZE, label)?
        .try_into()
        .map_err(|_| format!("{label} must be exactly {SIZE} bytes"))
}

fn verify_case(
    public_key: &MLDSA44VerificationKey,
    message: &[u8],
    context: &[u8],
    signature_hex: &str,
    expected_valid: bool,
    test_case_id: u16,
) -> Result<(), String> {
    let signature =
        MLDSA44Signature::new(decode_array::<SIGNATURE_SIZE>(signature_hex, "signature")?);
    let portable_valid = portable::verify(public_key, message, context, &signature).is_ok();
    let avx2_valid = avx2::verify(public_key, message, context, &signature).is_ok();

    if portable_valid != expected_valid {
        return Err(format!(
            "tcId {test_case_id} portable result drifted: expected {expected_valid}, got {portable_valid}"
        ));
    }
    if avx2_valid != expected_valid {
        return Err(format!(
            "tcId {test_case_id} AVX2 result drifted: expected {expected_valid}, got {avx2_valid}"
        ));
    }
    if portable_valid != avx2_valid {
        return Err(format!(
            "tcId {test_case_id} portable and AVX2 results disagree"
        ));
    }

    println!(
        "tcId={test_case_id} portable={} avx2={} expected={}",
        u8::from(portable_valid),
        u8::from(avx2_valid),
        u8::from(expected_valid),
    );
    Ok(())
}

fn run(arguments: &[String]) -> Result<(), String> {
    if !std::is_x86_feature_detected!("avx2") {
        return Err("AVX2 is unavailable at runtime".to_owned());
    }
    let [public_key_hex, message_hex, context_hex, valid_signature_hex, invalid_signature_hex] =
        arguments
    else {
        return Err(
            "expected exactly: <pk-hex> <message-hex> <context-hex> <tc147-sig-hex> <tc148-sig-hex>"
                .to_owned(),
        );
    };

    let public_key = MLDSA44VerificationKey::new(decode_array::<PUBLIC_KEY_SIZE>(
        public_key_hex,
        "public key",
    )?);
    let message = decode_hex(message_hex, MAX_MESSAGE_SIZE, "message")?;
    let context = decode_hex(context_hex, MAX_CONTEXT_SIZE, "context")?;

    verify_case(
        &public_key,
        &message,
        &context,
        valid_signature_hex,
        true,
        147,
    )?;
    verify_case(
        &public_key,
        &message,
        &context,
        invalid_signature_hex,
        false,
        148,
    )?;
    Ok(())
}

fn main() -> ExitCode {
    let mut raw_arguments = env::args_os();
    let _program = raw_arguments.next();
    let mut arguments = Vec::with_capacity(6);
    for argument in raw_arguments.by_ref().take(6) {
        match argument.into_string() {
            Ok(value) => arguments.push(value),
            Err(_) => {
                eprintln!("libcrux SIMD256 regression arguments must be UTF-8");
                return ExitCode::FAILURE;
            }
        }
    }
    if arguments.len() > 5 || raw_arguments.next().is_some() {
        eprintln!("libcrux SIMD256 regression received too many arguments");
        return ExitCode::from(2);
    }

    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("libcrux SIMD256 regression: {error}");
            ExitCode::FAILURE
        }
    }
}
