// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use libcrux_ml_dsa::ml_dsa_44::{
    portable, MLDSA44Signature, MLDSA44SigningKey, MLDSA44VerificationKey,
};
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;
use std::time::Instant;

const KEYGEN_SEED_SIZE: usize = 32;
const PRIVATE_KEY_SIZE: usize = 2560;
const PUBLIC_KEY_SIZE: usize = 1312;
const RANDOMIZER_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 2420;

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex input has odd length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "hex input is not ASCII")?;
            u8::from_str_radix(text, 16).map_err(|_| "hex input contains a non-hex digit")
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(str::to_owned)
}

fn decode_array<const SIZE: usize>(value: &str, label: &str) -> Result<[u8; SIZE], String> {
    let decoded = decode_hex(value)?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} must be {SIZE} bytes"))
}

fn print_hex(name: &str, value: &[u8]) {
    print!("{name}=");
    for byte in value {
        print!("{byte:02x}");
    }
    println!();
}

fn randomizer() -> Result<[u8; RANDOMIZER_SIZE], String> {
    let mut output = [0u8; RANDOMIZER_SIZE];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut output))
        .map_err(|error| format!("randomizer generation failed: {error}"))?;
    Ok(output)
}

fn run_keygen(seed_hex: &str) -> Result<(), String> {
    let seed = decode_array::<KEYGEN_SEED_SIZE>(seed_hex, "key-generation seed")?;
    let started = Instant::now();
    let key_pair = portable::generate_key_pair(seed);
    let keygen_ns = started.elapsed().as_nanos();

    print_hex("pk", key_pair.verification_key.as_ref());
    print_hex("sk", key_pair.signing_key.as_ref());
    println!("keygen_ns={keygen_ns}");
    Ok(())
}

fn run_sign(
    private_key_hex: &str,
    message_hex: &str,
    context_hex: &str,
    public_key_hex: &str,
    fixed_randomizer_hex: Option<&str>,
    randomized: bool,
) -> Result<(), String> {
    let private_key = MLDSA44SigningKey::new(decode_array::<PRIVATE_KEY_SIZE>(
        private_key_hex,
        "private key",
    )?);
    let public_key = MLDSA44VerificationKey::new(decode_array::<PUBLIC_KEY_SIZE>(
        public_key_hex,
        "public key",
    )?);
    let message = decode_hex(message_hex)?;
    let context = decode_hex(context_hex)?;
    if context.len() > 255 {
        return Err("context must not exceed 255 bytes".to_owned());
    }
    let signing_randomizer = match (fixed_randomizer_hex, randomized) {
        (Some(_), true) => return Err("fixed and random signing modes conflict".to_owned()),
        (Some(value), false) => decode_array::<RANDOMIZER_SIZE>(value, "randomizer")?,
        (None, true) => randomizer()?,
        (None, false) => [0u8; RANDOMIZER_SIZE],
    };

    let sign_started = Instant::now();
    let signature = portable::sign(&private_key, &message, &context, signing_randomizer)
        .map_err(|error| format!("signing failed: {error:?}"))?;
    let sign_ns = sign_started.elapsed().as_nanos();
    let verify_started = Instant::now();
    portable::verify(&public_key, &message, &context, &signature)
        .map_err(|error| format!("generated signature did not verify: {error:?}"))?;
    let verify_ns = verify_started.elapsed().as_nanos();

    print_hex("signature", signature.as_ref());
    println!("verified=1");
    println!("sign_ns={sign_ns}");
    println!("verify_ns={verify_ns}");
    Ok(())
}

fn run_verify(
    public_key_hex: &str,
    message_hex: &str,
    context_hex: &str,
    signature_hex: &str,
) -> Result<(), String> {
    let public_key = MLDSA44VerificationKey::new(decode_array::<PUBLIC_KEY_SIZE>(
        public_key_hex,
        "public key",
    )?);
    let message = decode_hex(message_hex)?;
    let context = decode_hex(context_hex)?;
    if context.len() > 255 {
        return Err("context must not exceed 255 bytes".to_owned());
    }
    let signature_bytes = decode_hex(signature_hex)?;
    if signature_bytes.len() != SIGNATURE_SIZE {
        println!("verified=0");
        println!("verify_ns=0");
        return Ok(());
    }
    let signature = MLDSA44Signature::new(
        signature_bytes
            .try_into()
            .map_err(|_| "signature must be 2420 bytes")?,
    );

    let verify_started = Instant::now();
    let verified = portable::verify(&public_key, &message, &context, &signature).is_ok();
    let verify_ns = verify_started.elapsed().as_nanos();
    println!("verified={}", u8::from(verified));
    println!("verify_ns={verify_ns}");
    Ok(())
}

fn usage(program: &str) {
    eprintln!("usage: {program} keygen <seed-hex>");
    eprintln!("       {program} sign <sk-hex> <message-hex> <context-hex> <pk-hex>");
    eprintln!("       {program} sign-randomized <sk-hex> <message-hex> <context-hex> <pk-hex>");
    eprintln!(
        "       {program} sign-with-randomizer <sk-hex> <message-hex> <context-hex> <randomizer-hex> <pk-hex>"
    );
    eprintln!("       {program} verify <pk-hex> <message-hex> <context-hex> <signature-hex>");
}

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().collect();
    let result = match arguments.as_slice() {
        [_, command, seed] if command == "keygen" => run_keygen(seed),
        [_, command, private_key, message, context, public_key] if command == "sign" => {
            run_sign(private_key, message, context, public_key, None, false)
        }
        [_, command, private_key, message, context, public_key] if command == "sign-randomized" => {
            run_sign(private_key, message, context, public_key, None, true)
        }
        [_, command, private_key, message, context, randomizer, public_key]
            if command == "sign-with-randomizer" =>
        {
            run_sign(
                private_key,
                message,
                context,
                public_key,
                Some(randomizer),
                false,
            )
        }
        [_, command, public_key, message, context, signature] if command == "verify" => {
            run_verify(public_key, message, context, signature)
        }
        _ => {
            usage(arguments.first().map_or("libcrux_oracle", String::as_str));
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("libcrux_oracle: {error}");
            ExitCode::FAILURE
        }
    }
}
