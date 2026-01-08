//! Test vector generation for SHRINCS signatures.
//!
//! Requires the `shrincs-dev` feature for signing functionality.

use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

use hex::encode as hex_encode;
use qpb_consensus::{
    OutPoint, Prevout, Transaction, TxIn, TxOut, build_p2qpkh, build_p2qtsh, qpb_sighash, qpkh32,
    qtap_leaf_hash, qtap_reconstruct_root,
};
use serde_json::json;

#[cfg(feature = "shrincs-dev")]
use qpb_consensus::pq::{shrincs_keypair, shrincs_sign};

/// SHRINCS algorithm ID (used for documentation/reference)
#[allow(dead_code)]
const SHRINCS_ALG_ID: u8 = 0x30;

fn write_vec(name: &str, value: serde_json::Value) {
    let dir = Path::new("vectors");
    create_dir_all(dir).expect("create vectors dir");
    let path = dir.join(name);
    let mut f = File::create(&path).expect("create vector file");
    let s = serde_json::to_string_pretty(&value).expect("serialize json");
    f.write_all(s.as_bytes()).expect("write json");
    println!("Wrote {}", path.display());
}

#[cfg(feature = "shrincs-dev")]
fn p2qpkh_vectors() {
    // Generate SHRINCS keypair
    let (pk_ser, key_material, mut signing_state) =
        shrincs_keypair().expect("SHRINCS keygen failed");

    let prevout = OutPoint {
        txid: [1u8; 32],
        vout: 0,
    };
    let spk = build_p2qpkh(qpkh32(&pk_ser));
    let prevouts = vec![Prevout::regular(50_0000_0000, spk.clone())];

    let base_tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout,
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1_0000,
            script_pubkey: spk.clone(),
        }],
        lock_time: 0,
    };

    let sighash_type = 0x01u8;
    let msg = qpb_sighash(&base_tx, 0, &prevouts, sighash_type, 0x00, None).unwrap();
    let msg_hex = hex_encode(&msg);

    // Sign with SHRINCS (signature includes type prefix, full_pk, sig_data, and sighash byte)
    let sig = shrincs_sign(&key_material, &mut signing_state, &msg, sighash_type)
        .expect("SHRINCS sign failed");

    let mut tx_valid = base_tx.clone();
    tx_valid.vin[0].witness = vec![sig.clone(), pk_ser.clone()];
    let tx_hex = hex_encode(tx_valid.serialize(true));

    let valid = json!({
        "description": "P2QPKH valid spend (SHRINCS)",
        "algorithm": "SHRINCS",
        "tx_hex": tx_hex,
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {
            "valid": true,
            "msg32_hex": msg_hex,
        },
        "pk_ser_hex": hex_encode(&pk_ser),
        "sig_size_bytes": sig.len(),
    });
    write_vec("p2qpkh_valid_shrincs.json", valid);

    // Invalid sig: flip one byte in sig body (not type prefix or pk)
    let mut sig_bad = sig.clone();
    if sig_bad.len() > 70 {
        sig_bad[70] ^= 0x01; // Flip a byte in the signature data
    }
    let mut tx_bad = base_tx.clone();
    tx_bad.vin[0].witness = vec![sig_bad, pk_ser.clone()];
    let bad = json!({
        "description": "P2QPKH invalid signature (tampered byte, SHRINCS)",
        "algorithm": "SHRINCS",
        "tx_hex": hex_encode(tx_bad.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {
            "valid": false,
            "msg32_hex": msg_hex,
        }
    });
    write_vec("p2qpkh_invalid_sig_shrincs.json", bad);

    // Invalid pk_ser length (truncate)
    let mut bad_pk_len = pk_ser.clone();
    bad_pk_len.truncate(10);
    let mut tx_bad_len = base_tx.clone();
    tx_bad_len.vin[0].witness = vec![sig.clone(), bad_pk_len];
    let bad_len = json!({
        "description": "P2QPKH invalid pk_ser length (SHRINCS)",
        "algorithm": "SHRINCS",
        "tx_hex": hex_encode(tx_bad_len.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_pkser_shrincs.json", bad_len);

    // Invalid alg_id 0x11 (old ML-DSA, now removed)
    let mut pk_alg11 = pk_ser.clone();
    pk_alg11[0] = 0x11;
    let mut tx_alg11 = base_tx.clone();
    tx_alg11.vin[0].witness = vec![sig.clone(), pk_alg11];
    let bad_alg11 = json!({
        "description": "P2QPKH invalid pk_ser alg_id 0x11 (ML-DSA removed)",
        "algorithm": "unknown",
        "tx_hex": hex_encode(tx_alg11.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_alg11.json", bad_alg11);

    // Invalid alg_id 0x21 (reserved)
    let mut pk_alg21 = pk_ser.clone();
    pk_alg21[0] = 0x21;
    let mut tx_alg21 = base_tx.clone();
    tx_alg21.vin[0].witness = vec![sig, pk_alg21];
    let bad_alg21 = json!({
        "description": "P2QPKH invalid pk_ser alg_id 0x21 (reserved)",
        "algorithm": "unknown",
        "tx_hex": hex_encode(tx_alg21.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_alg21.json", bad_alg21);

    println!("P2QPKH vectors generated with SHRINCS");
}

#[cfg(feature = "shrincs-dev")]
fn p2qtsh_vectors() {
    // Generate a SHRINCS keypair for the output
    let (pk_ser, _key_material, _signing_state) =
        shrincs_keypair().expect("SHRINCS keygen failed");

    let leaf_script = vec![0x51]; // OP_1
    let control_block = vec![0x01]; // parity=1, leaf_version=0x00, no merkle path
    let leaf_hash = qtap_leaf_hash(0x00, &leaf_script);
    let qroot = qtap_reconstruct_root(leaf_hash, &[]);
    let spk = build_p2qtsh(qroot);

    let prevouts = [Prevout::regular(10_0000, spk.clone())];

    let tx_valid = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [2u8; 32],
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffff_ffff,
            witness: vec![leaf_script.clone(), control_block.clone()],
        }],
        vout: vec![TxOut {
            value: 5_0000,
            script_pubkey: build_p2qpkh(qpkh32(&pk_ser)),
        }],
        lock_time: 0,
    };

    let tx_hex = hex_encode(tx_valid.serialize(true));
    let valid = json!({
        "description": "P2QTSH valid simple true leaf",
        "tx_hex": tx_hex,
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": true}
    });
    write_vec("p2qtsh_valid.json", valid);

    // Invalid control block: bad length (not 1 mod 32)
    let bad_control = vec![0x01, 0x02];
    let mut tx_bad = tx_valid.clone();
    tx_bad.vin[0].witness = vec![leaf_script, bad_control];
    let bad = json!({
        "description": "P2QTSH invalid control block length",
        "tx_hex": hex_encode(tx_bad.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qtsh_invalid_control.json", bad);

    println!("P2QTSH vectors generated");
}

#[cfg(feature = "shrincs-dev")]
fn shrincs_size_vectors() {
    // Generate multiple signatures to demonstrate size growth
    let (pk_ser, key_material, mut signing_state) =
        shrincs_keypair().expect("SHRINCS keygen failed");

    let mut sizes = Vec::new();
    for q in 1..=5 {
        let msg = [q as u8; 32];
        let sig = shrincs_sign(&key_material, &mut signing_state, &msg, 0x01)
            .expect("SHRINCS sign failed");
        sizes.push(json!({
            "q": q,
            "signature_size_bytes": sig.len(),
            "msg_hex": hex_encode(&msg),
        }));
    }

    let vec = json!({
        "description": "SHRINCS signature size progression (grows with q)",
        "algorithm": "SHRINCS",
        "pk_ser_hex": hex_encode(&pk_ser),
        "pk_size_bytes": pk_ser.len(),
        "note": "Signature size = 292 + q*16 bytes (plus type prefix, full_pk, sighash byte)",
        "signatures": sizes,
    });
    write_vec("shrincs_sizes.json", vec);

    println!("SHRINCS size vectors generated");
}

#[cfg(feature = "shrincs-dev")]
fn main() {
    println!("Generating SHRINCS test vectors...\n");
    p2qpkh_vectors();
    p2qtsh_vectors();
    shrincs_size_vectors();
    println!("\nAll vectors written to vectors/ directory");
}

#[cfg(not(feature = "shrincs-dev"))]
fn main() {
    eprintln!("gen_vectors requires the shrincs-dev feature for signing");
    eprintln!("Run with: cargo run --features shrincs-dev --bin gen_vectors");
    std::process::exit(1);
}
