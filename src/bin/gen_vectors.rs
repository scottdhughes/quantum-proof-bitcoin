use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::Path;

use hex::encode as hex_encode;
use qpb_consensus::{
    OutPoint, Prevout, Transaction, TxIn, TxOut, build_p2qpkh, build_p2qtsh, qpb_sighash, qpkh32,
    qtap_leaf_hash, qtap_reconstruct_root, shrincs_keygen, shrincs_sign,
};
use serde_json::json;

fn write_vec(name: &str, value: serde_json::Value) {
    let dir = Path::new("vectors");
    create_dir_all(dir).expect("create vectors dir");
    let path = dir.join(name);
    let mut f = File::create(&path).expect("create vector file");
    let s = serde_json::to_string_pretty(&value).expect("serialize json");
    f.write_all(s.as_bytes()).expect("write json");
}

fn p2qpkh_vectors() {
    let pk = shrincs_keygen();
    let mut pk_ser = Vec::with_capacity(65);
    pk_ser.push(0x30);
    pk_ser.extend_from_slice(&pk);

    let prevout = OutPoint {
        txid: [1u8; 32],
        vout: 0,
    };
    let spk = build_p2qpkh(qpkh32(&pk_ser));
    let prevouts = vec![Prevout {
        value: 50_0000_0000,
        script_pubkey: spk.clone(),
    }];

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
    let mut sig = shrincs_sign(&pk, &msg).to_vec();
    sig.push(sighash_type);

    let mut tx_valid = base_tx.clone();
    tx_valid.vin[0].witness = vec![sig.clone(), pk_ser.clone()];
    let tx_hex = hex_encode(tx_valid.serialize(true));

    let valid = json!({
        "description": "P2QPKH valid spend",
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
            "msg32_hex": hex_encode(&msg),
        }
    });
    write_vec("p2qpkh_valid.json", valid);

    // Invalid sig: flip one byte in sig body (not state bytes)
    let mut sig_bad = sig.clone();
    sig_bad[10] ^= 0x01;
    let mut tx_bad = base_tx.clone();
    tx_bad.vin[0].witness = vec![sig_bad, pk_ser.clone()];
    let bad = json!({
        "description": "P2QPKH invalid signature (tampered byte)",
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
            "msg32_hex": hex_encode(&msg),
        }
    });
    write_vec("p2qpkh_invalid_sig.json", bad);

    // Invalid pk_ser (wrong alg_id) but same scriptPubKey
    let mut bad_pk_ser = pk_ser.clone();
    bad_pk_ser[0] = 0x31;
    let mut tx_bad_pk = base_tx.clone();
    tx_bad_pk.vin[0].witness = vec![sig, bad_pk_ser];
    let bad_pk = json!({
        "description": "P2QPKH invalid pk_ser alg_id",
        "tx_hex": hex_encode(tx_bad_pk.serialize(true)),
        "input_index": 0,
        "prevouts": [
            {
                "value": prevouts[0].value,
                "script_pubkey_hex": hex_encode(&prevouts[0].script_pubkey),
            }
        ],
        "expected": {"valid": false}
    });
    write_vec("p2qpkh_invalid_pkser.json", bad_pk);
}

fn p2qtsh_vectors() {
    let leaf_script = vec![0x51]; // OP_1
    let control_block = vec![0x01]; // parity=1, leaf_version=0x00, no merkle path
    let leaf_hash = qtap_leaf_hash(0x00, &leaf_script);
    let qroot = qtap_reconstruct_root(leaf_hash, &[]);
    let spk = build_p2qtsh(qroot);

    let prevouts = vec![Prevout {
        value: 10_0000,
        script_pubkey: spk.clone(),
    }];

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
            script_pubkey: build_p2qpkh(qpkh32(&{
                let mut pkser = Vec::with_capacity(65);
                pkser.push(0x30);
                pkser.extend_from_slice(&shrincs_keygen());
                pkser
            })),
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
}

fn main() {
    p2qpkh_vectors();
    p2qtsh_vectors();
}
