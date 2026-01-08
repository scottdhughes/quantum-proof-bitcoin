use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use hex::FromHex;
use qpb_consensus::varint::read_compact_size;
use qpb_consensus::{
    Prevout, Transaction, TxIn, TxOut, activation::Network, parse_script_pubkey, qpb_sighash,
    qtap_leaf_hash, qtap_reconstruct_root, validate_transaction_basic,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Expected {
    valid: bool,
    #[serde(default)]
    msg32_hex: Option<String>,
}

#[derive(Deserialize)]
struct PrevoutJson {
    value: u64,
    script_pubkey_hex: String,
}

#[derive(Deserialize)]
struct Vector {
    tx_hex: String,
    input_index: usize,
    prevouts: Vec<PrevoutJson>,
    expected: Expected,
}

fn read_bytes(cur: &mut Cursor<Vec<u8>>, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    cur.read_exact(&mut buf).unwrap();
    buf
}

fn deserialize_tx(hex_tx: &str) -> Transaction {
    let bytes = Vec::from_hex(hex_tx).expect("hex");
    let mut cur = Cursor::new(bytes);

    let mut vbuf = [0u8; 4];
    cur.read_exact(&mut vbuf).unwrap();
    let version = i32::from_le_bytes(vbuf);

    // segwit marker/flag detection
    let mut marker = [0u8; 1];
    cur.read_exact(&mut marker).unwrap();
    let mut segwit = false;
    if marker[0] == 0x00 {
        let mut flag = [0u8; 1];
        cur.read_exact(&mut flag).unwrap();
        if flag[0] == 0x01 {
            segwit = true;
        } else {
            cur.set_position(cur.position() - 2); // rewind marker + flag as vin count
        }
    } else {
        cur.set_position(cur.position() - 1); // rewind marker as vin count
    }

    let vin_len = read_compact_size(&mut cur).unwrap() as usize;
    let mut vin = Vec::with_capacity(vin_len);
    for _ in 0..vin_len {
        let mut txid_le = [0u8; 32];
        cur.read_exact(&mut txid_le).unwrap();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_le.iter().rev().cloned().collect::<Vec<_>>());
        let mut voutb = [0u8; 4];
        cur.read_exact(&mut voutb).unwrap();
        let vout = u32::from_le_bytes(voutb);
        let script_len = read_compact_size(&mut cur).unwrap() as usize;
        let script_sig = read_bytes(&mut cur, script_len);
        let mut seqb = [0u8; 4];
        cur.read_exact(&mut seqb).unwrap();
        let sequence = u32::from_le_bytes(seqb);
        vin.push(TxIn {
            prevout: qpb_consensus::OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    let vout_len = read_compact_size(&mut cur).unwrap() as usize;
    let mut vout_vec = Vec::with_capacity(vout_len);
    for _ in 0..vout_len {
        let mut valb = [0u8; 8];
        cur.read_exact(&mut valb).unwrap();
        let value = u64::from_le_bytes(valb);
        let spk_len = read_compact_size(&mut cur).unwrap() as usize;
        let script_pubkey = read_bytes(&mut cur, spk_len);
        vout_vec.push(TxOut {
            value,
            script_pubkey,
        });
    }

    if segwit {
        for txin in vin.iter_mut() {
            let items = read_compact_size(&mut cur).unwrap() as usize;
            let mut stack = Vec::with_capacity(items);
            for _ in 0..items {
                let len = read_compact_size(&mut cur).unwrap() as usize;
                stack.push(read_bytes(&mut cur, len));
            }
            txin.witness = stack;
        }
    }

    let mut ltb = [0u8; 4];
    cur.read_exact(&mut ltb).unwrap();
    let lock_time = u32::from_le_bytes(ltb);

    Transaction {
        version,
        vin,
        vout: vout_vec,
        lock_time,
    }
}

fn prevouts_from_json(v: &[PrevoutJson]) -> Vec<Prevout> {
    v.iter()
        .map(|p| Prevout::regular(p.value, Vec::from_hex(&p.script_pubkey_hex).unwrap()))
        .collect()
}

#[test]
#[cfg_attr(miri, ignore)] // Validates against Dilithium FFI
fn run_vectors() {
    let dir = Path::new("vectors");
    let entries = fs::read_dir(dir).expect("vectors dir");
    let mut count = 0;
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().map(|s| s == "json").unwrap_or(false) {
            let data = fs::read_to_string(&path).unwrap();
            let vec: Vector = serde_json::from_str(&data).unwrap();
            let tx = deserialize_tx(&vec.tx_hex);
            let prevouts = prevouts_from_json(&vec.prevouts);

            let valid = validate_transaction_basic(&tx, &prevouts, 1, Network::Devnet).is_ok();
            assert_eq!(valid, vec.expected.valid, "{}", path.display());

            if let Some(msg_hex) = &vec.expected.msg32_hex {
                let spk = &prevouts[vec.input_index].script_pubkey;
                let ext_flag;
                let leaf_hash_opt;
                match parse_script_pubkey(spk) {
                    qpb_consensus::script::ScriptType::P2QPKH(_) => {
                        ext_flag = 0x00;
                        leaf_hash_opt = None;
                    }
                    qpb_consensus::script::ScriptType::P2QTSH(_) => {
                        ext_flag = 0x01;
                        let wit = &tx.vin[vec.input_index].witness;
                        assert!(wit.len() >= 2, "missing tap items");
                        let leaf_script = &wit[wit.len() - 2];
                        let control_block = &wit[wit.len() - 1];
                        let control_byte = control_block[0];
                        let leaf_version = control_byte & 0xfe;
                        let nodes_bytes = &control_block[1..];
                        let mut nodes: Vec<[u8; 32]> = Vec::new();
                        for chunk in nodes_bytes.chunks(32) {
                            if chunk.len() == 32 {
                                let mut n = [0u8; 32];
                                n.copy_from_slice(chunk);
                                nodes.push(n);
                            }
                        }
                        let leaf_hash = qtap_leaf_hash(leaf_version, leaf_script);
                        let _root = qtap_reconstruct_root(leaf_hash, &nodes); // ensure no panic
                        leaf_hash_opt = Some(leaf_hash);
                    }
                    _ => panic!("unsupported spk in vector {}", path.display()),
                }
                let msg = qpb_sighash(
                    &tx,
                    vec.input_index,
                    &prevouts,
                    0x01,
                    ext_flag,
                    leaf_hash_opt,
                )
                .unwrap();
                assert_eq!(
                    hex::encode(msg),
                    msg_hex.to_lowercase(),
                    "{}",
                    path.display()
                );
            }
            count += 1;
        }
    }
    assert!(count > 0, "no vectors executed");
}
