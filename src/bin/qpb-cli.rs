//! Development CLI for mining and testing QPB blocks.
//!
//! This tool requires the `shrincs-dev` feature for signing functionality.

use base64::{Engine as _, engine::general_purpose};
use qpb_consensus::{
    Block, BlockHeader, OutPoint, Prevout, Transaction, TxIn, TxOut, WEIGHT_FLOOR_WU,
    activation::Network, block_subsidy, build_p2qpkh, merkle_root, mine_header_parallel,
    mine_header_serial, qpb_sighash, qpkh32, validate_block_basic,
    witness_merkle_root,
};
#[cfg(feature = "shrincs-dev")]
use qpb_consensus::{shrincs_keypair, shrincs_sign};
#[cfg(feature = "shrincs-dev")]
use qpb_consensus::shrincs::shrincs::ShrincsKeyMaterial;
#[cfg(feature = "shrincs-dev")]
use qpb_consensus::shrincs::state::SigningState;
use rand::RngCore;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};

#[cfg(feature = "cli-vectors")]
use serde::Serialize;

/// SHRINCS algorithm ID (used for documentation/reference)
#[allow(dead_code)]
const SHRINCS_ALG_ID: u8 = 0x30;

fn parse_bits(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0x207fffff)
}

#[cfg(feature = "shrincs-dev")]
fn emit_vectors_mode(args: &[String]) {
    let mut msg: Option<Vec<u8>> = None;
    let mut batch: usize = 1;
    let mut pk_sig_only = false;
    let mut random_msg = false;
    let mut sig_format = String::from("hex");
    let mut output_file: Option<String> = None;

    for a in args.iter().skip(2) {
        match a.as_str() {
            "--pk-sig-only" => pk_sig_only = true,
            "--random-msg" => random_msg = true,
            _ if a.starts_with("--msg=") => {
                if let Ok(v) = hex::decode(&a["--msg=".len()..]) {
                    msg = Some(v);
                }
            }
            _ if a.starts_with("--batch=") => {
                if let Ok(v) = a["--batch=".len()..].parse::<usize>() {
                    batch = v.max(1);
                }
            }
            _ if a.starts_with("--sig-format=") => {
                sig_format = a["--sig-format=".len()..].to_ascii_lowercase();
            }
            _ if a.starts_with("--output-file=") => {
                output_file = Some(a["--output-file=".len()..].to_string());
            }
            _ => {}
        }
    }

    let msg32_template = {
        let m = msg.unwrap_or_else(|| vec![0u8; 32]);
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = *m.get(i).unwrap_or(&0);
        }
        out
    };

    let mut rng = rand::thread_rng();
    let mut out_handle = output_file.as_ref().map(|path| {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .expect("unable to open output file")
    });

    for idx in 0..batch {
        let msg32 = if random_msg {
            let mut m = [0u8; 32];
            rng.fill_bytes(&mut m);
            m
        } else {
            msg32_template
        };

        // Generate SHRINCS key
        let (pk_ser, key_material, mut signing_state) =
            shrincs_keypair().expect("SHRINCS keygen failed");

        // Sign with SHRINCS
        let sig_ser = shrincs_sign(&key_material, &mut signing_state, &msg32, 0x01)
            .expect("SHRINCS sign failed");

        let encode = |data: &[u8], fmt: &str| -> String {
            match fmt {
                "base64" => general_purpose::STANDARD.encode(data),
                "raw" => String::new(),
                _ => hex::encode(data),
            }
        };

        if sig_format == "raw" {
            let mut buf = Vec::with_capacity(pk_ser.len() + sig_ser.len() + 2);
            buf.extend_from_slice(&pk_ser);
            buf.push(b'\n');
            buf.extend_from_slice(&sig_ser);
            buf.push(b'\n');
            if let Some(file) = out_handle.as_mut() {
                file.write_all(&buf).expect("write raw pk/sig");
            } else {
                let mut stdout = io::stdout();
                stdout.write_all(&buf).unwrap();
            }
            continue;
        }

        let pk_enc = encode(&pk_ser, &sig_format);
        let sig_enc = encode(&sig_ser, &sig_format);

        let mut lines: Vec<String> = Vec::new();
        if pk_sig_only {
            lines.push(format!("pk_ser={}", pk_enc));
            lines.push(format!("sig_ser={}", sig_enc));
        } else {
            lines.push(format!("batch_index={}", idx));
            lines.push(format!("pk_ser={}", pk_enc));
            lines.push(format!("sig_ser={}", sig_enc));
            lines.push(format!("msg32={}", hex::encode(msg32)));
            lines.push(format!("algorithm=SHRINCS"));
        }

        if let Some(file) = out_handle.as_mut() {
            for line in lines {
                file.write_all(line.as_bytes()).expect("write vectors");
                file.write_all(b"\n").expect("write newline");
            }
        } else {
            for line in lines {
                println!("{}", line);
            }
        }
    }
}

#[cfg(not(feature = "shrincs-dev"))]
fn emit_vectors_mode(_args: &[String]) {
    eprintln!("Vector generation requires shrincs-dev feature");
    std::process::exit(1);
}

fn build_coinbase(height: u32, message: &[u8]) -> Transaction {
    let script_sig = {
        let mut v = Vec::new();
        v.extend_from_slice(&height.to_le_bytes());
        v.extend_from_slice(message);
        v
    };
    Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0xffff_ffff,
            },
            script_sig,
            sequence: 0xffff_ffff,
            witness: vec![vec![0u8; 32]],
        }],
        vout: vec![],
        lock_time: 0,
    }
}

/// SHRINCS key material for CLI mining.
#[cfg(feature = "shrincs-dev")]
struct CliKeyMaterial {
    pk_ser: Vec<u8>,
    key_material: ShrincsKeyMaterial,
    signing_state: SigningState,
}

#[cfg(feature = "shrincs-dev")]
impl CliKeyMaterial {
    fn new() -> Self {
        let (pk_ser, key_material, signing_state) =
            shrincs_keypair().expect("SHRINCS keygen failed");
        Self {
            pk_ser,
            key_material,
            signing_state,
        }
    }

    fn sign(&mut self, msg32: &[u8; 32]) -> Vec<u8> {
        shrincs_sign(&self.key_material, &mut self.signing_state, msg32, 0x01)
            .expect("SHRINCS sign failed")
    }

    fn pk_ser(&self) -> &[u8] {
        &self.pk_ser
    }
}

#[cfg(feature = "shrincs-dev")]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.get(1).map(|s| s.as_str()) == Some("vectors") {
        emit_vectors_mode(&args);
        return;
    }

    let mut nblocks: u32 = 1;
    let mut bits: u32 = 0x207fffff;
    let mut parallel = false;
    let mut do_spends = true;
    let mut fresh_key_each = false;
    let mut claim_fees = false;
    let mut burn_spend = false;
    let mut witness_only = false;
    let mut emit_wallet = false;

    for (idx, a) in args.iter().enumerate().skip(1) {
        match a.as_str() {
            "--parallel" => parallel = true,
            "--no-spend" => do_spends = false,
            "--fresh-key" => fresh_key_each = true,
            "--claim-fees" => claim_fees = true,
            "--burn-spend" => burn_spend = true,
            "--witness-only" => witness_only = true,
            "--emit-wallet" => emit_wallet = true,
            _ if a.starts_with("--bits=") => {
                bits = parse_bits(&a["--bits=".len()..]);
            }
            _ if a.starts_with("--blocks=") => {
                if let Ok(v) = a["--blocks=".len()..].parse() {
                    nblocks = v;
                }
            }
            _ => {
                if idx == 1 {
                    if let Ok(v) = a.parse() {
                        nblocks = v;
                    }
                } else if idx == 2 {
                    bits = parse_bits(a);
                }
            }
        }
    }

    let message = b"QPB dev mine";

    // SHRINCS key material (stateful)
    let mut current_key = CliKeyMaterial::new();
    let mut p2qpkh_spk = build_p2qpkh(qpkh32(current_key.pk_ser()));

    // Track last coinbase key for spending
    let mut last_coin_pk_ser = current_key.pk_ser().to_vec();
    let mut last_coin_spk = p2qpkh_spk.clone();
    let mut last_coin_key = CliKeyMaterial::new(); // Separate key for spending

    if emit_wallet {
        eprintln!("wallet_pk_ser={}", hex::encode(current_key.pk_ser()));
    }

    let fee: u64 = 1_000;
    let mut prev_hash = [0u8; 32];
    let mut prev_coin_value: u64 = 0;
    let mut prev_coin_outpoint: Option<OutPoint> = None;
    let mut utxos: Vec<(OutPoint, Prevout)> = Vec::new();

    for height in 0..nblocks {
        let subsidy = block_subsidy(height);

        if fresh_key_each {
            current_key = CliKeyMaterial::new();
            p2qpkh_spk = build_p2qpkh(qpkh32(current_key.pk_ser()));
        }

        let mut txs: Vec<Transaction> = Vec::new();
        let mut prevouts_for_block: Vec<Vec<Prevout>> = Vec::new();

        let mut coinbase = build_coinbase(height, message);
        let mut fee_for_block = fee;
        if burn_spend {
            fee_for_block = prev_coin_value.max(fee);
        }
        coinbase.vout.push(TxOut {
            value: subsidy + if claim_fees && do_spends { fee_for_block } else { 0 },
            script_pubkey: p2qpkh_spk.clone(),
        });
        txs.push(coinbase);
        prevouts_for_block.push(vec![]);

        if height > 0 && do_spends {
            let prev_out = prev_coin_outpoint.as_ref().cloned().expect("prev coinbase missing");
            let (prev_pos, prev_utxo) = utxos
                .iter()
                .enumerate()
                .find(|(_, (op, _))| *op == prev_out)
                .map(|(i, (_, u))| (i, u.clone()))
                .expect("prev coinbase utxo missing");

            let spend_in = TxIn {
                prevout: OutPoint {
                    txid: prev_out.txid,
                    vout: prev_out.vout,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                witness: vec![],
            };

            let mut spend_outputs = Vec::new();
            if !burn_spend {
                if witness_only {
                    spend_outputs.push(TxOut {
                        value: 0,
                        script_pubkey: vec![0x6a, 0x00],
                    });
                } else {
                    spend_outputs.push(TxOut {
                        value: prev_utxo.value.saturating_sub(fee_for_block),
                        script_pubkey: last_coin_spk.clone(),
                    });
                }
            }

            let mut spend_tx = Transaction {
                version: 1,
                vin: vec![spend_in],
                vout: spend_outputs,
                lock_time: 0,
            };

            let spend_prevouts = vec![prev_utxo.clone()];
            let sighash_type = 0x01u8;
            let msg = qpb_sighash(&spend_tx, 0, &spend_prevouts, sighash_type, 0x00, None)
                .expect("sighash");

            let sig_ser = last_coin_key.sign(&msg);
            spend_tx.vin[0].witness = vec![sig_ser, last_coin_pk_ser.clone()];
            txs.push(spend_tx);
            prevouts_for_block.push(spend_prevouts);

            utxos.remove(prev_pos);
        }

        // Compute witness commitment
        let wroot = witness_merkle_root(&Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash: prev_hash,
                merkle_root: [0u8; 32],
                time: 0,
                bits,
                nonce: 0,
            },
            txdata: txs.clone(),
        });
        let mut buf = Vec::new();
        buf.extend_from_slice(&wroot);
        buf.extend_from_slice(&txs[0].vin[0].witness[0]);
        let commitment_hash = qpb_consensus::hash256(&buf);
        let commitment_spk = {
            let mut spk = Vec::with_capacity(38);
            spk.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
            spk.extend_from_slice(&commitment_hash);
            spk
        };
        txs[0].vout.push(TxOut {
            value: 0,
            script_pubkey: commitment_spk,
        });

        let txids: Vec<[u8; 32]> = txs.iter().map(|tx| tx.txid()).collect();
        let merkle = merkle_root(&txids);
        let coinbase_txid = txids[0];

        let header = BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_735_171_200 + height,
            bits,
            nonce: 0,
        };

        let mined = if parallel {
            match mine_header_parallel(&header, 0..u32::MAX as u64) {
                Some(h) => Some(h),
                None => {
                    eprintln!("parallel mining unavailable; falling back to serial");
                    mine_header_serial(header.clone(), 0, u32::MAX as u64)
                }
            }
        } else {
            mine_header_serial(header.clone(), 0, u32::MAX as u64)
        };

        let header = mined.expect("no valid nonce found");
        prev_hash = header.hash();
        prev_coin_value = subsidy + if claim_fees && do_spends { fee_for_block } else { 0 };
        prev_coin_outpoint = Some(OutPoint {
            txid: coinbase_txid,
            vout: 0,
        });

        utxos.push((
            prev_coin_outpoint.as_ref().cloned().unwrap(),
            Prevout::regular(prev_coin_value, p2qpkh_spk.clone()),
        ));

        // Track key for next spend
        last_coin_pk_ser = current_key.pk_ser().to_vec();
        last_coin_spk = p2qpkh_spk.clone();
        last_coin_key = CliKeyMaterial::new(); // Fresh key for each coinbase

        let block = Block {
            header: header.clone(),
            txdata: txs.clone(),
        };

        validate_block_basic(
            &block,
            &prevouts_for_block,
            WEIGHT_FLOOR_WU,
            WEIGHT_FLOOR_WU,
            true,
            height,
            0,
            Network::Devnet,
            |_| 0,
        )
        .expect("block validation failed");

        println!(
            "height={} nonce={} block_hash={} merkle={} subsidy={} txs={} algorithm=SHRINCS",
            height,
            header.nonce,
            hex::encode(prev_hash),
            hex::encode(merkle),
            subsidy,
            txs.len(),
        );
    }
}

#[cfg(not(feature = "shrincs-dev"))]
fn main() {
    eprintln!("qpb-cli requires the shrincs-dev feature for signing operations");
    eprintln!("Run with: cargo run --features shrincs-dev --bin qpb-cli");
    std::process::exit(1);
}
