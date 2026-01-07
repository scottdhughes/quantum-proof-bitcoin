use base64::{Engine as _, engine::general_purpose};
use qpb_consensus::{
    Block, BlockHeader, OutPoint, Prevout, Transaction, TxIn, TxOut, WEIGHT_FLOOR_WU,
    activation::Network, block_subsidy, build_p2qpkh, merkle_root, mine_header_parallel,
    mine_header_serial, mldsa_keypair, mldsa_sign, qpb_sighash, qpkh32, validate_block_basic,
    witness_merkle_root,
};
use rand::{Rng, RngCore};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, Write};

#[cfg(feature = "cli-vectors")]
use serde::Serialize;

fn parse_bits(s: &str) -> u32 {
    u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0x207fffff)
}

#[cfg(feature = "cli-vectors")]
#[allow(dead_code)]
fn emit_vectors(pk_ser: &[u8], sig_ser: &[u8], msg32: &[u8], force_slh: bool) {
    let vector = serde_json::json!({
        "pk_ser": hex::encode(pk_ser),
        "sig_ser": hex::encode(sig_ser),
        "msg32": hex::encode(msg32),
        "force_slh": force_slh,
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

fn emit_vectors_mode(args: &[String]) {
    let mut force_slh = false;
    let mut msg: Option<Vec<u8>> = None;
    let mut batch: usize = 1;
    let mut q_sim: usize = 0;
    let mut state_index: u32 = 0;
    let mut custom_pad: usize = 0;
    let mut pk_sig_only = false;
    let mut random_msg = false;
    let mut sig_format = String::from("hex"); // hex|base64|raw
    let mut output_file: Option<String> = None;
    let mut sim_prob: f64 = 0.0; // probability to force SLH fallback per item
    for a in args.iter().skip(2) {
        match a.as_str() {
            "--force-slh" => force_slh = true,
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
            _ if a.starts_with("--q=") => {
                if let Ok(v) = a["--q=".len()..].parse::<usize>() {
                    q_sim = v;
                }
            }
            _ if a.starts_with("--state-index=") => {
                if let Ok(v) = a["--state-index=".len()..].parse::<u32>() {
                    state_index = v;
                }
            }
            _ if a.starts_with("--custom-pad=") => {
                if let Ok(v) = a["--custom-pad=".len()..].parse::<usize>() {
                    custom_pad = v;
                }
            }
            _ if a.starts_with("--sig-format=") => {
                sig_format = a["--sig-format=".len()..].to_ascii_lowercase();
            }
            _ if a.starts_with("--output-file=") => {
                output_file = Some(a["--output-file=".len()..].to_string());
            }
            _ if a.starts_with("--sim-fallback-prob=") => {
                if let Ok(v) = a["--sim-fallback-prob=".len()..].parse::<f64>() {
                    sim_prob = v.clamp(0.0, 1.0);
                }
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
        // Generate key and sig via ML-DSA
        let (pk_bytes, sk_bytes) = mldsa_keypair();
        let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
        pk_ser.push(0x11);
        pk_ser.extend_from_slice(&pk_bytes);
        let mut sig = mldsa_sign(&sk_bytes, &msg32).expect("mldsa sign");
        let random_fallback = sim_prob > 0.0 && rng.gen_range(0.0..1.0) < sim_prob;
        let applied_force_slh = force_slh || random_fallback;
        if applied_force_slh {
            sig[0] ^= 0xff; // perturb sig
        }
        // override state index if requested (big-endian in sig[0..4]) when not forcing SLH
        // (no-op for ML-DSA; kept for interface compatibility)
        let mut sig_ser = sig.to_vec();
        if q_sim > 0 {
            // add 16 bytes per simulated auth level (arbitrary pad to mimic growth)
            sig_ser.extend(std::iter::repeat_n(0u8, 16 * q_sim));
        }
        if custom_pad > 0 {
            sig_ser.extend(std::iter::repeat_n(0u8, custom_pad));
        }
        sig_ser.push(0x01); // SIGHASH_ALL marker for consistency

        // encoding helpers
        let encode = |data: &[u8], fmt: &str| -> String {
            match fmt {
                "base64" => general_purpose::STANDARD.encode(data),
                "raw" => String::new(), // handled separately
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
            #[cfg(feature = "cli-vectors")]
            {
                let vector = serde_json::json!({
                    "batch_index": idx,
                    "pk_ser": pk_enc,
                    "sig_ser": sig_enc,
                    "msg32": hex::encode(msg32),
                    "force_slh": applied_force_slh,
                    "forced_by_prob": random_fallback,
                    "q_sim": q_sim,
                    "state_index": state_index,
                    "custom_pad": custom_pad,
                    "sig_format": sig_format,
                    "random_msg": random_msg,
                    "sim_fallback_prob": sim_prob,
                });
                lines.push(serde_json::to_string_pretty(&vector).unwrap());
            }
            #[cfg(not(feature = "cli-vectors"))]
            {
                lines.push(format!("batch_index={}", idx));
                lines.push(format!("pk_ser={}", pk_enc));
                lines.push(format!("sig_ser={}", sig_enc));
                lines.push(format!("msg32={}", hex::encode(msg32)));
                lines.push(format!("force_slh={}", applied_force_slh));
                lines.push(format!("forced_by_prob={}", random_fallback));
                lines.push(format!("q_sim={}", q_sim));
                lines.push(format!("state_index={}", state_index));
                lines.push(format!("custom_pad={}", custom_pad));
                lines.push(format!("sig_format={}", sig_format));
                lines.push(format!("random_msg={}", random_msg));
                lines.push(format!("sim_fallback_prob={}", sim_prob));
            }
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
            witness: vec![vec![0u8; 32]], // witness_reserved_value
        }],
        vout: vec![],
        lock_time: 0,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Vector-only mode: emit pk/sig/msg without mining
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
    let mut force_slh = false;
    let mut emit_vectors: Option<String> = None;
    let mut target_count: usize = 0;
    let mut burn_spend = false;
    let mut witness_only = false; // spend to OP_RETURN to avoid UTXO growth
    let mut emit_wallet = false;

    // Parse: [blocks] [bits] [--parallel] [--no-spend] [--blocks=N] [--bits=HEX]
    for (idx, a) in args.iter().enumerate().skip(1) {
        match a.as_str() {
            "--parallel" => parallel = true,
            "--no-spend" => do_spends = false,
            "--fresh-key" => fresh_key_each = true,
            "--claim-fees" => claim_fees = true,
            "--force-slh" => force_slh = true,
            _ if a.starts_with("--emit-vectors=") => {
                emit_vectors = Some(a["--emit-vectors=".len()..].to_string());
            }
            _ if a.starts_with("--targets=") => {
                if let Ok(v) = a["--targets=".len()..].parse() {
                    target_count = v;
                }
            }
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

    // Dev key material (can refresh per block with --fresh-key)
    let (mut current_pk_bytes, mut current_sk_bytes) = mldsa_keypair();
    let mut current_pk_ser = {
        let mut v = Vec::with_capacity(1 + current_pk_bytes.len());
        v.push(0x11);
        v.extend_from_slice(&current_pk_bytes);
        v
    };
    let mut p2qpkh_spk = build_p2qpkh(qpkh32(&current_pk_ser));
    // Track last coinbase material for spending in the next block.
    let mut last_coin_pk_ser = current_pk_ser.clone();
    let mut last_coin_spk = p2qpkh_spk.clone();
    let mut last_coin_sk = current_sk_bytes.clone();

    // Optional target set for varied outputs
    let mut targets: Vec<Vec<u8>> = Vec::new();
    for i in 0..target_count {
        let (pkb, _skb) = mldsa_keypair();
        let mut pk = pkb;
        // simple variation: xor first byte with index
        pk[0] ^= i as u8;
        let mut pkser = Vec::with_capacity(1 + pk.len());
        pkser.push(0x11);
        pkser.extend_from_slice(&pk);
        targets.push(build_p2qpkh(qpkh32(&pkser)));
    }

    if emit_wallet {
        eprintln!("wallet_pk_ser={}", hex::encode(&current_pk_ser));
    }
    let fee: u64 = 1_000;

    let mut prev_hash = [0u8; 32];
    let mut prev_coin_value: u64 = 0;
    let mut prev_coin_outpoint: Option<OutPoint> = None;
    let mut utxos: Vec<(OutPoint, Prevout)> = Vec::new();

    for height in 0..nblocks {
        let subsidy = block_subsidy(height);

        // Rotate key for the new coinbase if requested
        if fresh_key_each {
            let (pkb, skb) = mldsa_keypair();
            current_pk_bytes = pkb;
            current_sk_bytes = skb;
            current_pk_ser = {
                let mut v = Vec::with_capacity(1 + current_pk_bytes.len());
                v.push(0x11);
                v.extend_from_slice(&current_pk_bytes);
                v
            };
            p2qpkh_spk = build_p2qpkh(qpkh32(&current_pk_ser));
        }

        let mut txs: Vec<Transaction> = Vec::new();
        let mut prevouts_for_block: Vec<Vec<Prevout>> = Vec::new();

        // Coinbase with spendable output to our static key; commitment added later.
        let mut coinbase = build_coinbase(height, message);
        let mut fee_for_block = fee;
        if burn_spend {
            fee_for_block = prev_coin_value.max(fee); // burn entire previous coinbase if spend occurs
        }
        coinbase.vout.push(TxOut {
            value: subsidy
                + if claim_fees && do_spends {
                    fee_for_block
                } else {
                    0
                },
            script_pubkey: p2qpkh_spk.clone(),
        });
        txs.push(coinbase);
        prevouts_for_block.push(vec![]); // coinbase

        if height > 0 && do_spends {
            // Spend previous block's coinbase vout 0 (p2qpkh)
            let prev_out = prev_coin_outpoint
                .as_ref()
                .cloned()
                .expect("prev coinbase missing");
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
                witness: vec![], // fill after signing
            };
            let mut spend_outputs = Vec::new();
            if !burn_spend {
                if witness_only {
                    spend_outputs.push(TxOut {
                        value: 0,
                        script_pubkey: vec![0x6a, 0x00], // OP_RETURN 0-byte push
                    });
                } else if targets.is_empty() {
                    spend_outputs.push(TxOut {
                        value: prev_utxo.value.saturating_sub(fee_for_block),
                        script_pubkey: last_coin_spk.clone(),
                    });
                } else {
                    let each = prev_utxo.value.saturating_sub(fee_for_block) / targets.len() as u64;
                    for spk in &targets {
                        spend_outputs.push(TxOut {
                            value: each,
                            script_pubkey: spk.clone(),
                        });
                    }
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
            let mut sig_ser = mldsa_sign(&last_coin_sk, &msg).expect("ml-dsa sign");
            if force_slh {
                sig_ser[0] ^= 0x01; // simple perturbation for path testing
            }
            sig_ser.push(sighash_type);
            spend_tx.vin[0].witness = vec![sig_ser, last_coin_pk_ser.clone()];
            txs.push(spend_tx);
            prevouts_for_block.push(spend_prevouts);

            // Remove spent UTXO
            utxos.remove(prev_pos);
        }

        // Compute witness commitment and add to coinbase outputs
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
        buf.extend_from_slice(&txs[0].vin[0].witness[0]); // reserved value
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

        // Now recompute txids and merkle root
        let txids: Vec<[u8; 32]> = txs.iter().map(|tx| tx.txid()).collect();
        let merkle = merkle_root(&txids);
        let coinbase_txid = txids[0];

        let header = BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_735_171_200 + height, // dev default: 2025-12-25 + height seconds
            bits,
            nonce: 0,
        };

        let mined = if parallel {
            match mine_header_parallel(&header, 0..u32::MAX as u64) {
                Some(h) => Some(h),
                None => {
                    eprintln!(
                        "parallel mining unavailable or no nonce found; falling back to serial"
                    );
                    mine_header_serial(header.clone(), 0, u32::MAX as u64)
                }
            }
        } else {
            mine_header_serial(header.clone(), 0, u32::MAX as u64)
        };

        let header = mined.expect("no valid nonce found in range");
        prev_hash = header.hash();
        prev_coin_value = subsidy
            + if claim_fees && do_spends {
                fee_for_block
            } else {
                0
            };
        prev_coin_outpoint = Some(OutPoint {
            txid: coinbase_txid,
            vout: 0,
        });

        // Record coinbase UTXO for next block's spend
        utxos.push((
            prev_coin_outpoint.as_ref().cloned().unwrap(),
            Prevout::regular(prev_coin_value, p2qpkh_spk.clone()),
        ));
        // Track coinbase key used this height for next spend
        last_coin_pk_ser = current_pk_ser.clone();
        last_coin_spk = p2qpkh_spk.clone();
        last_coin_sk = current_sk_bytes.clone();

        // Build block object for validation
        let block = Block {
            header: header.clone(),
            txdata: txs.clone(),
        };

        // MTP is 0 since all transactions in this CLI tool are final
        // (lock_time=0 and all inputs have sequence=0xffffffff)
        validate_block_basic(
            &block,
            &prevouts_for_block,
            WEIGHT_FLOOR_WU,
            WEIGHT_FLOOR_WU,
            true,
            height,
            0,               // MTP not needed for final transactions
            Network::Devnet, // Use devnet for CLI tool (most permissive)
            |_| 0,           // No MTP lookup needed for final transactions
        )
        .expect("block validation failed");

        #[cfg(feature = "cli-vectors")]
        {
            if let Some(path) = emit_vectors.as_ref()
                && height > 0
                && do_spends
            {
                let spend = &txs[1];
                let spend_prevouts = &prevouts_for_block[1];
                let sighash_type = 0x01u8;
                let msg = qpb_sighash(spend, 0, spend_prevouts, sighash_type, 0x00, None)
                    .expect("sighash");
                let sig = &spend.vin[0].witness[0]; // sig_ser (sig||sighash_type)
                let pkser = &spend.vin[0].witness[1];
                #[derive(Serialize)]
                struct Vector<'a> {
                    height: u32,
                    txid: String,
                    pk_ser: String,
                    sig_ser: String,
                    msg32: String,
                    force_slh: bool,
                    path: &'a str,
                }
                let vector = Vector {
                    height,
                    txid: hex::encode(spend.txid()),
                    pk_ser: hex::encode(pkser),
                    sig_ser: hex::encode(sig),
                    msg32: hex::encode(msg),
                    force_slh,
                    path,
                };
                std::fs::write(path, serde_json::to_string_pretty(&vector).unwrap())
                    .expect("write vector");
            }
        }

        println!(
            "height={} nonce={} block_hash={} merkle={} subsidy={} txs={} fee_claimed={} targets={} burn_spend={} witness_only={}{}",
            height,
            header.nonce,
            hex::encode(prev_hash),
            hex::encode(merkle),
            subsidy,
            txs.len(),
            claim_fees && do_spends,
            target_count,
            burn_spend,
            witness_only,
            if let Some(p) = emit_vectors.as_ref() {
                format!(" vectors={}", p)
            } else {
                "".to_string()
            }
        );
    }
}
