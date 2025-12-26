use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use hex::ToHex;
use pqcrypto_dilithium::dilithium3::{detached_sign, keypair, verify_detached_signature};
use pqcrypto_traits::sign::{DetachedSignature as SigTrait, PublicKey as PKTrait};
use qpb_consensus::constants::{MAX_PQSIGCHECK_BUDGET, MAX_PQSIGCHECK_PER_TX};
use qpb_consensus::pq::{AlgorithmId, verify_pq};
use qpb_consensus::sighash::qpb_sighash;
use qpb_consensus::types::{OutPoint, Prevout, Transaction, TxIn, TxOut};

#[derive(Parser, Debug)]
#[command(
    name = "bench_perf",
    about = "Deterministic perf harness for PQ verify and sighash"
)]
struct Args {
    #[arg(long, default_value_t = 2000)]
    iters: u64,
    #[arg(long, default_value_t = 200)]
    warmup: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();
    println!("iters={} warmup={}", args.iters, args.warmup);

    // Deterministic key/sig/msg.
    let (pk, sk) = keypair();
    let msg = [0u8; 32];
    let sig = detached_sign(&msg, &sk);
    let pk_bytes = pk.as_bytes().to_vec();
    let sig_bytes = sig.as_bytes().to_vec();

    // Sample tx + prevouts for sighash bench.
    let bench_tx = build_sample_tx(&pk_bytes);
    let prevouts = sample_prevouts(&pk_bytes);
    let sighash_type: u8 = 0x01;
    let msg32_sighash = qpb_sighash(&bench_tx, 0, &prevouts, sighash_type, 0x00, None)?;

    bench(
        "MLDSA verify (raw pqcrypto)",
        args.warmup,
        args.iters,
        || verify_detached_signature(&sig, &msg, &pk).unwrap(),
    );

    bench(
        "MLDSA verify (consensus path)",
        args.warmup,
        args.iters,
        || verify_pq(AlgorithmId::MLDSA65, &pk_bytes, &msg, &sig_bytes).unwrap(),
    );

    bench(
        "QPB sighash (P2QPKH 1-in-2-out)",
        args.warmup,
        args.iters,
        || {
            qpb_sighash(&bench_tx, 0, &prevouts, sighash_type, 0x00, None).unwrap();
        },
    );

    // Derived budget guidance (no consensus change).
    let ns_total = bench_once(
        || verify_pq(AlgorithmId::MLDSA65, &pk_bytes, &msg, &sig_bytes).unwrap(),
        args.warmup,
        args.iters,
    );
    let ns_per = ns_total / args.iters as f64;
    let per_block = (ns_per * MAX_PQSIGCHECK_BUDGET as f64) / 1e9;
    let per_tx = (ns_per * MAX_PQSIGCHECK_PER_TX as f64) / 1e9;
    println!(
        "Derived (ns/verify = {:.1}): block budget {:.4} s, tx budget {:.4} s",
        ns_per, per_block, per_tx
    );
    println!(
        "sample sighash msg32={}",
        msg32_sighash.encode_hex::<String>()
    );

    Ok(())
}

fn bench<F: FnMut()>(label: &str, warmup: u64, iters: u64, mut f: F) {
    for _ in 0..warmup {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = start.elapsed();
    let ns = elapsed.as_nanos() as f64;
    let ns_per = ns / iters as f64;
    let ops_sec = 1_000_000_000.0 / ns_per;
    println!(
        "{label}: total {:.3}s, {:.1} ns/op ({:.2} ops/sec)",
        ns / 1e9,
        ns_per,
        ops_sec
    );
}

fn bench_once<F: FnMut()>(mut f: F, warmup: u64, iters: u64) -> f64 {
    for _ in 0..warmup {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_nanos() as f64
}

fn build_sample_tx(pk_bytes: &[u8]) -> Transaction {
    let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
    pk_ser.push(0x11);
    pk_ser.extend_from_slice(pk_bytes);
    let qpkh = qpb_consensus::address::qpkh32(&pk_ser);
    let spk = build_spk_v3(&qpkh);

    let txin = TxIn {
        prevout: OutPoint {
            txid: [0u8; 32],
            vout: 0,
        },
        script_sig: vec![],
        sequence: 0xffff_fffe,
        witness: vec![],
    };
    let txout1 = TxOut {
        value: 49_0000_0000,
        script_pubkey: spk.clone(),
    };
    let txout2 = TxOut {
        value: 1_0000_0000,
        script_pubkey: spk,
    };
    Transaction {
        version: 1,
        vin: vec![txin],
        vout: vec![txout1, txout2],
        lock_time: 0,
    }
}

fn sample_prevouts(pk_bytes: &[u8]) -> Vec<Prevout> {
    let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
    pk_ser.push(0x11);
    pk_ser.extend_from_slice(pk_bytes);
    let qpkh = qpb_consensus::address::qpkh32(&pk_ser);
    let spk = build_spk_v3(&qpkh);
    vec![Prevout {
        value: 50_0000_0000,
        script_pubkey: spk,
    }]
}

fn build_spk_v3(prog: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x53); // OP_3
    spk.push(0x20);
    spk.extend_from_slice(prog);
    spk
}
