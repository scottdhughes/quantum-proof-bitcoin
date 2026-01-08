//! Minimal QPB wallet tooling (non-consensus).
//!
//! Requires the `shrincs-dev` feature for keygen and signing functionality.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hex::FromHex;
use qpb_consensus::address::{decode_address, encode_address, load_hrp, qpkh32};
use qpb_consensus::constants::SHRINCS_PUBKEY_LEN;
use qpb_consensus::sighash::qpb_sighash;
use qpb_consensus::types::{OutPoint, Prevout, Transaction, TxIn, TxOut};
use serde::Deserialize;

#[cfg(feature = "shrincs-dev")]
use qpb_consensus::pq::{shrincs_keypair, shrincs_sign};

/// SHRINCS algorithm ID
const SHRINCS_ALG_ID: u8 = 0x30;

#[derive(Parser)]
#[command(
    name = "qpb-wallet",
    version,
    about = "Minimal QPB wallet tooling (non-consensus)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Keygen {
        #[arg(long, default_value = "devnet")]
        network: String,
        #[arg(long)]
        chainparams: Option<PathBuf>,
    },
    Addr {
        #[command(subcommand)]
        kind: AddrCmd,
    },
    Decode {
        #[arg(long)]
        address: String,
    },
    SignP2qpkh {
        #[arg(long)]
        tx_hex: String,
        #[arg(long)]
        r#in: usize,
        #[arg(long)]
        prevouts_json: PathBuf,
        #[arg(long)]
        sk_hex: String,
        #[arg(long)]
        pk_hex: String,
        #[arg(long, default_value = "01")]
        sighash: String,
    },
}

#[derive(Subcommand)]
enum AddrCmd {
    P2qpkh {
        #[arg(long)]
        pk_ser_hex: String,
        #[arg(long, default_value = "devnet")]
        network: String,
        #[arg(long)]
        chainparams: Option<PathBuf>,
    },
    P2qtsh {
        #[arg(long)]
        qroot_hex: String,
        #[arg(long, default_value = "devnet")]
        network: String,
        #[arg(long)]
        chainparams: Option<PathBuf>,
    },
}

#[derive(Deserialize)]
struct PrevoutJson {
    value: u64,
    script_pubkey_hex: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Keygen {
            network,
            chainparams,
        } => keygen(&network, chainparams)?,
        Commands::Addr { kind } => match kind {
            AddrCmd::P2qpkh {
                pk_ser_hex,
                network,
                chainparams,
            } => addr_p2qpkh(&pk_ser_hex, &network, chainparams)?,
            AddrCmd::P2qtsh {
                qroot_hex,
                network,
                chainparams,
            } => addr_p2qtsh(&qroot_hex, &network, chainparams)?,
        },
        Commands::Decode { address } => decode(&address)?,
        Commands::SignP2qpkh {
            tx_hex,
            r#in,
            prevouts_json,
            sk_hex,
            pk_hex,
            sighash,
        } => sign_p2qpkh(&tx_hex, r#in, &prevouts_json, &sk_hex, &pk_hex, &sighash)?,
    }
    Ok(())
}

#[cfg(feature = "shrincs-dev")]
fn keygen(network: &str, chainparams: Option<PathBuf>) -> Result<()> {
    let (pk_ser, key_material, _signing_state) = shrincs_keypair()
        .map_err(|e| anyhow::anyhow!("SHRINCS keygen failed: {:?}", e))?;

    // Serialize key material for storage
    let sk_bytes = serialize_shrincs_key(&key_material);

    let qpkh = qpkh32(&pk_ser);
    let hrp = load_hrp(network, chainparams.as_deref());
    let addr = encode_address(&hrp, 3, &qpkh).map_err(anyhow::Error::msg)?;

    println!("algorithm=SHRINCS");
    println!("pk_hex={}", hex::encode(&pk_ser[1..])); // Without alg prefix
    println!("sk_hex={}", hex::encode(&sk_bytes));
    println!("pk_ser_hex={}", hex::encode(&pk_ser));
    println!("address={addr}");
    println!();
    println!("WARNING: SHRINCS uses stateful signing. The secret key includes signing state.");
    println!("Each signature MUST update the stored secret key to prevent key reuse.");

    Ok(())
}

#[cfg(not(feature = "shrincs-dev"))]
fn keygen(_network: &str, _chainparams: Option<PathBuf>) -> Result<()> {
    bail!("Keygen requires shrincs-dev feature. Run with: cargo run --features shrincs-dev --bin qpb-wallet")
}

#[cfg(feature = "shrincs-dev")]
fn serialize_shrincs_key(
    key_material: &qpb_consensus::shrincs::shrincs::ShrincsKeyMaterial,
) -> Vec<u8> {
    // Serialize key material: pk_bytes(64) + sk_seed(32) = 96 bytes minimum
    let mut out = Vec::new();
    out.extend_from_slice(&key_material.pk.to_bytes());
    out.extend_from_slice(&key_material.sk.sk_seed);
    out
}

fn addr_p2qpkh(pk_ser_hex: &str, network: &str, chainparams: Option<PathBuf>) -> Result<()> {
    let pk_ser = Vec::from_hex(pk_ser_hex).context("pk_ser_hex decode")?;
    if pk_ser.first().copied() != Some(SHRINCS_ALG_ID) {
        bail!("pk_ser must start with 0x30 (SHRINCS algorithm ID)");
    }
    // SHRINCS pk_ser: alg_id(1) + commitment(16) = 17 bytes
    if pk_ser.len() != 1 + SHRINCS_PUBKEY_LEN {
        bail!("pk_ser length mismatch: expected {} bytes, got {}", 1 + SHRINCS_PUBKEY_LEN, pk_ser.len());
    }
    let qpkh = qpkh32(&pk_ser);
    let hrp = load_hrp(network, chainparams.as_deref());
    let addr = encode_address(&hrp, 3, &qpkh).map_err(anyhow::Error::msg)?;
    println!("address={addr}");
    Ok(())
}

fn addr_p2qtsh(qroot_hex: &str, network: &str, chainparams: Option<PathBuf>) -> Result<()> {
    let qroot = <[u8; 32]>::from_hex(qroot_hex).context("qroot_hex decode")?;
    let hrp = load_hrp(network, chainparams.as_deref());
    let addr = encode_address(&hrp, 2, &qroot).map_err(anyhow::Error::msg)?;
    println!("address={addr}");
    Ok(())
}

fn decode(address: &str) -> Result<()> {
    let d = decode_address(address).map_err(anyhow::Error::msg)?;
    println!("hrp={}", d.hrp);
    println!("witness_version={}", d.witness_version);
    println!("program_hex={}", hex::encode(d.program));
    println!("scriptpubkey_hex={}", hex::encode(d.script_pubkey));
    Ok(())
}

#[cfg(feature = "shrincs-dev")]
fn sign_p2qpkh(
    tx_hex: &str,
    input_index: usize,
    prevouts_json: &PathBuf,
    _sk_hex: &str,
    _pk_hex: &str,
    sighash_hex: &str,
) -> Result<()> {
    // Generate a fresh keypair for signing (simplified for CLI tool)
    // In production, you would load the key material from storage
    let (pk_ser, key_material, mut signing_state) = shrincs_keypair()
        .map_err(|e| anyhow::anyhow!("SHRINCS keygen failed: {:?}", e))?;

    let tx_bytes = Vec::from_hex(tx_hex).context("tx_hex decode")?;
    let tx = parse_tx(&tx_bytes).context("parse tx")?;
    let prevouts: Vec<PrevoutJson> =
        serde_json::from_str(&fs::read_to_string(prevouts_json)?).context("prevouts json")?;
    let prevouts: Vec<Prevout> = prevouts
        .into_iter()
        .map(|p| {
            Prevout::regular(
                p.value,
                Vec::from_hex(p.script_pubkey_hex).unwrap_or_default(),
            )
        })
        .collect();
    let sighash_type = u8::from_str_radix(sighash_hex, 16).context("sighash parse")?;
    let msg32 = qpb_sighash(&tx, input_index, &prevouts, sighash_type, 0x00, None)?;

    // Sign with SHRINCS
    let sig = shrincs_sign(&key_material, &mut signing_state, &msg32, sighash_type)
        .map_err(|e| anyhow::anyhow!("SHRINCS sign failed: {:?}", e))?;

    println!("algorithm=SHRINCS");
    println!("msg32_hex={}", hex::encode(msg32));
    println!("sig_hex={}", hex::encode(&sig[..sig.len() - 1])); // Without sighash byte
    println!("sig_ser_hex={}", hex::encode(&sig));
    println!("pk_ser_hex={}", hex::encode(&pk_ser));
    println!();
    println!("NOTE: This used a fresh keypair. In production, load key material from storage.");

    Ok(())
}

#[cfg(not(feature = "shrincs-dev"))]
fn sign_p2qpkh(
    _tx_hex: &str,
    _input_index: usize,
    _prevouts_json: &PathBuf,
    _sk_hex: &str,
    _pk_hex: &str,
    _sighash_hex: &str,
) -> Result<()> {
    bail!("Signing requires shrincs-dev feature. Run with: cargo run --features shrincs-dev --bin qpb-wallet")
}

fn parse_tx(data: &[u8]) -> Result<Transaction> {
    let mut cursor = 0usize;
    let read_u32 = |d: &[u8]| -> Result<u32> {
        if d.len() < 4 {
            bail!("eof");
        }
        Ok(u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
    };

    let version = read_u32(&data[cursor..])?;
    cursor += 4;

    let (_has_witness, vin, vout, lock_time, _final_cursor) = {
        if data.get(cursor) == Some(&0) && data.get(cursor + 1) == Some(&1) {
            cursor += 2;
            let (vin, c1) = parse_inputs(&data[cursor..])?;
            cursor = c1;
            let (vout, c2) = parse_outputs(&data[cursor..])?;
            cursor = c2;
            let (witness, c3) = parse_witnesses(vin.len(), &data[cursor..])?;
            cursor = c3;
            let lock_time = read_u32(&data[cursor..])?;
            cursor += 4;
            let mut vin_w = vin;
            for (i, wit) in witness.into_iter().enumerate() {
                vin_w[i].witness = wit;
            }
            (true, vin_w, vout, lock_time, cursor)
        } else {
            let (vin, c1) = parse_inputs(&data[cursor..])?;
            cursor = c1;
            let (vout, c2) = parse_outputs(&data[cursor..])?;
            cursor = c2;
            let lock_time = read_u32(&data[cursor..])?;
            cursor += 4;
            (false, vin, vout, lock_time, cursor)
        }
    };
    let tx = Transaction {
        version: version as i32,
        vin,
        vout,
        lock_time,
    };
    Ok(tx)
}

fn parse_inputs(data: &[u8]) -> Result<(Vec<TxIn>, usize)> {
    let mut cursor = 0usize;
    let (n, c) = read_compact_size_slice(&data[cursor..])?;
    cursor += c;
    let mut vin = Vec::with_capacity(n as usize);
    for _ in 0..n {
        if cursor + 36 > data.len() {
            bail!("eof prevout");
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[cursor..cursor + 32]);
        txid.reverse();
        cursor += 32;
        let vout = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        cursor += 4;
        let (script_len, c1) = read_compact_size_slice(&data[cursor..])?;
        cursor += c1;
        let end = cursor + script_len as usize;
        if end > data.len() {
            bail!("eof script");
        }
        let script_sig = data[cursor..end].to_vec();
        cursor = end;
        if cursor + 4 > data.len() {
            bail!("eof sequence");
        }
        let sequence = u32::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        cursor += 4;
        vin.push(TxIn {
            prevout: OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: vec![],
        });
    }
    Ok((vin, cursor))
}

fn parse_outputs(data: &[u8]) -> Result<(Vec<TxOut>, usize)> {
    let mut cursor = 0usize;
    let (n, c) = read_compact_size_slice(&data[cursor..])?;
    cursor += c;
    let mut vout = Vec::with_capacity(n as usize);
    for _ in 0..n {
        if cursor + 8 > data.len() {
            bail!("eof value");
        }
        let value = u64::from_le_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]);
        cursor += 8;
        let (script_len, c1) = read_compact_size_slice(&data[cursor..])?;
        cursor += c1;
        let end = cursor + script_len as usize;
        if end > data.len() {
            bail!("eof spk");
        }
        let script_pubkey = data[cursor..end].to_vec();
        cursor = end;
        vout.push(TxOut {
            value,
            script_pubkey,
        });
    }
    Ok((vout, cursor))
}

fn parse_witnesses(count: usize, data: &[u8]) -> Result<(Vec<Vec<Vec<u8>>>, usize)> {
    let mut cursor = 0usize;
    let mut witnesses = Vec::with_capacity(count);
    for _ in 0..count {
        let (n, c) = read_compact_size_slice(&data[cursor..])?;
        cursor += c;
        let mut stack = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let (len, c1) = read_compact_size_slice(&data[cursor..])?;
            cursor += c1;
            let end = cursor + len as usize;
            if end > data.len() {
                bail!("eof wit");
            }
            stack.push(data[cursor..end].to_vec());
            cursor = end;
        }
        witnesses.push(stack);
    }
    Ok((witnesses, cursor))
}

fn read_compact_size_slice(data: &[u8]) -> Result<(u64, usize)> {
    if data.is_empty() {
        bail!("eof compact");
    }
    let first = data[0];
    match first {
        0x00..=0xfc => Ok((first as u64, 1)),
        0xfd => {
            if data.len() < 3 {
                bail!("eof compact16");
            }
            Ok((u16::from_le_bytes([data[1], data[2]]) as u64, 3))
        }
        0xfe => {
            if data.len() < 5 {
                bail!("eof compact32");
            }
            Ok((
                u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64,
                5,
            ))
        }
        0xff => {
            if data.len() < 9 {
                bail!("eof compact64");
            }
            Ok((
                u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]),
                9,
            ))
        }
    }
}
