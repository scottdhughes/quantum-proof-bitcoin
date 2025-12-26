use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use hex::FromHex;
use pqcrypto_dilithium::dilithium3::{
    SecretKey, detached_sign, keypair, public_key_bytes, secret_key_bytes,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SigTrait, PublicKey as PKTrait, SecretKey as SKTrait,
};
use qpb_consensus::address::{decode_address, encode_address, load_hrp, qpkh32};
use qpb_consensus::sighash::qpb_sighash;
use qpb_consensus::types::{OutPoint, Prevout, Transaction, TxIn, TxOut};
use serde::Deserialize;

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

fn keygen(network: &str, chainparams: Option<PathBuf>) -> Result<()> {
    let (pk, sk) = keypair();
    let pk_bytes = pk.as_bytes();
    let sk_bytes = sk.as_bytes();
    let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
    pk_ser.push(0x11);
    pk_ser.extend_from_slice(pk_bytes);
    let qpkh = qpkh32(&pk_ser);
    let hrp = load_hrp(network, chainparams.as_deref());
    let addr = encode_address(&hrp, 3, &qpkh).map_err(anyhow::Error::msg)?;
    println!("pk_hex={}", hex::encode(pk_bytes));
    println!("sk_hex={}", hex::encode(sk_bytes));
    println!("pk_ser_hex={}", hex::encode(&pk_ser));
    println!("address={addr}");
    Ok(())
}

fn addr_p2qpkh(pk_ser_hex: &str, network: &str, chainparams: Option<PathBuf>) -> Result<()> {
    let pk_ser = Vec::from_hex(pk_ser_hex).context("pk_ser_hex decode")?;
    if pk_ser.first().copied() != Some(0x11) {
        bail!("pk_ser must start with 0x11");
    }
    if pk_ser.len() != 1 + public_key_bytes() {
        bail!("pk_ser length mismatch");
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

fn sign_p2qpkh(
    tx_hex: &str,
    input_index: usize,
    prevouts_json: &PathBuf,
    sk_hex: &str,
    pk_hex: &str,
    sighash_hex: &str,
) -> Result<()> {
    let tx_bytes = Vec::from_hex(tx_hex).context("tx_hex decode")?;
    let tx = parse_tx(&tx_bytes).context("parse tx")?;
    let prevouts: Vec<PrevoutJson> =
        serde_json::from_str(&fs::read_to_string(prevouts_json)?).context("prevouts json")?;
    let prevouts: Vec<Prevout> = prevouts
        .into_iter()
        .map(|p| Prevout {
            value: p.value,
            script_pubkey: Vec::from_hex(p.script_pubkey_hex).unwrap_or_default(),
        })
        .collect();
    let sighash_type = u8::from_str_radix(sighash_hex, 16).context("sighash parse")?;
    let msg32 = qpb_sighash(&tx, input_index, &prevouts, sighash_type, 0x00, None)?;
    let sk_bytes = Vec::from_hex(sk_hex).context("sk_hex decode")?;
    if sk_bytes.len() != secret_key_bytes() {
        bail!("sk length mismatch");
    }
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let sig = detached_sign(&msg32, &sk);
    let sig_bytes = sig.as_bytes();
    let mut sig_ser = Vec::with_capacity(sig_bytes.len() + 1);
    sig_ser.extend_from_slice(sig_bytes);
    sig_ser.push(sighash_type);

    let pk_bytes = Vec::from_hex(pk_hex).context("pk_hex decode")?;
    if pk_bytes.len() != public_key_bytes() {
        bail!("pk length mismatch");
    }
    let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
    pk_ser.push(0x11);
    pk_ser.extend_from_slice(&pk_bytes);

    println!("msg32_hex={}", hex::encode(msg32));
    println!("sig_hex={}", hex::encode(sig_bytes));
    println!("sig_ser_hex={}", hex::encode(&sig_ser));
    println!("pk_ser_hex={}", hex::encode(pk_ser));
    Ok(())
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
