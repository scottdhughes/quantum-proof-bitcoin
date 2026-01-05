use std::fs;
use std::path::Path;

use qpb_consensus::hashing::hash256;
use qpb_consensus::pow::{bits_to_target, pow_hash};
use qpb_consensus::types::{BlockHeader, OutPoint, Transaction, TxIn, TxOut};

use hex::ToHex;
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const DERIVATION: &str = "CHAIN_ID = HASH256(SerializeBlockHeader(genesis_header))";
const GENESIS_TIME: u32 = 1_766_620_800; // 2025-12-25 00:00:00 UTC
const GENESIS_VERSION: u32 = 1;
const GENESIS_BITS: u32 = 0x207f_ffff;

#[derive(Serialize)]
struct ChainParams {
    schema_version: u32,
    chain_id_derivation: &'static str,
    networks: Networks,
}

#[derive(Serialize)]
struct Networks {
    devnet: Network,
    regtest: Network,
    testnet: Network,
}

#[derive(Serialize)]
struct Network {
    name: String,
    hrp: String,
    p2p_magic: String,
    p2p_port: u16,
    rpc_port: u16,
    dns_seeds: Vec<String>,
    genesis: Genesis,
}

#[derive(Serialize)]
struct Genesis {
    coinbase_tx_hex: String,
    header: HeaderJson,
    block_hash_hex: String,
    chain_id_hex: String,
}

#[derive(Serialize)]
struct HeaderJson {
    version: u32,
    prev_blockhash_hex: String,
    merkle_root_hex: String,
    time: u32,
    bits: u32,
    nonce: u32,
}

fn main() -> anyhow::Result<()> {
    let devnet = build_network(
        "devnet",
        "qpb",
        38_333,
        38_332,
        "QPB devnet genesis 2025-12-25",
    )?;
    let regtest = build_network(
        "regtest",
        "qpbreg",
        38_444,
        38_443,
        "QPB regtest genesis 2025-12-25",
    )?;

    let testnet = build_network(
        "testnet",
        "tqpb",
        38_334,
        38_335,
        "QPB testnet genesis 2025-12-25",
    )?;

    let params = ChainParams {
        schema_version: SCHEMA_VERSION,
        chain_id_derivation: DERIVATION,
        networks: Networks {
            devnet,
            regtest,
            testnet,
        },
    };

    let out_path = Path::new("docs/chain/chainparams.json");
    if let Some(dir) = out_path.parent() {
        fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(&params)?;
    fs::write(out_path, json)?;
    println!("Wrote {}", out_path.display());
    Ok(())
}

fn build_network(
    name: &str,
    hrp: &str,
    p2p_port: u16,
    rpc_port: u16,
    coinbase_msg: &str,
) -> anyhow::Result<Network> {
    let magic = derive_magic(name);
    let genesis = build_genesis_block(coinbase_msg)?;

    Ok(Network {
        name: name.to_string(),
        hrp: hrp.to_string(),
        p2p_magic: magic,
        p2p_port,
        rpc_port,
        dns_seeds: vec![],
        genesis,
    })
}

fn derive_magic(name: &str) -> String {
    let hash = hash256(format!("QPB:{name}").as_bytes());
    hex::encode_upper(&hash[..4])
}

fn build_genesis_block(coinbase_msg: &str) -> anyhow::Result<Genesis> {
    let coinbase_tx = build_coinbase_tx(coinbase_msg);
    let txid = coinbase_tx.txid();
    let merkle_root = txid;

    let mut header = BlockHeader {
        version: GENESIS_VERSION,
        prev_blockhash: [0u8; 32],
        merkle_root,
        time: GENESIS_TIME,
        bits: GENESIS_BITS,
        nonce: 0,
    };

    let target = bits_to_target(GENESIS_BITS).expect("valid bits");
    let mut block_hash = pow_hash(&header)?;
    while block_hash > target {
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce overflow"))?;
        block_hash = pow_hash(&header)?;
    }

    let chain_id = hash256(&header.serialize());

    let header_json = HeaderJson {
        version: header.version,
        prev_blockhash_hex: header.prev_blockhash.encode_hex::<String>(),
        merkle_root_hex: merkle_root.encode_hex::<String>(),
        time: header.time,
        bits: header.bits,
        nonce: header.nonce,
    };

    Ok(Genesis {
        coinbase_tx_hex: hex::encode(coinbase_tx.serialize(true)),
        header: header_json,
        block_hash_hex: block_hash.encode_hex::<String>(),
        chain_id_hex: chain_id.encode_hex::<String>(),
    })
}

fn build_coinbase_tx(msg: &str) -> Transaction {
    let script_sig = msg.as_bytes().to_vec();
    let txin = TxIn {
        prevout: OutPoint {
            txid: [0u8; 32],
            vout: u32::MAX,
        },
        script_sig,
        sequence: 0xffff_ffff,
        witness: vec![],
    };
    // Burn the subsidy: OP_RETURN
    let txout = TxOut {
        value: 0,
        script_pubkey: vec![0x6a],
    };
    Transaction {
        version: 1,
        vin: vec![txin],
        vout: vec![txout],
        lock_time: 0,
    }
}
