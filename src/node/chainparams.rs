use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

use crate::hashing::hash256;
use crate::pow::pow_hash;
use crate::types::BlockHeader;

#[derive(Debug, Deserialize, Clone)]
pub struct ChainParamsFile {
    pub networks: Networks,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Networks {
    pub devnet: Option<NetworkParams>,
    pub regtest: Option<NetworkParams>,
    pub testnet: Option<NetworkParams>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkParams {
    pub name: String,
    pub hrp: String,
    pub p2p_magic: String,
    pub p2p_port: u16,
    pub rpc_port: u16,
    /// DNS seed hostnames for peer discovery.
    #[serde(default)]
    pub dns_seeds: Vec<String>,
    pub genesis: Option<GenesisParams>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GenesisParams {
    pub coinbase_tx_hex: String,
    pub header: GenesisHeader,
    pub block_hash_hex: String,
    pub chain_id_hex: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GenesisHeader {
    pub version: u32,
    pub prev_blockhash_hex: String,
    pub merkle_root_hex: String,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

pub fn load_chainparams(path: &Path) -> Result<ChainParamsFile> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("reading chainparams {}", path.display()))?;
    Ok(serde_json::from_str(&data)?)
}

pub fn select_network<'a>(params: &'a ChainParamsFile, chain: &str) -> Result<&'a NetworkParams> {
    let net = match chain {
        "devnet" => params.networks.devnet.as_ref(),
        "regtest" => params.networks.regtest.as_ref(),
        "testnet" => params.networks.testnet.as_ref(),
        _ => None,
    };
    net.ok_or_else(|| anyhow!("network {} not found in chainparams", chain))
}

pub fn compute_genesis_hash(header: &GenesisHeader) -> Result<[u8; 32]> {
    let bh = to_block_header(header)?;
    Ok(pow_hash(&bh)?)
}

pub fn compute_chain_id(header: &GenesisHeader) -> Result<[u8; 32]> {
    let bh = to_block_header(header)?;
    Ok(hash256(&bh.serialize()))
}

pub fn to_block_header(h: &GenesisHeader) -> Result<BlockHeader> {
    Ok(BlockHeader {
        version: h.version,
        prev_blockhash: hex_to32(&h.prev_blockhash_hex)?,
        merkle_root: hex_to32(&h.merkle_root_hex)?,
        time: h.time,
        bits: h.bits,
        nonce: h.nonce,
    })
}

fn hex_to32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("hex decode {}: {}", s, e))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32-byte hex, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
