use std::fs;
use std::path::Path;

use bech32::{self, Variant};
use serde::Deserialize;

use crate::hashing::{hash256, tagged_hash};

const WITNESS_V2: u8 = 2;
const WITNESS_V3: u8 = 3;
const PROG_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAddress {
    pub hrp: String,
    pub witness_version: u8,
    pub program: [u8; PROG_LEN],
    pub script_pubkey: Vec<u8>,
}

#[derive(Deserialize)]
struct ChainParams {
    networks: Networks,
}

#[derive(Deserialize)]
struct Networks {
    devnet: Option<NetworkEntry>,
    regtest: Option<NetworkEntry>,
    testnet: Option<NetworkEntry>,
}

#[derive(Deserialize)]
struct NetworkEntry {
    hrp: String,
}

/// Load HRP for the given network from chainparams.json, falling back to "qpb" if missing.
#[allow(clippy::collapsible_if)]
pub fn load_hrp(network: &str, chainparams_path: Option<&Path>) -> String {
    let path = chainparams_path.unwrap_or_else(|| Path::new("docs/chain/chainparams.json"));
    if let Ok(data) = fs::read_to_string(path) {
        if let Ok(cp) = serde_json::from_str::<ChainParams>(&data) {
            let hrp = match network {
                "devnet" => cp.networks.devnet.map(|n| n.hrp),
                "regtest" => cp.networks.regtest.map(|n| n.hrp),
                "testnet" => cp.networks.testnet.map(|n| n.hrp),
                _ => None,
            };
            if let Some(h) = hrp {
                return h;
            }
        }
    }
    "qpb".to_string()
}

pub fn encode_address(
    hrp: &str,
    witness_version: u8,
    program: &[u8; PROG_LEN],
) -> Result<String, String> {
    if witness_version != WITNESS_V2 && witness_version != WITNESS_V3 {
        return Err("invalid witness version".into());
    }
    let wit = bech32::u5::try_from_u8(witness_version).map_err(|_| "witness version")?;
    let prog5_raw = bech32::convert_bits(program, 8, 5, true).map_err(|_| "convert_bits failed")?;
    let mut data: Vec<bech32::u5> = Vec::with_capacity(1 + prog5_raw.len());
    data.push(wit);
    for b in prog5_raw {
        data.push(bech32::u5::try_from_u8(b).map_err(|_| "convert_bits failed")?);
    }
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.to_string())
}

pub fn decode_address(addr: &str) -> Result<DecodedAddress, String> {
    let (hrp, data, variant) = bech32::decode(addr).map_err(|e| e.to_string())?;
    if variant != Variant::Bech32m {
        return Err("address is not bech32m".into());
    }
    if data.is_empty() {
        return Err("data empty".into());
    }
    let witness_version = data[0];
    let witness_version_u8 = witness_version.to_u8();
    if witness_version_u8 != WITNESS_V2 && witness_version_u8 != WITNESS_V3 {
        return Err("unsupported witness version".into());
    }
    let prog5 = &data[1..];
    let program = bech32::convert_bits(prog5, 5, 8, false).map_err(|_| "convert_bits failed")?;
    if program.len() != PROG_LEN {
        return Err("invalid program length".into());
    }
    let mut program_arr = [0u8; PROG_LEN];
    program_arr.copy_from_slice(&program);
    let mut spk = Vec::with_capacity(2 + PROG_LEN);
    match witness_version_u8 {
        WITNESS_V2 => spk.push(0x52),
        WITNESS_V3 => spk.push(0x53),
        _ => unreachable!(),
    }
    spk.push(0x20);
    spk.extend_from_slice(&program_arr);

    Ok(DecodedAddress {
        hrp,
        witness_version: witness_version_u8,
        program: program_arr,
        script_pubkey: spk,
    })
}

/// Compute qpkh32 = HASH256(TaggedHash("QPB/QPKH", pk_ser)).
pub fn qpkh32(pk_ser: &[u8]) -> [u8; 32] {
    let tagged = tagged_hash("QPB/QPKH", pk_ser);
    hash256(&tagged)
}
