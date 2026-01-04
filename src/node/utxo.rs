use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::types::Prevout;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UtxoEntry {
    value: u64,
    script_pubkey: Vec<u8>,
    /// Block height at which this output was created.
    height: u32,
    /// True if this output is from a coinbase transaction.
    is_coinbase: bool,
}

#[derive(Debug, Default)]
pub struct UtxoSet {
    map: BTreeMap<String, UtxoEntry>,
}

impl UtxoSet {
    pub fn load(datadir: &Path) -> Result<Self> {
        let path = datadir.join("utxo.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let map: BTreeMap<String, UtxoEntry> = serde_json::from_reader(fs::File::open(&path)?)?;
        Ok(Self { map })
    }

    pub fn save(&self, datadir: &Path) -> Result<()> {
        let path = datadir.join("utxo.json");
        let data = serde_json::to_vec_pretty(&self.map)?;
        fs::write(path, data)?;
        Ok(())
    }

    pub fn get(&self, txid: &[u8; 32], vout: u32) -> Option<Prevout> {
        let key = key_for(txid, vout);
        self.map.get(&key).map(|e| Prevout {
            value: e.value,
            script_pubkey: e.script_pubkey.clone(),
            height: e.height,
            is_coinbase: e.is_coinbase,
        })
    }

    pub fn remove(&mut self, txid: &[u8; 32], vout: u32) {
        let key = key_for(txid, vout);
        self.map.remove(&key);
    }

    pub fn insert(
        &mut self,
        txid: &[u8; 32],
        vout: u32,
        value: u64,
        script_pubkey: Vec<u8>,
        height: u32,
        is_coinbase: bool,
    ) {
        let key = key_for(txid, vout);
        self.map.insert(
            key,
            UtxoEntry {
                value,
                script_pubkey,
                height,
                is_coinbase,
            },
        );
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate over all UTXOs in the set.
    /// Returns (txid_hex, vout, Prevout) for each entry.
    pub fn iter_all(&self) -> Vec<(String, u32, Prevout)> {
        self.map
            .iter()
            .filter_map(|(key, entry)| {
                let parts: Vec<&str> = key.split(':').collect();
                if parts.len() != 2 {
                    return None;
                }
                let txid_hex = parts[0].to_string();
                let vout: u32 = parts[1].parse().ok()?;
                Some((
                    txid_hex,
                    vout,
                    Prevout {
                        value: entry.value,
                        script_pubkey: entry.script_pubkey.clone(),
                        height: entry.height,
                        is_coinbase: entry.is_coinbase,
                    },
                ))
            })
            .collect()
    }
}

fn key_for(txid: &[u8; 32], vout: u32) -> String {
    format!("{}:{}", hex::encode(txid), vout)
}
