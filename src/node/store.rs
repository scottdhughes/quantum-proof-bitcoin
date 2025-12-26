use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeState {
    pub chain: String,
    pub height: u64,
    pub tip_hash_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockIndex {
    pub hashes: Vec<String>, // index by height
}

pub struct Store {
    pub datadir: PathBuf,
    pub state: NodeState,
    pub index: BlockIndex,
}

impl Store {
    pub fn open_or_init(datadir: &Path, chain: &str, genesis_hash_hex: &str) -> Result<Self> {
        fs::create_dir_all(datadir)?;
        let state_path = datadir.join("state.json");
        let index_path = datadir.join("index.json");

        if state_path.exists() && index_path.exists() {
            let state: NodeState =
                serde_json::from_reader(fs::File::open(&state_path).context("open state.json")?)?;
            let index: BlockIndex =
                serde_json::from_reader(fs::File::open(&index_path).context("open index.json")?)?;
            return Ok(Self {
                datadir: datadir.to_path_buf(),
                state,
                index,
            });
        }

        let state = NodeState {
            chain: chain.to_string(),
            height: 0,
            tip_hash_hex: genesis_hash_hex.to_string(),
        };
        let index = BlockIndex {
            hashes: vec![genesis_hash_hex.to_string()],
        };
        write_state(datadir, &state, &index)?;
        Ok(Self {
            datadir: datadir.to_path_buf(),
            state,
            index,
        })
    }

    pub fn tip_hash(&self) -> &str {
        &self.state.tip_hash_hex
    }

    pub fn height(&self) -> u64 {
        self.state.height
    }

    pub fn chain(&self) -> &str {
        &self.state.chain
    }
}

fn write_state(datadir: &Path, state: &NodeState, index: &BlockIndex) -> Result<()> {
    let state_path = datadir.join("state.json");
    let index_path = datadir.join("index.json");
    fs::write(&state_path, serde_json::to_vec_pretty(state)?)?;
    fs::write(&index_path, serde_json::to_vec_pretty(index)?)?;
    Ok(())
}
