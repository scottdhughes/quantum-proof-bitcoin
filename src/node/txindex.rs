//! Transaction index for QPB.
//!
//! Maintains a txid -> (block_hash, tx_position) mapping for confirmed transactions.
//! Supports efficient transaction lookup by txid for getrawtransaction RPC.
//!
//! The index is optional and must be enabled via `--txindex` CLI flag or config.
//! When enabled, all confirmed transactions are indexed on block connect and
//! removed on block disconnect (reorg handling).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Transaction location in a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxLocation {
    /// Block hash where transaction is confirmed (hex string).
    pub block_hash: String,
    /// Transaction position within the block (0 = coinbase).
    pub tx_position: u32,
}

/// Transaction index for looking up confirmed transactions.
#[derive(Debug)]
pub struct TxIndex {
    /// Map from txid (hex) to transaction location.
    index: BTreeMap<String, TxLocation>,
    /// Whether the index is enabled.
    enabled: bool,
}

impl Default for TxIndex {
    fn default() -> Self {
        Self::new_disabled()
    }
}

impl TxIndex {
    /// Create a new disabled index.
    pub fn new_disabled() -> Self {
        Self {
            index: BTreeMap::new(),
            enabled: false,
        }
    }

    /// Create a new enabled index.
    pub fn new_enabled() -> Self {
        Self {
            index: BTreeMap::new(),
            enabled: true,
        }
    }

    /// Check if txindex is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Load index from disk. Returns disabled index if not enabled.
    pub fn load(datadir: &Path, enabled: bool) -> Result<Self> {
        if !enabled {
            return Ok(Self::new_disabled());
        }

        let path = datadir.join("txindex.json");
        if !path.exists() {
            return Ok(Self::new_enabled());
        }

        let data = fs::read_to_string(&path)?;
        let index: BTreeMap<String, TxLocation> = serde_json::from_str(&data)?;
        Ok(Self {
            index,
            enabled: true,
        })
    }

    /// Save index to disk.
    pub fn save(&self, datadir: &Path) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let path = datadir.join("txindex.json");
        let data = serde_json::to_vec_pretty(&self.index)?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Get transaction location by txid.
    pub fn get(&self, txid: &[u8; 32]) -> Option<&TxLocation> {
        if !self.enabled {
            return None;
        }
        self.index.get(&hex::encode(txid))
    }

    /// Insert transaction into index.
    pub fn insert(&mut self, txid: &[u8; 32], block_hash: &str, tx_position: u32) {
        if !self.enabled {
            return;
        }
        self.index.insert(
            hex::encode(txid),
            TxLocation {
                block_hash: block_hash.to_string(),
                tx_position,
            },
        );
    }

    /// Remove transaction from index (for reorgs).
    pub fn remove(&mut self, txid: &[u8; 32]) {
        if !self.enabled {
            return;
        }
        self.index.remove(&hex::encode(txid));
    }

    /// Remove all transactions from a specific block (for reorgs).
    pub fn remove_block(&mut self, block_hash: &str) {
        if !self.enabled {
            return;
        }
        self.index.retain(|_, loc| loc.block_hash != block_hash);
    }

    /// Number of indexed transactions.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Check if index is empty.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_disabled_index() {
        let idx = TxIndex::new_disabled();
        assert!(!idx.is_enabled());
        assert_eq!(idx.len(), 0);

        let txid = [1u8; 32];
        assert!(idx.get(&txid).is_none());
    }

    #[test]
    fn test_enabled_index_insert_get() {
        let mut idx = TxIndex::new_enabled();
        assert!(idx.is_enabled());

        let txid = [1u8; 32];
        idx.insert(&txid, "blockhash123", 0);

        let loc = idx.get(&txid).unwrap();
        assert_eq!(loc.block_hash, "blockhash123");
        assert_eq!(loc.tx_position, 0);
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn test_remove_transaction() {
        let mut idx = TxIndex::new_enabled();

        let txid1 = [1u8; 32];
        let txid2 = [2u8; 32];
        idx.insert(&txid1, "block1", 0);
        idx.insert(&txid2, "block1", 1);
        assert_eq!(idx.len(), 2);

        idx.remove(&txid1);
        assert!(idx.get(&txid1).is_none());
        assert!(idx.get(&txid2).is_some());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn test_remove_block() {
        let mut idx = TxIndex::new_enabled();

        let txid1 = [1u8; 32];
        let txid2 = [2u8; 32];
        let txid3 = [3u8; 32];
        idx.insert(&txid1, "block1", 0);
        idx.insert(&txid2, "block1", 1);
        idx.insert(&txid3, "block2", 0);
        assert_eq!(idx.len(), 3);

        idx.remove_block("block1");
        assert!(idx.get(&txid1).is_none());
        assert!(idx.get(&txid2).is_none());
        assert!(idx.get(&txid3).is_some());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();

        // Save
        {
            let mut idx = TxIndex::new_enabled();
            let txid = [42u8; 32];
            idx.insert(&txid, "blockhash", 5);
            idx.save(dir.path()).unwrap();
        }

        // Load
        {
            let idx = TxIndex::load(dir.path(), true).unwrap();
            let txid = [42u8; 32];
            let loc = idx.get(&txid).unwrap();
            assert_eq!(loc.block_hash, "blockhash");
            assert_eq!(loc.tx_position, 5);
        }
    }

    #[test]
    fn test_load_nonexistent() {
        let dir = tempdir().unwrap();
        let idx = TxIndex::load(dir.path(), true).unwrap();
        assert!(idx.is_enabled());
        assert!(idx.is_empty());
    }

    #[test]
    fn test_disabled_no_save() {
        let dir = tempdir().unwrap();
        let idx = TxIndex::new_disabled();
        idx.save(dir.path()).unwrap();

        // Should not create file
        assert!(!dir.path().join("txindex.json").exists());
    }
}
