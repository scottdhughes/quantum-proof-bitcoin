//! Chain state management with fork tracking and reorg support.
//!
//! This module manages the block tree, tracks competing chains,
//! and handles chain reorganizations.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::types::Prevout;

/// Block metadata stored in the chain index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMeta {
    /// Block hash (32 bytes, hex encoded for storage).
    pub hash: [u8; 32],
    /// Previous block hash.
    pub prev_hash: [u8; 32],
    /// Block height.
    pub height: u64,
    /// Cumulative chain work (simplified: just height for now).
    /// In production, this would be sum of work from genesis.
    pub cumulative_work: u64,
    /// Block validation status.
    pub status: BlockStatus,
}

/// Block validation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockStatus {
    /// Block header received, not yet validated.
    HeaderOnly,
    /// Block data available, not yet validated.
    DataAvailable,
    /// Block fully validated and connected to chain.
    Valid,
    /// Block failed validation.
    Invalid,
}

/// UTXO undo data for disconnecting a block.
/// Stores the spent outputs that need to be restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoData {
    /// Spent outputs: (txid, vout, value, script_pubkey).
    pub spent_outputs: Vec<SpentOutput>,
}

/// A single spent output for undo purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentOutput {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
    /// Block height at which this output was created.
    pub height: u32,
    /// True if this output is from a coinbase transaction.
    pub is_coinbase: bool,
}

impl UndoData {
    /// Create empty undo data.
    pub fn new() -> Self {
        Self {
            spent_outputs: Vec::new(),
        }
    }

    /// Add a spent output.
    pub fn add_spent(&mut self, txid: [u8; 32], vout: u32, prevout: &Prevout) {
        self.spent_outputs.push(SpentOutput {
            txid,
            vout,
            value: prevout.value,
            script_pubkey: prevout.script_pubkey.clone(),
            height: prevout.height,
            is_coinbase: prevout.is_coinbase,
        });
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simple format: count (4 bytes) + entries
        let mut out = Vec::new();
        let count = self.spent_outputs.len() as u32;
        out.extend_from_slice(&count.to_le_bytes());

        for spent in &self.spent_outputs {
            out.extend_from_slice(&spent.txid);
            out.extend_from_slice(&spent.vout.to_le_bytes());
            out.extend_from_slice(&spent.value.to_le_bytes());
            let spk_len = spent.script_pubkey.len() as u32;
            out.extend_from_slice(&spk_len.to_le_bytes());
            out.extend_from_slice(&spent.script_pubkey);
            out.extend_from_slice(&spent.height.to_le_bytes());
            out.push(if spent.is_coinbase { 1 } else { 0 });
        }

        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            anyhow::bail!("undo data too short");
        }

        let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut offset = 4;
        let mut spent_outputs = Vec::with_capacity(count);

        for _ in 0..count {
            // txid(32) + vout(4) + value(8) + spk_len(4) + height(4) + is_coinbase(1) = 53 base
            if offset + 32 + 4 + 8 + 4 > bytes.len() {
                anyhow::bail!("undo data truncated");
            }

            let mut txid = [0u8; 32];
            txid.copy_from_slice(&bytes[offset..offset + 32]);
            offset += 32;

            let vout = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            offset += 8;

            let spk_len =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + spk_len + 4 + 1 > bytes.len() {
                anyhow::bail!("undo data script truncated");
            }

            let script_pubkey = bytes[offset..offset + spk_len].to_vec();
            offset += spk_len;

            let height = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let is_coinbase = bytes[offset] != 0;
            offset += 1;

            spent_outputs.push(SpentOutput {
                txid,
                vout,
                value,
                script_pubkey,
                height,
                is_coinbase,
            });
        }

        Ok(Self { spent_outputs })
    }
}

impl Default for UndoData {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain index tracking all known blocks and their relationships.
#[derive(Debug, Default)]
pub struct ChainIndex {
    /// All known block metadata by hash.
    blocks: HashMap<[u8; 32], BlockMeta>,
    /// Blocks by height (may have multiple at same height during forks).
    by_height: HashMap<u64, Vec<[u8; 32]>>,
    /// Current best chain tip.
    tip: Option<[u8; 32]>,
    /// Orphan blocks (parent not yet known).
    orphans: HashMap<[u8; 32], Vec<[u8; 32]>>, // parent_hash -> child hashes
    /// Genesis block hash.
    genesis: Option<[u8; 32]>,
}

impl ChainIndex {
    /// Create a new empty chain index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize with genesis block.
    pub fn init_genesis(&mut self, hash: [u8; 32], prev_hash: [u8; 32]) {
        let meta = BlockMeta {
            hash,
            prev_hash,
            height: 0,
            cumulative_work: 1, // Genesis has work 1
            status: BlockStatus::Valid,
        };

        self.blocks.insert(hash, meta);
        self.by_height.entry(0).or_default().push(hash);
        self.tip = Some(hash);
        self.genesis = Some(hash);
    }

    /// Get block metadata by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<&BlockMeta> {
        self.blocks.get(hash)
    }

    /// Get current tip hash.
    pub fn tip(&self) -> Option<[u8; 32]> {
        self.tip
    }

    /// Get current tip height.
    pub fn tip_height(&self) -> u64 {
        self.tip
            .and_then(|h| self.blocks.get(&h))
            .map(|m| m.height)
            .unwrap_or(0)
    }

    /// Get genesis block hash.
    pub fn genesis(&self) -> Option<[u8; 32]> {
        self.genesis
    }

    /// Check if a block is known.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.blocks.contains_key(hash)
    }

    /// Add a new block to the index.
    ///
    /// Returns `true` if this block extends the best chain (new tip).
    pub fn add_block(&mut self, hash: [u8; 32], prev_hash: [u8; 32]) -> Result<bool> {
        // Already known?
        if self.blocks.contains_key(&hash) {
            return Ok(false);
        }

        // Find parent
        let parent = match self.blocks.get(&prev_hash) {
            Some(p) => p.clone(),
            None => {
                // Parent not known - store as orphan
                self.orphans.entry(prev_hash).or_default().push(hash);
                // Store minimal metadata
                self.blocks.insert(
                    hash,
                    BlockMeta {
                        hash,
                        prev_hash,
                        height: 0, // Unknown until parent found
                        cumulative_work: 0,
                        status: BlockStatus::HeaderOnly,
                    },
                );
                return Ok(false);
            }
        };

        // Calculate height and work
        let height = parent.height + 1;
        let cumulative_work = parent.cumulative_work + 1; // Simplified: +1 per block

        let meta = BlockMeta {
            hash,
            prev_hash,
            height,
            cumulative_work,
            status: BlockStatus::DataAvailable,
        };

        self.blocks.insert(hash, meta);
        self.by_height.entry(height).or_default().push(hash);

        // Check if this is the new best tip
        let is_new_tip = self
            .tip
            .and_then(|t| self.blocks.get(&t))
            .map(|tip_meta| cumulative_work > tip_meta.cumulative_work)
            .unwrap_or(true);

        if is_new_tip {
            self.tip = Some(hash);
        }

        // Check for orphans that can now be connected
        if let Some(orphan_children) = self.orphans.remove(&hash) {
            for child_hash in orphan_children {
                // Update orphan's metadata now that parent is known
                if let Some(child_meta) = self.blocks.get_mut(&child_hash) {
                    child_meta.height = height + 1;
                    child_meta.cumulative_work = cumulative_work + 1;
                    child_meta.status = BlockStatus::DataAvailable;
                    self.by_height
                        .entry(child_meta.height)
                        .or_default()
                        .push(child_hash);
                }
            }
        }

        Ok(is_new_tip)
    }

    /// Mark a block as valid after full validation.
    pub fn mark_valid(&mut self, hash: &[u8; 32]) {
        if let Some(meta) = self.blocks.get_mut(hash) {
            meta.status = BlockStatus::Valid;
        }
    }

    /// Mark a block as invalid.
    pub fn mark_invalid(&mut self, hash: &[u8; 32]) {
        if let Some(meta) = self.blocks.get_mut(hash) {
            meta.status = BlockStatus::Invalid;
        }
    }

    /// Find the fork point between two blocks.
    /// Returns the common ancestor hash.
    pub fn find_fork_point(&self, hash_a: &[u8; 32], hash_b: &[u8; 32]) -> Option<[u8; 32]> {
        let mut ancestors_a: HashSet<[u8; 32]> = HashSet::new();

        // Walk back from A, collecting ancestors
        let mut current = *hash_a;
        while let Some(meta) = self.blocks.get(&current) {
            ancestors_a.insert(current);
            if meta.height == 0 {
                break;
            }
            current = meta.prev_hash;
        }

        // Walk back from B until we find a common ancestor
        current = *hash_b;
        while let Some(meta) = self.blocks.get(&current) {
            if ancestors_a.contains(&current) {
                return Some(current);
            }
            if meta.height == 0 {
                break;
            }
            current = meta.prev_hash;
        }

        // Check if we ended at genesis
        if ancestors_a.contains(&current) {
            return Some(current);
        }

        None
    }

    /// Get the path from fork_point to target (exclusive of fork_point).
    pub fn get_path(&self, fork_point: &[u8; 32], target: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        let mut current = *target;

        while current != *fork_point {
            if let Some(meta) = self.blocks.get(&current) {
                path.push(current);
                current = meta.prev_hash;
            } else {
                break;
            }
        }

        path.reverse(); // Return in connect order (oldest first)
        path
    }

    /// Get blocks at a specific height.
    pub fn blocks_at_height(&self, height: u64) -> Vec<[u8; 32]> {
        self.by_height.get(&height).cloned().unwrap_or_default()
    }

    /// Check if a reorg is needed to switch to a new tip.
    pub fn needs_reorg(&self, new_tip: &[u8; 32]) -> bool {
        if let Some(current_tip) = self.tip {
            if current_tip == *new_tip {
                return false;
            }
            // Check if new_tip is a descendant of current_tip
            let mut current = *new_tip;
            while let Some(meta) = self.blocks.get(&current) {
                if current == current_tip {
                    return false; // new_tip extends current chain
                }
                if meta.height == 0 {
                    break;
                }
                current = meta.prev_hash;
            }
            return true;
        }
        false
    }

    /// Update the tip (used after successful reorg).
    pub fn set_tip(&mut self, hash: [u8; 32]) {
        self.tip = Some(hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    #[test]
    fn chain_index_genesis() {
        let mut index = ChainIndex::new();
        let genesis = make_hash(0);
        let prev = [0u8; 32];

        index.init_genesis(genesis, prev);

        assert_eq!(index.tip(), Some(genesis));
        assert_eq!(index.tip_height(), 0);
        assert!(index.contains(&genesis));
    }

    #[test]
    fn chain_index_linear_growth() {
        let mut index = ChainIndex::new();
        let genesis = make_hash(0);
        index.init_genesis(genesis, [0u8; 32]);

        let block1 = make_hash(1);
        let is_tip = index.add_block(block1, genesis).unwrap();
        assert!(is_tip);
        assert_eq!(index.tip(), Some(block1));
        assert_eq!(index.tip_height(), 1);

        let block2 = make_hash(2);
        let is_tip = index.add_block(block2, block1).unwrap();
        assert!(is_tip);
        assert_eq!(index.tip_height(), 2);
    }

    #[test]
    fn chain_index_fork() {
        let mut index = ChainIndex::new();
        let genesis = make_hash(0);
        index.init_genesis(genesis, [0u8; 32]);

        // Main chain: genesis -> block1 -> block2
        let block1 = make_hash(1);
        index.add_block(block1, genesis).unwrap();
        let block2 = make_hash(2);
        index.add_block(block2, block1).unwrap();

        // Fork: genesis -> block1 -> block1b (same height as block2)
        let block1b = make_hash(10);
        let is_tip = index.add_block(block1b, block1).unwrap();
        // Same work, shouldn't become tip (first seen wins)
        assert!(!is_tip);
        assert_eq!(index.tip(), Some(block2));

        // Fork extends: block1b -> block1b2 (now longer)
        let block1b2 = make_hash(11);
        let is_tip = index.add_block(block1b2, block1b).unwrap();
        assert!(is_tip); // Now longer chain
        assert_eq!(index.tip(), Some(block1b2));
    }

    #[test]
    fn chain_index_find_fork_point() {
        let mut index = ChainIndex::new();
        let genesis = make_hash(0);
        index.init_genesis(genesis, [0u8; 32]);

        let block1 = make_hash(1);
        index.add_block(block1, genesis).unwrap();

        let block2a = make_hash(2);
        index.add_block(block2a, block1).unwrap();

        let block2b = make_hash(20);
        index.add_block(block2b, block1).unwrap();

        let fork_point = index.find_fork_point(&block2a, &block2b);
        assert_eq!(fork_point, Some(block1));
    }

    #[test]
    fn undo_data_roundtrip() {
        let mut undo = UndoData::new();
        undo.add_spent(
            [1u8; 32],
            0,
            &Prevout::new(50000, vec![0x00, 0x14, 0xab], 5, true),
        );
        undo.add_spent([2u8; 32], 1, &Prevout::new(100000, vec![0x51], 10, false));

        let bytes = undo.to_bytes();
        let restored = UndoData::from_bytes(&bytes).unwrap();

        assert_eq!(restored.spent_outputs.len(), 2);
        assert_eq!(restored.spent_outputs[0].txid, [1u8; 32]);
        assert_eq!(restored.spent_outputs[0].value, 50000);
        assert_eq!(restored.spent_outputs[0].height, 5);
        assert!(restored.spent_outputs[0].is_coinbase);
        assert_eq!(restored.spent_outputs[1].vout, 1);
        assert_eq!(restored.spent_outputs[1].height, 10);
        assert!(!restored.spent_outputs[1].is_coinbase);
    }
}
