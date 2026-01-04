//! Transaction memory pool for QPB.
//!
//! Holds unconfirmed transactions awaiting inclusion in blocks.
//! Provides fee-prioritized selection for miners.

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::{Result, anyhow};

use crate::types::{OutPoint, Prevout, Transaction};
use crate::validation::validate_transaction_basic;

/// Mempool configuration limits (similar to Bitcoin Core defaults).
pub const MAX_ANCESTORS: usize = 25;
pub const MAX_DESCENDANTS: usize = 25;
pub const MAX_ANCESTOR_SIZE_VBYTES: usize = 101_000;
pub const MAX_DESCENDANT_SIZE_VBYTES: usize = 101_000;
pub const MAX_MEMPOOL_SIZE: usize = 300_000_000; // 300 MB

/// Entry in the mempool with cached metadata.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction itself.
    pub tx: Transaction,
    /// Cached txid.
    pub txid: [u8; 32],
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Transaction weight in WU.
    pub weight: u32,
    /// Virtual size (vbytes) = (weight + 3) / 4.
    pub vsize: u32,
    /// Fee rate in sat/vbyte (scaled by 1000 for precision).
    pub fee_rate_millionths: u64,
    /// Txids of unconfirmed parents in mempool.
    pub mempool_parents: HashSet<[u8; 32]>,
    /// Txids of children spending our outputs.
    pub mempool_children: HashSet<[u8; 32]>,
    /// Ancestor count (including self).
    pub ancestor_count: usize,
    /// Ancestor size in vbytes (including self).
    pub ancestor_size: usize,
    /// Descendant count (including self).
    pub descendant_count: usize,
    /// Descendant size in vbytes (including self).
    pub descendant_size: usize,
    /// Combined ancestor fee (for CPFP mining).
    pub ancestor_fee: u64,
}

impl MempoolEntry {
    /// Ancestor fee rate for mining prioritization (sat/vbyte * 1M).
    pub fn ancestor_fee_rate(&self) -> u64 {
        if self.ancestor_size == 0 {
            return 0;
        }
        (self.ancestor_fee as u128 * 1_000_000 / self.ancestor_size as u128) as u64
    }
}

/// Fee rate comparison key for BTreeSet ordering.
/// Higher fee rate = higher priority, ties broken by txid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeeRateKey {
    /// Negated fee rate (so higher rates sort first).
    neg_fee_rate: i64,
    /// Txid for tie-breaking.
    txid: [u8; 32],
}

/// Transaction memory pool.
#[derive(Debug, Default)]
pub struct Mempool {
    /// All transactions by txid.
    txns: HashMap<[u8; 32], MempoolEntry>,
    /// Index: outpoint -> txid that spends it.
    spenders: HashMap<OutPoint, [u8; 32]>,
    /// Fee-sorted index for mining selection.
    by_ancestor_fee_rate: BTreeSet<FeeRateKey>,
    /// Total size in bytes.
    total_size: usize,
}

impl Mempool {
    /// Create a new empty mempool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.txns.len()
    }

    /// Check if mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.txns.is_empty()
    }

    /// Total size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.total_size
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.txns.contains_key(txid)
    }

    /// Get a transaction by txid.
    pub fn get(&self, txid: &[u8; 32]) -> Option<&MempoolEntry> {
        self.txns.get(txid)
    }

    /// Check if an outpoint is already spent by a mempool transaction.
    pub fn is_spent(&self, outpoint: &OutPoint) -> bool {
        self.spenders.contains_key(outpoint)
    }

    /// Add a transaction to the mempool.
    ///
    /// # Arguments
    /// * `tx` - The transaction to add
    /// * `prevouts` - Previous outputs for fee calculation
    /// * `utxo_lookup` - Function to lookup UTXOs (for prevouts not in mempool)
    ///
    /// # Returns
    /// * `Ok(txid)` on success
    /// * `Err` if validation fails or limits exceeded
    pub fn add_transaction<F>(
        &mut self,
        tx: Transaction,
        prevouts: Vec<Prevout>,
        _utxo_lookup: F,
    ) -> Result<[u8; 32]>
    where
        F: Fn(&[u8; 32], u32) -> Option<Prevout>,
    {
        let txid = tx.txid();

        // Reject if already in mempool
        if self.txns.contains_key(&txid) {
            return Err(anyhow!("transaction already in mempool"));
        }

        // Check for double-spends
        for vin in &tx.vin {
            if self.spenders.contains_key(&vin.prevout) {
                return Err(anyhow!("input already spent by mempool transaction"));
            }
        }

        // Validate transaction
        validate_transaction_basic(&tx, &prevouts)?;

        // Calculate fee
        let input_sum: u64 = prevouts.iter().map(|p| p.value).sum();
        let output_sum: u64 = tx.vout.iter().map(|o| o.value).sum();
        if output_sum > input_sum {
            return Err(anyhow!("output value exceeds input value"));
        }
        let fee = input_sum - output_sum;

        // Calculate weight/vsize
        let base_bytes = tx.serialize(false).len();
        let full_bytes = tx.serialize(true).len();
        let witness_bytes = full_bytes.saturating_sub(base_bytes);
        let weight = (4 * base_bytes + witness_bytes) as u32;
        let vsize = weight.div_ceil(4);

        // Fee rate in millionths of sat/vbyte for precision
        let fee_rate_millionths = if vsize > 0 {
            (fee as u128 * 1_000_000 / vsize as u128) as u64
        } else {
            0
        };

        // Track mempool parents (inputs that come from other mempool txs)
        let mut mempool_parents = HashSet::new();
        for vin in &tx.vin {
            if self.txns.contains_key(&vin.prevout.txid) {
                mempool_parents.insert(vin.prevout.txid);
            }
        }

        // Calculate ancestor stats
        let (ancestor_count, ancestor_size, ancestor_fee) =
            self.calculate_ancestors(&txid, &mempool_parents, vsize as usize, fee)?;

        // Check ancestor limits
        if ancestor_count > MAX_ANCESTORS {
            return Err(anyhow!(
                "exceeds ancestor limit: {} > {}",
                ancestor_count,
                MAX_ANCESTORS
            ));
        }
        if ancestor_size > MAX_ANCESTOR_SIZE_VBYTES {
            return Err(anyhow!(
                "exceeds ancestor size limit: {} > {}",
                ancestor_size,
                MAX_ANCESTOR_SIZE_VBYTES
            ));
        }

        // Check descendant limits for all ancestors
        for parent_txid in &mempool_parents {
            if let Some(parent) = self.txns.get(parent_txid)
                && parent.descendant_count >= MAX_DESCENDANTS
            {
                return Err(anyhow!(
                    "parent {} exceeds descendant limit",
                    hex::encode(parent_txid)
                ));
            }
        }

        // Check mempool size limit
        let tx_size = full_bytes;
        if self.total_size + tx_size > MAX_MEMPOOL_SIZE {
            return Err(anyhow!("mempool full"));
        }

        // Create entry
        let entry = MempoolEntry {
            tx,
            txid,
            fee,
            weight,
            vsize,
            fee_rate_millionths,
            mempool_parents: mempool_parents.clone(),
            mempool_children: HashSet::new(),
            ancestor_count,
            ancestor_size,
            descendant_count: 1, // Just self
            descendant_size: vsize as usize,
            ancestor_fee,
        };

        // Update parent's children set and descendant counts
        for parent_txid in &mempool_parents {
            if let Some(parent) = self.txns.get_mut(parent_txid) {
                parent.mempool_children.insert(txid);
            }
            // Update all ancestors' descendant stats
            self.update_ancestor_descendants(parent_txid, vsize as usize);
        }

        // Add to spender index
        for vin in &entry.tx.vin {
            self.spenders.insert(vin.prevout.clone(), txid);
        }

        // Add to fee-sorted index
        self.by_ancestor_fee_rate.insert(FeeRateKey {
            neg_fee_rate: -(entry.ancestor_fee_rate() as i64),
            txid,
        });

        self.total_size += tx_size;
        self.txns.insert(txid, entry);

        Ok(txid)
    }

    /// Calculate ancestor count, size, and fee for a new transaction.
    fn calculate_ancestors(
        &self,
        _txid: &[u8; 32],
        parents: &HashSet<[u8; 32]>,
        self_vsize: usize,
        self_fee: u64,
    ) -> Result<(usize, usize, u64)> {
        let mut visited = HashSet::new();
        let mut to_visit: Vec<[u8; 32]> = parents.iter().copied().collect();

        while let Some(ancestor_txid) = to_visit.pop() {
            if visited.contains(&ancestor_txid) {
                continue;
            }
            visited.insert(ancestor_txid);

            if let Some(ancestor) = self.txns.get(&ancestor_txid) {
                for grandparent in &ancestor.mempool_parents {
                    if !visited.contains(grandparent) {
                        to_visit.push(*grandparent);
                    }
                }
            }
        }

        let mut total_size = self_vsize;
        let mut total_fee = self_fee;

        for ancestor_txid in &visited {
            if let Some(ancestor) = self.txns.get(ancestor_txid) {
                total_size += ancestor.vsize as usize;
                total_fee += ancestor.fee;
            }
        }

        // +1 for self
        Ok((visited.len() + 1, total_size, total_fee))
    }

    /// Update descendant stats for all ancestors of a transaction.
    fn update_ancestor_descendants(&mut self, txid: &[u8; 32], added_vsize: usize) {
        let mut to_update: Vec<[u8; 32]> = vec![*txid];
        let mut visited = HashSet::new();

        while let Some(current) = to_update.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            if let Some(entry) = self.txns.get_mut(&current) {
                entry.descendant_count += 1;
                entry.descendant_size += added_vsize;

                for parent in entry.mempool_parents.clone() {
                    if !visited.contains(&parent) {
                        to_update.push(parent);
                    }
                }
            }
        }
    }

    /// Remove a transaction from the mempool.
    ///
    /// If `remove_descendants` is true, also removes all descendants.
    pub fn remove_transaction(&mut self, txid: &[u8; 32], remove_descendants: bool) -> bool {
        let entry = match self.txns.remove(txid) {
            Some(e) => e,
            None => return false,
        };

        // Remove from spender index
        for vin in &entry.tx.vin {
            self.spenders.remove(&vin.prevout);
        }

        // Remove from fee-sorted index
        self.by_ancestor_fee_rate.remove(&FeeRateKey {
            neg_fee_rate: -(entry.ancestor_fee_rate() as i64),
            txid: *txid,
        });

        // Update parents' children sets
        for parent_txid in &entry.mempool_parents {
            if let Some(parent) = self.txns.get_mut(parent_txid) {
                parent.mempool_children.remove(txid);
            }
        }

        let tx_size = entry.tx.serialize(true).len();
        self.total_size = self.total_size.saturating_sub(tx_size);

        // Optionally remove descendants
        if remove_descendants {
            let children: Vec<[u8; 32]> = entry.mempool_children.iter().copied().collect();
            for child_txid in children {
                self.remove_transaction(&child_txid, true);
            }
        }

        true
    }

    /// Remove transactions that were confirmed in a block.
    pub fn remove_confirmed(&mut self, block_txids: &[[u8; 32]]) {
        for txid in block_txids {
            self.remove_transaction(txid, false);
        }

        // Also remove any txs that now have conflicts (double-spends with confirmed txs)
        // This is handled by the UTXO set becoming authoritative
    }

    /// Select transactions for block template, ordered by ancestor fee rate.
    ///
    /// Returns transactions in an order suitable for inclusion in a block
    /// (parents before children).
    pub fn select_for_block(&self, max_weight: u32) -> Vec<&MempoolEntry> {
        let mut selected = Vec::new();
        let mut selected_txids = HashSet::new();
        let mut total_weight: u32 = 0;

        // Iterate by ancestor fee rate (highest first)
        for key in &self.by_ancestor_fee_rate {
            if let Some(entry) = self.txns.get(&key.txid) {
                // Skip if already selected (as ancestor of another tx)
                if selected_txids.contains(&entry.txid) {
                    continue;
                }

                // Collect tx and all unselected ancestors in topological order
                // (get_unselected_ancestors returns [grandparent, parent, ..., child])
                let package_txids = self.get_unselected_ancestors(&entry.txid, &selected_txids);
                let package_weight: u32 = package_txids
                    .iter()
                    .filter_map(|txid| self.txns.get(txid))
                    .map(|e| e.weight)
                    .sum();

                if total_weight + package_weight > max_weight {
                    continue;
                }

                // Add all in topological order (ancestors first)
                for pkg_txid in package_txids {
                    if !selected_txids.contains(&pkg_txid)
                        && let Some(e) = self.txns.get(&pkg_txid)
                    {
                        selected.push(e);
                        selected_txids.insert(pkg_txid);
                        total_weight += e.weight;
                    }
                }
            }
        }

        selected
    }

    /// Get unselected ancestors in topological order.
    fn get_unselected_ancestors(
        &self,
        txid: &[u8; 32],
        selected: &HashSet<[u8; 32]>,
    ) -> Vec<[u8; 32]> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();

        self.collect_ancestors_recursive(txid, selected, &mut visited, &mut result);

        result
    }

    fn collect_ancestors_recursive(
        &self,
        txid: &[u8; 32],
        selected: &HashSet<[u8; 32]>,
        visited: &mut HashSet<[u8; 32]>,
        result: &mut Vec<[u8; 32]>,
    ) {
        if visited.contains(txid) || selected.contains(txid) {
            return;
        }
        visited.insert(*txid);

        if let Some(entry) = self.txns.get(txid) {
            // Visit parents first
            for parent in &entry.mempool_parents {
                self.collect_ancestors_recursive(parent, selected, visited, result);
            }
            result.push(*txid);
        }
    }

    /// Get mempool info for RPC.
    pub fn get_info(&self) -> MempoolInfo {
        let fees: u64 = self.txns.values().map(|e| e.fee).sum();
        MempoolInfo {
            size: self.txns.len(),
            bytes: self.total_size,
            total_fee: fees,
        }
    }

    /// Get all txids in the mempool.
    pub fn all_txids(&self) -> Vec<[u8; 32]> {
        self.txns.keys().copied().collect()
    }
}

/// Mempool statistics for RPC.
#[derive(Debug, Clone)]
pub struct MempoolInfo {
    pub size: usize,
    pub bytes: usize,
    pub total_fee: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TxIn, TxOut};

    fn make_dummy_tx(inputs: Vec<([u8; 32], u32)>, output_value: u64) -> Transaction {
        Transaction {
            version: 1,
            vin: inputs
                .into_iter()
                .map(|(txid, vout)| TxIn {
                    prevout: OutPoint { txid, vout },
                    script_sig: vec![],
                    sequence: 0xffffffff,
                    witness: vec![],
                })
                .collect(),
            vout: vec![TxOut {
                value: output_value,
                script_pubkey: vec![0x00; 33], // dummy P2QPKH-like
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn mempool_empty() {
        let pool = Mempool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn mempool_contains() {
        let pool = Mempool::new();
        let txid = [0x42u8; 32];
        assert!(!pool.contains(&txid));
    }

    #[test]
    fn mempool_double_spend_detection() {
        let mut pool = Mempool::new();

        // Create a "confirmed" UTXO
        let prev_txid = [0x01u8; 32];
        let prevout = OutPoint {
            txid: prev_txid,
            vout: 0,
        };

        // First tx spending the UTXO - manually add to simulate
        let tx1 = make_dummy_tx(vec![(prev_txid, 0)], 1000);
        let txid1 = tx1.txid();

        // Manually insert to spenders index (simulating successful add)
        pool.spenders.insert(prevout.clone(), txid1);

        // Second tx trying to spend same UTXO should detect conflict
        assert!(pool.is_spent(&prevout));
    }
}
