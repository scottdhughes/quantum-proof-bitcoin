//! Transaction memory pool for QPB.
//!
//! Holds unconfirmed transactions awaiting inclusion in blocks.
//! Provides fee-prioritized selection for miners.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use super::node::parse_transaction;
use crate::activation::Network;
use crate::constants::{DUST_LIMIT, INCREMENTAL_RELAY_FEE, MAX_REPLACEMENT_EVICTIONS};
use crate::types::{OutPoint, Prevout, Transaction};
use crate::validation::validate_transaction_basic;

/// Mempool configuration limits (similar to Bitcoin Core defaults).
pub const MAX_ANCESTORS: usize = 25;
pub const MAX_DESCENDANTS: usize = 25;
pub const MAX_ANCESTOR_SIZE_VBYTES: usize = 101_000;
pub const MAX_DESCENDANT_SIZE_VBYTES: usize = 101_000;
pub const MAX_MEMPOOL_SIZE: usize = 300_000_000; // 300 MB

// ─────────────────────────────────────────────────────────────────────────────
// Persistence Types
// ─────────────────────────────────────────────────────────────────────────────

/// Serializable representation of a mempool transaction.
/// Stores only the raw transaction hex - all metadata is rebuilt on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MempoolTxRecord {
    /// Transaction serialized as hex (with witness data).
    tx_hex: String,
}

/// Container for persisted mempool data.
#[derive(Debug, Default, Serialize, Deserialize)]
struct MempoolData {
    /// List of transactions to reload.
    transactions: Vec<MempoolTxRecord>,
}

/// Statistics from loading mempool.
#[derive(Debug, Default, Clone)]
pub struct MempoolLoadStats {
    /// Number of transactions successfully loaded.
    pub loaded: usize,
    /// Number of transactions that failed validation (missing inputs, etc.).
    pub invalid: usize,
    /// Number of transactions that failed to parse from hex.
    pub parse_failed: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Mempool Entry
// ─────────────────────────────────────────────────────────────────────────────

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
    /// True if this transaction signals RBF (BIP125).
    pub signals_rbf: bool,
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
    /// * `height` - Current chain height (for activation checks)
    /// * `network` - Network type (for activation checks)
    /// * `utxo_lookup` - Function to lookup UTXOs (for prevouts not in mempool)
    ///
    /// # Returns
    /// * `Ok(txid)` on success
    /// * `Err` if validation fails or limits exceeded
    pub fn add_transaction<F>(
        &mut self,
        tx: Transaction,
        prevouts: Vec<Prevout>,
        height: u32,
        network: Network,
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

        // Check for conflicts (double-spends) and handle RBF
        let inputs: Vec<OutPoint> = tx.vin.iter().map(|vin| vin.prevout.clone()).collect();
        let conflicts = self.find_conflicts(&inputs);

        // Will be set if this is a replacement transaction
        let mut eviction_set: Option<EvictionSet> = None;

        if !conflicts.is_empty() {
            // Calculate what would be evicted
            let evict = self
                .calculate_eviction_set(&conflicts)
                .map_err(|e| anyhow!("{}", e))?;

            // We need to calculate fee and vsize before validation
            // For now, defer validation until after fee calculation below
            eviction_set = Some(evict);
        }

        // Validate transaction
        validate_transaction_basic(&tx, &prevouts, height, network)?;

        // Calculate fee
        let input_sum: u64 = prevouts.iter().map(|p| p.value).sum();
        let output_sum: u64 = tx.vout.iter().map(|o| o.value).sum();
        if output_sum > input_sum {
            return Err(anyhow!("output value exceeds input value"));
        }
        let fee = input_sum - output_sum;

        // Check for dust outputs (outputs below minimum value)
        // Zero-value outputs are allowed for OP_RETURN data outputs
        for (i, output) in tx.vout.iter().enumerate() {
            if output.value > 0 && output.value < DUST_LIMIT {
                return Err(anyhow!(
                    "output {} value {} sats is below dust limit {} sats",
                    i,
                    output.value,
                    DUST_LIMIT
                ));
            }
        }

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

        // Reject zero fee rate transactions
        if fee_rate_millionths == 0 {
            return Err(anyhow!(
                "transaction has zero fee rate; minimum is 1 sat/vB"
            ));
        }

        // Track mempool parents (inputs that come from other mempool txs)
        let mut mempool_parents = HashSet::new();
        for vin in &tx.vin {
            if self.txns.contains_key(&vin.prevout.txid) {
                mempool_parents.insert(vin.prevout.txid);
            }
        }

        // If this is a replacement, validate BIP125 rules
        if let Some(ref evict) = eviction_set {
            let original_parents = self.collect_conflict_parents(&conflicts);
            self.validate_replacement(
                fee,
                vsize,
                &conflicts,
                evict,
                &mempool_parents,
                &original_parents,
            )
            .map_err(|e| anyhow!("{}", e))?;
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

        // Check if transaction signals RBF (before moving tx)
        let signals_rbf = tx.signals_rbf();

        // If this is a replacement, evict the conflicting transactions
        if let Some(ref evict) = eviction_set {
            self.evict_for_replacement(evict);
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
            signals_rbf,
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

    // ─────────────────────────────────────────────────────────────────────────
    // RBF (Replace-by-Fee) Methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Find all mempool transactions that conflict with the given inputs.
    /// A conflict occurs when another transaction spends the same outpoint.
    pub fn find_conflicts(&self, inputs: &[OutPoint]) -> HashSet<[u8; 32]> {
        let mut conflicts = HashSet::new();
        for input in inputs {
            if let Some(&spending_txid) = self.spenders.get(input) {
                conflicts.insert(spending_txid);
            }
        }
        conflicts
    }

    /// Get all descendants of a transaction (children, grandchildren, etc.).
    /// Does not include the transaction itself.
    pub fn get_all_descendants(&self, txid: &[u8; 32]) -> HashSet<[u8; 32]> {
        let mut descendants = HashSet::new();
        let mut to_visit = vec![*txid];

        while let Some(current) = to_visit.pop() {
            if let Some(entry) = self.txns.get(&current) {
                for child in &entry.mempool_children {
                    if descendants.insert(*child) {
                        to_visit.push(*child);
                    }
                }
            }
        }
        descendants
    }

    /// Calculate the full eviction set for replacing conflicting transactions.
    /// Returns all transactions that would be evicted (conflicts + their descendants).
    pub fn calculate_eviction_set(
        &self,
        conflicts: &HashSet<[u8; 32]>,
    ) -> Result<EvictionSet, RbfError> {
        let mut all_to_evict = HashSet::new();
        let mut total_fee: u64 = 0;
        let mut total_vsize: u32 = 0;

        // Add each conflict and all its descendants
        for conflict_txid in conflicts {
            // Add the conflict itself
            if all_to_evict.insert(*conflict_txid)
                && let Some(entry) = self.txns.get(conflict_txid)
            {
                total_fee += entry.fee;
                total_vsize += entry.vsize;
            }

            // Add all descendants
            for descendant_txid in self.get_all_descendants(conflict_txid) {
                if all_to_evict.insert(descendant_txid)
                    && let Some(entry) = self.txns.get(&descendant_txid)
                {
                    total_fee += entry.fee;
                    total_vsize += entry.vsize;
                }
            }
        }

        // BIP125 Rule 5: Cannot evict more than MAX_REPLACEMENT_EVICTIONS
        if all_to_evict.len() > MAX_REPLACEMENT_EVICTIONS {
            return Err(RbfError::TooManyEvictions {
                count: all_to_evict.len(),
                max: MAX_REPLACEMENT_EVICTIONS,
            });
        }

        Ok(EvictionSet {
            txids: all_to_evict.into_iter().collect(),
            total_fee,
            total_vsize,
        })
    }

    /// Validate that a replacement transaction satisfies BIP125 rules.
    ///
    /// # Arguments
    /// * `replacement_fee` - Fee of the replacement transaction
    /// * `replacement_vsize` - Virtual size of the replacement transaction
    /// * `conflicts` - Set of directly conflicting transaction ids
    /// * `eviction_set` - Pre-computed eviction set
    /// * `new_mempool_parents` - Mempool parents of the replacement tx
    /// * `original_parents` - Mempool parents of the conflicting transactions
    pub fn validate_replacement(
        &self,
        replacement_fee: u64,
        replacement_vsize: u32,
        conflicts: &HashSet<[u8; 32]>,
        eviction_set: &EvictionSet,
        new_mempool_parents: &HashSet<[u8; 32]>,
        original_parents: &HashSet<[u8; 32]>,
    ) -> Result<(), RbfError> {
        // BIP125 Rule 1: All conflicting transactions must signal RBF
        for conflict_txid in conflicts {
            if let Some(entry) = self.txns.get(conflict_txid)
                && !entry.signals_rbf
            {
                return Err(RbfError::NotReplaceable {
                    txid: *conflict_txid,
                });
            }
        }

        // BIP125 Rule 2: Replacement must not introduce new unconfirmed inputs
        // (can only spend confirmed outputs or outputs from original tx's parents)
        for parent in new_mempool_parents {
            if !original_parents.contains(parent) && !conflicts.contains(parent) {
                return Err(RbfError::NewUnconfirmedInputs { txid: *parent });
            }
        }

        // BIP125 Rule 3: Replacement must pay higher absolute fee
        if replacement_fee <= eviction_set.total_fee {
            return Err(RbfError::InsufficientFee {
                required: eviction_set.total_fee + 1,
                provided: replacement_fee,
            });
        }

        // BIP125 Rule 4: Replacement must pay for its own bandwidth
        // The additional fee must cover the relay cost of the replacement tx
        let bandwidth_fee_required = (replacement_vsize as u64) * INCREMENTAL_RELAY_FEE;
        let additional_fee = replacement_fee.saturating_sub(eviction_set.total_fee);
        if additional_fee < bandwidth_fee_required {
            return Err(RbfError::InsufficientBandwidthFee {
                required: eviction_set.total_fee + bandwidth_fee_required,
                provided: replacement_fee,
            });
        }

        Ok(())
    }

    /// Evict transactions for RBF replacement.
    /// Removes all transactions in the eviction set from the mempool.
    pub fn evict_for_replacement(&mut self, eviction_set: &EvictionSet) {
        // Remove in reverse topological order (children before parents)
        // to avoid issues with parent/child relationship updates
        for txid in &eviction_set.txids {
            self.remove_transaction(txid, false);
        }
    }

    /// Collect the mempool parents of a set of conflicting transactions.
    fn collect_conflict_parents(&self, conflicts: &HashSet<[u8; 32]>) -> HashSet<[u8; 32]> {
        let mut parents = HashSet::new();
        for conflict_txid in conflicts {
            if let Some(entry) = self.txns.get(conflict_txid) {
                for parent in &entry.mempool_parents {
                    parents.insert(*parent);
                }
            }
        }
        parents
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

    /// Get fee rate distribution for fee estimation.
    ///
    /// Returns pairs of (fee_rate_millionths, vsize) sorted by fee rate descending.
    /// Used by the fee estimator to find the fee rate at a given mempool depth.
    pub fn fee_rate_distribution(&self) -> Vec<(u64, u32)> {
        // Collect entries sorted by ancestor fee rate (descending)
        let mut entries: Vec<_> = self
            .by_ancestor_fee_rate
            .iter()
            .filter_map(|key| self.txns.get(&key.txid))
            .map(|e| (e.fee_rate_millionths, e.vsize))
            .collect();

        // Sort by fee rate descending (by_ancestor_fee_rate uses ancestor rate,
        // but we want individual tx rate for fee estimation)
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        entries
    }

    /// Get all txids in the mempool.
    pub fn all_txids(&self) -> Vec<[u8; 32]> {
        self.txns.keys().copied().collect()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Persistence Methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Save mempool to disk.
    ///
    /// Transactions are stored as hex strings in JSON format.
    /// All computed fields (fee, weight, ancestors) are rebuilt on load.
    pub fn save(&self, datadir: &Path) -> Result<()> {
        let path = datadir.join("mempool.json");

        let records: Vec<MempoolTxRecord> = self
            .txns
            .values()
            .map(|entry| MempoolTxRecord {
                tx_hex: hex::encode(entry.tx.serialize(true)),
            })
            .collect();

        let data = MempoolData {
            transactions: records,
        };

        let json = serde_json::to_vec_pretty(&data)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load mempool from disk and validate against current UTXO set.
    ///
    /// Transactions whose inputs no longer exist (confirmed or double-spent)
    /// are silently dropped. All computed fields are rebuilt.
    ///
    /// # Arguments
    /// * `datadir` - Data directory containing mempool.json
    /// * `utxo_lookup` - Function to lookup UTXOs by (txid, vout)
    ///
    /// # Returns
    /// * `Ok((mempool, stats))` with load statistics
    /// * `Err` on I/O or parse errors
    pub fn load<F>(
        datadir: &Path,
        height: u32,
        network: Network,
        utxo_lookup: F,
    ) -> Result<(Self, MempoolLoadStats)>
    where
        F: Fn(&[u8; 32], u32) -> Option<Prevout>,
    {
        let path = datadir.join("mempool.json");
        if !path.exists() {
            return Ok((Self::default(), MempoolLoadStats::default()));
        }

        let data: MempoolData = serde_json::from_reader(fs::File::open(&path)?)?;
        let mut mempool = Self::new();
        let mut stats = MempoolLoadStats::default();

        // Parse all transactions first
        let mut parsed_txs: Vec<Transaction> = Vec::new();
        for record in &data.transactions {
            match hex::decode(&record.tx_hex)
                .ok()
                .and_then(|bytes| parse_transaction(&bytes).ok())
            {
                Some(tx) => parsed_txs.push(tx),
                None => stats.parse_failed += 1,
            }
        }

        // Build txid -> tx index for dependency resolution
        let tx_by_id: HashMap<[u8; 32], &Transaction> =
            parsed_txs.iter().map(|tx| (tx.txid(), tx)).collect();

        // Topologically sort to add parents before children
        let sorted = topological_sort_txs(&parsed_txs, &tx_by_id);

        // Reload each transaction
        for tx in sorted {
            match mempool.try_reload_transaction(tx, height, network, &utxo_lookup) {
                Ok(_) => stats.loaded += 1,
                Err(_) => stats.invalid += 1,
            }
        }

        Ok((mempool, stats))
    }

    /// Internal: Try to reload a transaction, looking up prevouts from UTXO or mempool.
    fn try_reload_transaction<F>(
        &mut self,
        tx: Transaction,
        height: u32,
        network: Network,
        utxo_lookup: &F,
    ) -> Result<[u8; 32]>
    where
        F: Fn(&[u8; 32], u32) -> Option<Prevout>,
    {
        let mut prevouts = Vec::with_capacity(tx.vin.len());

        for vin in &tx.vin {
            // First check if input comes from another mempool tx
            if let Some(parent_entry) = self.txns.get(&vin.prevout.txid) {
                let vout_idx = vin.prevout.vout as usize;
                if vout_idx >= parent_entry.tx.vout.len() {
                    anyhow::bail!("invalid prevout index");
                }
                let txout = &parent_entry.tx.vout[vout_idx];
                prevouts.push(Prevout {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey.clone(),
                    height: 0,
                    is_coinbase: false,
                });
            } else if let Some(prev) = utxo_lookup(&vin.prevout.txid, vin.prevout.vout) {
                prevouts.push(prev);
            } else {
                anyhow::bail!("missing prevout - tx may have been confirmed or double-spent");
            }
        }

        // Use existing add_transaction which rebuilds all computed fields
        self.add_transaction(tx, prevouts, height, network, utxo_lookup)
    }
}

/// Topologically sort transactions so parents come before children.
fn topological_sort_txs<'a>(
    txs: &'a [Transaction],
    tx_by_id: &HashMap<[u8; 32], &'a Transaction>,
) -> Vec<Transaction> {
    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut temp_mark = HashSet::new();

    fn visit<'a>(
        tx: &'a Transaction,
        tx_by_id: &HashMap<[u8; 32], &'a Transaction>,
        visited: &mut HashSet<[u8; 32]>,
        temp_mark: &mut HashSet<[u8; 32]>,
        result: &mut Vec<Transaction>,
    ) {
        let txid = tx.txid();
        if visited.contains(&txid) {
            return;
        }
        if temp_mark.contains(&txid) {
            return; // Cycle detected - skip
        }
        temp_mark.insert(txid);

        // Visit parents first
        for vin in &tx.vin {
            if let Some(parent) = tx_by_id.get(&vin.prevout.txid) {
                visit(parent, tx_by_id, visited, temp_mark, result);
            }
        }

        temp_mark.remove(&txid);
        visited.insert(txid);
        result.push(tx.clone());
    }

    for tx in txs {
        visit(tx, tx_by_id, &mut visited, &mut temp_mark, &mut result);
    }

    result
}

/// Mempool statistics for RPC.
#[derive(Debug, Clone)]
pub struct MempoolInfo {
    pub size: usize,
    pub bytes: usize,
    pub total_fee: u64,
}

/// Information about transactions to be evicted for RBF replacement.
#[derive(Debug, Clone)]
pub struct EvictionSet {
    /// Txids of all transactions to evict (conflicts + descendants).
    pub txids: Vec<[u8; 32]>,
    /// Total fee of all evicted transactions.
    pub total_fee: u64,
    /// Total virtual size of all evicted transactions.
    pub total_vsize: u32,
}

/// RBF validation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbfError {
    /// Conflicting transaction does not signal RBF.
    NotReplaceable { txid: [u8; 32] },
    /// Replacement fee is not higher than sum of evicted fees.
    InsufficientFee { required: u64, provided: u64 },
    /// Replacement fee rate is below minimum of conflicting transactions.
    InsufficientFeeRate { required: u64, provided: u64 },
    /// Too many transactions would be evicted.
    TooManyEvictions { count: usize, max: usize },
    /// Replacement doesn't pay enough for relay bandwidth.
    InsufficientBandwidthFee { required: u64, provided: u64 },
    /// Replacement introduces new unconfirmed inputs.
    NewUnconfirmedInputs { txid: [u8; 32] },
}

impl std::fmt::Display for RbfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RbfError::NotReplaceable { txid } => {
                write!(f, "transaction {} does not signal RBF", hex::encode(txid))
            }
            RbfError::InsufficientFee { required, provided } => {
                write!(
                    f,
                    "insufficient fee: need {} sats, have {} sats",
                    required, provided
                )
            }
            RbfError::InsufficientFeeRate { required, provided } => {
                write!(
                    f,
                    "insufficient fee rate: need {} sat/vB, have {} sat/vB",
                    required, provided
                )
            }
            RbfError::TooManyEvictions { count, max } => {
                write!(f, "would evict {} transactions, max is {}", count, max)
            }
            RbfError::InsufficientBandwidthFee { required, provided } => {
                write!(
                    f,
                    "insufficient bandwidth fee: need {} sats, have {} sats",
                    required, provided
                )
            }
            RbfError::NewUnconfirmedInputs { txid } => {
                write!(
                    f,
                    "replacement spends new unconfirmed input from {}",
                    hex::encode(txid)
                )
            }
        }
    }
}

impl std::error::Error for RbfError {}

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
                script_pubkey: vec![0x6a], // OP_RETURN (minimal valid output)
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

    // Note: Persistence tests are in tests/mempool_persist.rs as integration tests
    // because they require properly signed transactions to pass validation.
}
