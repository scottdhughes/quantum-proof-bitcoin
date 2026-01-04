//! Orphan transaction pool.
//!
//! Buffers transactions whose parent inputs are not yet available.
//! When parent transactions arrive, orphans are resolved and added to mempool.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

use crate::constants::{
    MAX_MISSING_PARENTS, MAX_ORPHAN_POOL_BYTES, MAX_ORPHAN_TRANSACTIONS, MAX_ORPHAN_TX_SIZE,
    MAX_ORPHANS_PER_PEER,
};
use crate::types::Transaction;

/// An orphan transaction waiting for its parent(s) to arrive.
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    /// The transaction itself.
    pub tx: Transaction,
    /// Transaction ID (cached for efficiency).
    pub txid: [u8; 32],
    /// Serialized size in bytes.
    pub size: usize,
    /// Set of parent txids that are missing.
    pub missing_parents: HashSet<[u8; 32]>,
    /// Peer that sent this transaction (for DoS tracking).
    pub from_peer: Option<u64>,
    /// Unix timestamp when this orphan was received.
    pub received_at: u64,
}

/// Pool for buffering orphan transactions.
///
/// Orphans are transactions received from peers before their parent
/// transactions. Instead of rejecting them immediately, we buffer them
/// here and attempt to add them to mempool when parents arrive.
#[derive(Debug, Default)]
pub struct OrphanPool {
    /// Orphan transactions indexed by txid.
    orphans: HashMap<[u8; 32], OrphanEntry>,
    /// Index: parent txid -> set of orphan txids waiting for it.
    by_missing_parent: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    /// Index: peer ID -> set of orphan txids from that peer.
    by_peer: HashMap<u64, HashSet<[u8; 32]>>,
    /// Insertion order for LRU eviction.
    insertion_order: VecDeque<[u8; 32]>,
    /// Total bytes of all orphan transactions.
    total_bytes: usize,
}

impl OrphanPool {
    /// Create a new empty orphan pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of orphan transactions in the pool.
    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.orphans.is_empty()
    }

    /// Total bytes of orphan transactions.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Check if an orphan with the given txid exists.
    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.orphans.contains_key(txid)
    }

    /// Get an orphan entry by txid.
    pub fn get(&self, txid: &[u8; 32]) -> Option<&OrphanEntry> {
        self.orphans.get(txid)
    }

    /// Add a transaction to the orphan pool.
    ///
    /// Returns `Ok(true)` if added, `Ok(false)` if already present,
    /// or an error if rejected due to limits.
    pub fn add_orphan(
        &mut self,
        tx: Transaction,
        missing: HashSet<[u8; 32]>,
        peer: Option<u64>,
    ) -> Result<bool> {
        let txid = tx.txid();

        // Already have this orphan?
        if self.orphans.contains_key(&txid) {
            return Ok(false);
        }

        // Validate missing parents count
        if missing.len() > MAX_MISSING_PARENTS {
            return Err(anyhow!(
                "orphan has {} missing parents, max {}",
                missing.len(),
                MAX_MISSING_PARENTS
            ));
        }

        // Check per-peer limit
        if let Some(peer_id) = peer
            && let Some(peer_orphans) = self.by_peer.get(&peer_id)
            && peer_orphans.len() >= MAX_ORPHANS_PER_PEER
        {
            return Err(anyhow!(
                "peer {} has {} orphans, max {}",
                peer_id,
                peer_orphans.len(),
                MAX_ORPHANS_PER_PEER
            ));
        }

        // Calculate size
        let size = tx.serialize(true).len();

        // Check individual tx size limit
        if size > MAX_ORPHAN_TX_SIZE {
            return Err(anyhow!(
                "orphan tx size {} exceeds max {}",
                size,
                MAX_ORPHAN_TX_SIZE
            ));
        }

        // Evict if at capacity
        while self.orphans.len() >= MAX_ORPHAN_TRANSACTIONS
            || self.total_bytes + size > MAX_ORPHAN_POOL_BYTES
        {
            if self.evict_oldest().is_none() {
                // Nothing to evict but still over limit - shouldn't happen
                return Err(anyhow!("orphan pool full and cannot evict"));
            }
        }

        let received_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = OrphanEntry {
            tx,
            txid,
            size,
            missing_parents: missing.clone(),
            from_peer: peer,
            received_at,
        };

        // Add to main index
        self.orphans.insert(txid, entry);

        // Add to by_missing_parent index
        for parent_txid in &missing {
            self.by_missing_parent
                .entry(*parent_txid)
                .or_default()
                .insert(txid);
        }

        // Add to by_peer index
        if let Some(peer_id) = peer {
            self.by_peer.entry(peer_id).or_default().insert(txid);
        }

        // Track insertion order for LRU
        self.insertion_order.push_back(txid);
        self.total_bytes += size;

        Ok(true)
    }

    /// Get txids of orphans waiting for a specific parent.
    pub fn get_orphans_for_parent(&self, parent_txid: &[u8; 32]) -> Vec<[u8; 32]> {
        self.by_missing_parent
            .get(parent_txid)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Remove an orphan from the pool.
    ///
    /// Returns the entry if it existed.
    pub fn remove_orphan(&mut self, txid: &[u8; 32]) -> Option<OrphanEntry> {
        let entry = self.orphans.remove(txid)?;

        // Remove from by_missing_parent index
        for parent_txid in &entry.missing_parents {
            if let Some(set) = self.by_missing_parent.get_mut(parent_txid) {
                set.remove(txid);
                if set.is_empty() {
                    self.by_missing_parent.remove(parent_txid);
                }
            }
        }

        // Remove from by_peer index
        if let Some(peer_id) = entry.from_peer
            && let Some(set) = self.by_peer.get_mut(&peer_id)
        {
            set.remove(txid);
            if set.is_empty() {
                self.by_peer.remove(&peer_id);
            }
        }

        // Remove from insertion order
        self.insertion_order.retain(|id| id != txid);

        self.total_bytes = self.total_bytes.saturating_sub(entry.size);

        Some(entry)
    }

    /// Notify that a parent has been found, removing it from an orphan's missing set.
    ///
    /// Returns `true` if this was the last missing parent (orphan is now resolvable).
    pub fn parent_found(&mut self, parent_txid: &[u8; 32], orphan_txid: &[u8; 32]) -> bool {
        // Remove orphan from the parent's waiting list
        if let Some(set) = self.by_missing_parent.get_mut(parent_txid) {
            set.remove(orphan_txid);
            if set.is_empty() {
                self.by_missing_parent.remove(parent_txid);
            }
        }

        // Update the orphan's missing_parents set
        if let Some(entry) = self.orphans.get_mut(orphan_txid) {
            entry.missing_parents.remove(parent_txid);
            return entry.missing_parents.is_empty();
        }

        false
    }

    /// Evict the oldest orphan (LRU eviction).
    ///
    /// Returns the evicted entry if one was removed.
    fn evict_oldest(&mut self) -> Option<OrphanEntry> {
        // Find oldest that still exists
        while let Some(txid) = self.insertion_order.pop_front() {
            if self.orphans.contains_key(&txid) {
                return self.remove_orphan(&txid);
            }
        }
        None
    }

    /// Remove all orphans from a specific peer.
    ///
    /// Used when disconnecting a peer to clean up their buffered orphans.
    pub fn remove_for_peer(&mut self, peer_id: u64) -> Vec<[u8; 32]> {
        let txids: Vec<[u8; 32]> = self
            .by_peer
            .get(&peer_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default();

        for txid in &txids {
            self.remove_orphan(txid);
        }

        txids
    }

    /// Remove orphans that conflict with a confirmed transaction.
    ///
    /// When a transaction is confirmed, any orphans spending the same
    /// inputs become invalid and should be removed.
    pub fn remove_conflicts(&mut self, spent_outpoints: &[([u8; 32], u32)]) -> Vec<[u8; 32]> {
        let mut removed = Vec::new();

        // Build set of conflicting txids
        let mut to_remove = HashSet::new();
        for (txid, entry) in &self.orphans {
            for vin in &entry.tx.vin {
                if spent_outpoints
                    .iter()
                    .any(|(t, v)| *t == vin.prevout.txid && *v == vin.prevout.vout)
                {
                    to_remove.insert(*txid);
                    break;
                }
            }
        }

        // Remove conflicts
        for txid in to_remove {
            if self.remove_orphan(&txid).is_some() {
                removed.push(txid);
            }
        }

        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OutPoint, TxIn, TxOut};

    fn make_tx(inputs: Vec<[u8; 32]>, out_count: usize) -> Transaction {
        let vin: Vec<TxIn> = inputs
            .into_iter()
            .map(|txid| TxIn {
                prevout: OutPoint { txid, vout: 0 },
                script_sig: vec![],
                sequence: 0xffffffff,
                witness: vec![],
            })
            .collect();

        let vout: Vec<TxOut> = (0..out_count)
            .map(|_| TxOut {
                value: 1000,
                script_pubkey: vec![0x51], // OP_1
            })
            .collect();

        Transaction {
            version: 2,
            vin,
            vout,
            lock_time: 0,
        }
    }

    #[test]
    fn add_and_remove_orphan() {
        let mut pool = OrphanPool::new();
        let parent_txid = [1u8; 32];
        let tx = make_tx(vec![parent_txid], 1);
        let txid = tx.txid();

        let mut missing = HashSet::new();
        missing.insert(parent_txid);

        assert!(pool.add_orphan(tx.clone(), missing.clone(), None).unwrap());
        assert!(pool.contains(&txid));
        assert_eq!(pool.len(), 1);

        // Check parent index
        let orphans = pool.get_orphans_for_parent(&parent_txid);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0], txid);

        // Remove
        let entry = pool.remove_orphan(&txid).unwrap();
        assert_eq!(entry.txid, txid);
        assert!(!pool.contains(&txid));
        assert_eq!(pool.len(), 0);
        assert!(pool.get_orphans_for_parent(&parent_txid).is_empty());
    }

    #[test]
    fn parent_found_resolution() {
        let mut pool = OrphanPool::new();
        let parent1 = [1u8; 32];
        let parent2 = [2u8; 32];
        let tx = make_tx(vec![parent1, parent2], 1);
        let txid = tx.txid();

        let mut missing = HashSet::new();
        missing.insert(parent1);
        missing.insert(parent2);

        pool.add_orphan(tx, missing, None).unwrap();

        // First parent found - not yet resolvable
        assert!(!pool.parent_found(&parent1, &txid));
        assert!(pool.contains(&txid));

        // Second parent found - now resolvable
        assert!(pool.parent_found(&parent2, &txid));
        // Still in pool until explicitly removed after mempool add
        assert!(pool.contains(&txid));
    }

    #[test]
    fn lru_eviction() {
        let mut pool = OrphanPool::new();

        // Add orphans up to limit
        for i in 0..MAX_ORPHAN_TRANSACTIONS {
            let parent = [(i as u8).wrapping_add(100); 32];
            let tx = make_tx(vec![parent], 1);
            let mut missing = HashSet::new();
            missing.insert(parent);
            pool.add_orphan(tx, missing, None).unwrap();
        }

        assert_eq!(pool.len(), MAX_ORPHAN_TRANSACTIONS);

        // Get first orphan's txid before eviction
        let first_txid = pool.insertion_order.front().copied().unwrap();
        assert!(pool.contains(&first_txid));

        // Add one more - should evict oldest
        let new_parent = [255u8; 32];
        let new_tx = make_tx(vec![new_parent], 1);
        let mut missing = HashSet::new();
        missing.insert(new_parent);
        pool.add_orphan(new_tx, missing, None).unwrap();

        // Still at max capacity
        assert_eq!(pool.len(), MAX_ORPHAN_TRANSACTIONS);
        // Oldest should be evicted
        assert!(!pool.contains(&first_txid));
    }

    #[test]
    fn per_peer_limit() {
        let mut pool = OrphanPool::new();
        let peer_id = 42;

        // Add up to per-peer limit
        for i in 0..MAX_ORPHANS_PER_PEER {
            let parent = [(i as u8).wrapping_add(100); 32];
            let tx = make_tx(vec![parent], 1);
            let mut missing = HashSet::new();
            missing.insert(parent);
            pool.add_orphan(tx, missing, Some(peer_id)).unwrap();
        }

        // One more from same peer should fail
        let parent = [200u8; 32];
        let tx = make_tx(vec![parent], 1);
        let mut missing = HashSet::new();
        missing.insert(parent);
        let result = pool.add_orphan(tx.clone(), missing.clone(), Some(peer_id));
        assert!(result.is_err());

        // But from different peer should work
        let result = pool.add_orphan(tx, missing, Some(peer_id + 1));
        assert!(result.is_ok());
    }

    #[test]
    fn remove_for_peer() {
        let mut pool = OrphanPool::new();
        let peer1 = 1;
        let peer2 = 2;

        // Add orphans from peer1
        for i in 0..3 {
            let parent = [(i as u8).wrapping_add(100); 32];
            let tx = make_tx(vec![parent], 1);
            let mut missing = HashSet::new();
            missing.insert(parent);
            pool.add_orphan(tx, missing, Some(peer1)).unwrap();
        }

        // Add orphan from peer2
        let parent = [200u8; 32];
        let tx = make_tx(vec![parent], 1);
        let mut missing = HashSet::new();
        missing.insert(parent);
        pool.add_orphan(tx, missing, Some(peer2)).unwrap();

        assert_eq!(pool.len(), 4);

        // Remove peer1's orphans
        let removed = pool.remove_for_peer(peer1);
        assert_eq!(removed.len(), 3);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn too_many_missing_parents() {
        let mut pool = OrphanPool::new();

        // Create tx with too many missing parents
        let parents: Vec<[u8; 32]> = (0..=MAX_MISSING_PARENTS as u8)
            .map(|i| [i.wrapping_add(100); 32])
            .collect();

        let tx = make_tx(parents.clone(), 1);
        let missing: HashSet<[u8; 32]> = parents.into_iter().collect();

        let result = pool.add_orphan(tx, missing, None);
        assert!(result.is_err());
    }
}
