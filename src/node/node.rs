use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};

use std::collections::HashSet;

use crate::constants::{COINBASE_MATURITY, MAX_REORG_DEPTH, WEIGHT_FLOOR_WU};
use crate::node::blockstore;
use crate::node::chain::{ChainIndex, UndoData};
use crate::node::chainparams::{
    compute_chain_id, compute_genesis_hash, load_chainparams, select_network, to_block_header,
};
use crate::node::checkpoints::CheckpointVerifier;
use crate::node::discovery::{AddrManager, MAX_ADDR_MANAGER_SIZE};
use crate::node::feeest::{BlockFeeStats, FeeEstimate, FeeEstimator};
use crate::node::mempool::{Mempool, MempoolEntry, MempoolInfo};
use crate::node::orphan::OrphanPool;
use crate::node::peer::{BanList, PeerManager};
use crate::node::store::{Store, write_state};
use crate::node::utxo::UtxoSet;
use crate::pow::pow_hash;
use crate::types::{Block, BlockHeader, OutPoint, Prevout, Transaction, TxIn, TxOut};
use crate::validation::validate_block_basic;
use crate::varint::read_compact_size;

/// Result of attempting to add a transaction.
#[derive(Debug)]
pub enum AddTxResult {
    /// Transaction was accepted into mempool.
    Accepted([u8; 32]),
    /// Transaction was added to orphan pool (missing parents).
    Orphaned {
        txid: [u8; 32],
        missing: Vec<[u8; 32]>,
    },
    /// Transaction was rejected.
    Rejected(String),
}

/// Internal error type for transaction addition.
#[derive(Debug)]
enum AddError {
    /// Transaction has missing input(s).
    MissingInputs(Vec<[u8; 32]>),
    /// Other validation error.
    Other(String),
}

#[derive(Debug)]
pub struct Node {
    pub chain: String,
    pub datadir: PathBuf,
    pub store: Store,
    utxo: UtxoSet,
    mempool: Mempool,
    orphan_pool: OrphanPool,
    chain_index: ChainIndex,
    fee_estimator: FeeEstimator,
    #[allow(dead_code)]
    params_path: PathBuf,
    no_pow: bool,
    /// Checkpoint verifier for chain validation.
    checkpoint_verifier: CheckpointVerifier,
    /// Persistent ban list for misbehaving peers.
    ban_list: BanList,
    /// Cached unlocked wallet (for encrypted wallets).
    wallet: Option<super::wallet::Wallet>,
    /// Peer manager for tracking connected peers (inbound and outbound).
    peer_manager: Option<Arc<PeerManager>>,
    /// Address manager for peer discovery.
    addr_manager: AddrManager,
}

impl Node {
    pub fn open_or_init(chain: &str, datadir: &Path, no_pow: bool) -> Result<Self> {
        let params_path = PathBuf::from("docs/chain/chainparams.json");
        let params = load_chainparams(&params_path)?;
        let net = select_network(&params, chain)?;
        let genesis = net
            .genesis
            .as_ref()
            .ok_or_else(|| anyhow!("genesis missing for chain {}", chain))?;

        // Validate genesis hash and chain_id
        let header = &genesis.header;
        let computed_hash = compute_genesis_hash(header)?;
        let stored_hash =
            hex::decode(&genesis.block_hash_hex).context("decode stored genesis block hash")?;
        if computed_hash.as_ref() != stored_hash {
            anyhow::bail!("genesis block hash mismatch for {}", chain);
        }
        let computed_chain_id = compute_chain_id(header)?;
        let stored_chain_id =
            hex::decode(&genesis.chain_id_hex).context("decode stored chain id")?;
        if computed_chain_id.as_ref() != stored_chain_id {
            anyhow::bail!("genesis chain_id mismatch for {}", chain);
        }

        let store = Store::open_or_init(datadir, chain, &genesis.block_hash_hex)?;
        let mut utxo = UtxoSet::load(datadir)?;

        // Load mempool, validating transactions against current UTXO set
        let (mempool, mempool_stats) = Mempool::load(datadir, |txid, vout| utxo.get(txid, vout))?;
        if mempool_stats.loaded > 0 || mempool_stats.invalid > 0 {
            eprintln!(
                "mempool: loaded {} txs ({} invalid, {} parse errors)",
                mempool_stats.loaded, mempool_stats.invalid, mempool_stats.parse_failed
            );
        }

        // Ensure genesis block bytes are present in blockstore
        if blockstore::get_block(datadir, &genesis.block_hash_hex)?.is_none() {
            let genesis_block = build_genesis_block(genesis)?;
            let bytes = genesis_block.serialize(true);
            blockstore::put_block(datadir, &genesis.block_hash_hex, &bytes)?;
            if utxo.is_empty() {
                populate_utxo_from_block(&mut utxo, &genesis_block, 0);
                utxo.save(datadir)?;
            }
        }

        // Initialize chain index from stored state
        let mut chain_index = ChainIndex::new();
        let mut genesis_hash = [0u8; 32];
        genesis_hash.copy_from_slice(&stored_hash);
        chain_index.init_genesis(genesis_hash, [0u8; 32]);

        // Rebuild chain index from stored block hashes
        for (height, hash_hex) in store.index.hashes.iter().enumerate() {
            if height == 0 {
                continue; // Genesis already added
            }
            let mut hash = [0u8; 32];
            if let Ok(h) = hex::decode(hash_hex)
                && h.len() == 32
            {
                hash.copy_from_slice(&h);
                // Get prev hash from previous height
                if let Some(prev_hex) = store.index.hashes.get(height - 1) {
                    let mut prev_hash = [0u8; 32];
                    if let Ok(p) = hex::decode(prev_hex)
                        && p.len() == 32
                    {
                        prev_hash.copy_from_slice(&p);
                        let _ = chain_index.add_block(hash, prev_hash);
                        chain_index.mark_valid(&hash);
                    }
                }
            }
        }

        Ok(Self {
            chain: chain.to_string(),
            datadir: datadir.to_path_buf(),
            store,
            utxo,
            mempool,
            orphan_pool: OrphanPool::new(),
            chain_index,
            fee_estimator: FeeEstimator::new(),
            params_path,
            no_pow,
            checkpoint_verifier: CheckpointVerifier::new(chain),
            ban_list: BanList::load(datadir).unwrap_or_else(|_| BanList::new()),
            wallet: None,
            peer_manager: None,
            addr_manager: AddrManager::load(datadir, MAX_ADDR_MANAGER_SIZE)
                .unwrap_or_else(|_| AddrManager::new(MAX_ADDR_MANAGER_SIZE)),
        })
    }

    pub fn height(&self) -> u64 {
        self.store.height()
    }

    pub fn best_hash_hex(&self) -> &str {
        self.store.tip_hash()
    }

    pub fn get_blockhash(&self, height: u64) -> Option<String> {
        self.store.index.hashes.get(height as usize).cloned()
    }

    pub fn get_block_bytes(&self, hash_hex: &str) -> Option<Vec<u8>> {
        blockstore::get_block(&self.datadir, hash_hex)
            .ok()
            .flatten()
    }

    /// Check if we have a block by its hash (raw bytes, not hex).
    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.get_block_bytes(&hex::encode(hash)).is_some()
    }

    /// Get a reference to the cached wallet (if unlocked).
    pub fn wallet(&self) -> Option<&super::wallet::Wallet> {
        self.wallet.as_ref()
    }

    /// Get a mutable reference to the cached wallet (if unlocked).
    pub fn wallet_mut(&mut self) -> Option<&mut super::wallet::Wallet> {
        self.wallet.as_mut()
    }

    /// Set the cached wallet.
    pub fn set_wallet(&mut self, wallet: Option<super::wallet::Wallet>) {
        self.wallet = wallet;
    }

    /// Get a reference to the address manager.
    pub fn addr_manager(&self) -> &AddrManager {
        &self.addr_manager
    }

    /// Get a mutable reference to the address manager.
    pub fn addr_manager_mut(&mut self) -> &mut AddrManager {
        &mut self.addr_manager
    }

    /// Get a reference to the checkpoint verifier.
    pub fn checkpoint_verifier(&self) -> &CheckpointVerifier {
        &self.checkpoint_verifier
    }

    /// Get a reference to the ban list.
    pub fn ban_list(&self) -> &BanList {
        &self.ban_list
    }

    /// Get a mutable reference to the ban list.
    pub fn ban_list_mut(&mut self) -> &mut BanList {
        &mut self.ban_list
    }

    // ---- Peer Management Methods ----

    /// Initialize the peer manager for P2P connections.
    ///
    /// Creates a PeerManager with a shared ban list. Must be called before
    /// starting the inbound listener. Returns the PeerManager for use with
    /// InboundListener::start().
    pub fn init_peer_manager(&mut self) -> Arc<PeerManager> {
        let ban_list = Arc::new(Mutex::new(BanList::new()));
        let peer_manager = Arc::new(PeerManager::new(ban_list));
        self.peer_manager = Some(Arc::clone(&peer_manager));
        peer_manager
    }

    /// Set the peer manager (for testing or external initialization).
    pub fn set_peer_manager(&mut self, pm: Arc<PeerManager>) {
        self.peer_manager = Some(pm);
    }

    /// Get the count of connected peers.
    ///
    /// Returns (inbound_count, outbound_count). Returns (0, 0) if peer manager
    /// is not initialized.
    pub fn peer_count(&self) -> (usize, usize) {
        match &self.peer_manager {
            Some(pm) => pm.peer_counts(),
            None => (0, 0),
        }
    }

    /// Get a reference to the peer manager (if initialized).
    pub fn peer_manager(&self) -> Option<&Arc<PeerManager>> {
        self.peer_manager.as_ref()
    }

    /// Extract the timestamp from block bytes (offset 68-71 in the 80-byte header).
    fn extract_block_time(block_bytes: &[u8]) -> u32 {
        if block_bytes.len() < 76 {
            return 0;
        }
        u32::from_le_bytes([
            block_bytes[68],
            block_bytes[69],
            block_bytes[70],
            block_bytes[71],
        ])
    }

    /// Compute Median Time Past (MTP) for the block at the given height.
    /// MTP is the median of the timestamps of the last 11 blocks (BIP113).
    /// Returns 0 for height 0.
    pub fn compute_mtp(&self, height: u64) -> u32 {
        use crate::constants::MTP_BLOCKS;

        if height == 0 {
            return 0;
        }

        // Collect timestamps from the last MTP_BLOCKS blocks (or fewer if not enough)
        let start = height.saturating_sub(MTP_BLOCKS as u64 - 1);
        let mut timestamps: Vec<u32> = Vec::with_capacity(MTP_BLOCKS);

        for h in start..=height {
            if let Some(hash_hex) = self.get_blockhash(h)
                && let Some(block_bytes) = self.get_block_bytes(&hash_hex)
            {
                timestamps.push(Self::extract_block_time(&block_bytes));
            }
        }

        crate::validation::compute_mtp(&timestamps)
    }

    pub fn utxo_get(&self, txid: &[u8; 32], vout: u32) -> Option<Prevout> {
        self.utxo.get(txid, vout)
    }

    /// Iterate over all UTXOs in the set.
    pub fn utxo_iter_all(&self) -> Vec<(String, u32, Prevout)> {
        self.utxo.iter_all()
    }

    pub fn no_pow(&self) -> bool {
        self.no_pow
    }

    /// Add a transaction to the mempool.
    pub fn add_to_mempool(&mut self, tx: Transaction) -> Result<[u8; 32]> {
        // Gather prevouts for the transaction
        let mut prevouts = Vec::with_capacity(tx.vin.len());
        let current_height = self.store.height() as u32;

        for vin in &tx.vin {
            // First check mempool for unconfirmed parents
            if let Some(parent_entry) = self.mempool.get(&vin.prevout.txid) {
                let vout_idx = vin.prevout.vout as usize;
                if vout_idx >= parent_entry.tx.vout.len() {
                    anyhow::bail!("invalid prevout index");
                }
                let txout = &parent_entry.tx.vout[vout_idx];
                // Mempool outputs are unconfirmed (height=0) and never coinbase
                prevouts.push(Prevout {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey.clone(),
                    height: 0,
                    is_coinbase: false,
                });
            } else if let Some(prev) = self.utxo.get(&vin.prevout.txid, vin.prevout.vout) {
                // Check coinbase maturity for mempool acceptance
                if prev.is_coinbase {
                    let confirmations = current_height.saturating_sub(prev.height);
                    if confirmations < COINBASE_MATURITY {
                        anyhow::bail!(
                            "coinbase output not mature: {} confirmations, need {}",
                            confirmations,
                            COINBASE_MATURITY
                        );
                    }
                }
                prevouts.push(prev);
            } else {
                anyhow::bail!(
                    "missing prevout: {}:{}",
                    hex::encode(vin.prevout.txid),
                    vin.prevout.vout
                );
            }
        }

        // Check absolute locktime before accepting into mempool (BIP113)
        // Use next block height and current MTP for evaluation
        let current_mtp = self.compute_mtp(self.store.height());
        crate::validation::check_locktime_for_mempool(&tx, current_height, current_mtp)
            .map_err(|e| anyhow::anyhow!("locktime not satisfied: {}", e))?;

        // Check relative locktimes before accepting into mempool (BIP68)
        let get_mtp_at_height = |h: u32| self.compute_mtp(h as u64);
        crate::validation::check_sequence_locks_for_mempool(
            &tx,
            &prevouts,
            current_height,
            current_mtp,
            get_mtp_at_height,
        )
        .map_err(|e| anyhow::anyhow!("relative locktime not satisfied: {}", e))?;

        // Use a closure that captures our UTXO set for any additional lookups
        let utxo_ref = &self.utxo;
        self.mempool
            .add_transaction(tx, prevouts, |txid, vout| utxo_ref.get(txid, vout))
    }

    /// Get mempool info.
    pub fn mempool_info(&self) -> MempoolInfo {
        self.mempool.get_info()
    }

    /// Get a transaction from the mempool.
    pub fn mempool_get(&self, txid: &[u8; 32]) -> Option<&Transaction> {
        self.mempool.get(txid).map(|e| &e.tx)
    }

    /// Get a mempool entry with full metadata (for RBF, fee inspection, etc.).
    pub fn mempool_get_entry(&self, txid: &[u8; 32]) -> Option<MempoolEntry> {
        self.mempool.get(txid).cloned()
    }

    /// Check if a transaction is in the mempool.
    pub fn mempool_contains(&self, txid: &[u8; 32]) -> bool {
        self.mempool.contains(txid)
    }

    /// Get all txids in the mempool.
    pub fn mempool_txids(&self) -> Vec<[u8; 32]> {
        self.mempool.all_txids()
    }

    /// Select transactions from mempool for block building.
    pub fn mempool_select_for_block(&self, max_weight: u32) -> Vec<Transaction> {
        self.mempool
            .select_for_block(max_weight)
            .into_iter()
            .map(|e| e.tx.clone())
            .collect()
    }

    /// Select transactions from mempool with full entry metadata (for block templates).
    pub fn mempool_select_entries_for_block(
        &self,
        max_weight: u32,
    ) -> Vec<crate::node::mempool::MempoolEntry> {
        self.mempool
            .select_for_block(max_weight)
            .into_iter()
            .cloned()
            .collect()
    }

    // ---- Orphan Pool Methods ----

    /// Add a transaction, routing to orphan pool if parents are missing.
    ///
    /// This is the main entry point for transactions received from peers.
    /// Unlike `add_to_mempool`, this won't fail for missing parents - it
    /// will buffer the transaction as an orphan instead.
    pub fn add_transaction_or_orphan(&mut self, tx: Transaction, peer: Option<u64>) -> AddTxResult {
        let txid = tx.txid();

        // Try to add directly to mempool
        match self.try_add_to_mempool_with_missing(&tx) {
            Ok(()) => {
                // Success! Now process any orphans that were waiting for this tx
                let resolved = self.process_orphan_resolution(&txid);
                if !resolved.is_empty() {
                    // Log or handle resolved orphans if needed
                }
                AddTxResult::Accepted(txid)
            }
            Err(AddError::MissingInputs(missing)) => {
                // Transaction has missing parents - add to orphan pool
                let missing_set: HashSet<[u8; 32]> = missing.iter().copied().collect();
                match self.orphan_pool.add_orphan(tx, missing_set, peer) {
                    Ok(true) => AddTxResult::Orphaned {
                        txid,
                        missing: missing.clone(),
                    },
                    Ok(false) => {
                        // Already in orphan pool
                        AddTxResult::Orphaned { txid, missing }
                    }
                    Err(e) => AddTxResult::Rejected(format!("orphan rejected: {}", e)),
                }
            }
            Err(AddError::Other(msg)) => AddTxResult::Rejected(msg),
        }
    }

    /// Try to add a transaction to mempool, returning missing inputs if any.
    fn try_add_to_mempool_with_missing(&mut self, tx: &Transaction) -> Result<(), AddError> {
        let mut prevouts = Vec::with_capacity(tx.vin.len());
        let mut missing = Vec::new();
        let current_height = self.store.height() as u32;

        for vin in &tx.vin {
            // First check mempool for unconfirmed parents
            if let Some(parent_entry) = self.mempool.get(&vin.prevout.txid) {
                let vout_idx = vin.prevout.vout as usize;
                if vout_idx >= parent_entry.tx.vout.len() {
                    return Err(AddError::Other("invalid prevout index".to_string()));
                }
                let txout = &parent_entry.tx.vout[vout_idx];
                prevouts.push(Prevout {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey.clone(),
                    height: 0,
                    is_coinbase: false,
                });
            } else if let Some(prev) = self.utxo.get(&vin.prevout.txid, vin.prevout.vout) {
                // Check coinbase maturity
                if prev.is_coinbase {
                    let confirmations = current_height.saturating_sub(prev.height);
                    if confirmations < COINBASE_MATURITY {
                        return Err(AddError::Other(format!(
                            "coinbase output not mature: {} confirmations, need {}",
                            confirmations, COINBASE_MATURITY
                        )));
                    }
                }
                prevouts.push(prev);
            } else {
                // Missing input - record and continue to find all missing
                missing.push(vin.prevout.txid);
                // Push placeholder to maintain index alignment
                prevouts.push(Prevout {
                    value: 0,
                    script_pubkey: vec![],
                    height: 0,
                    is_coinbase: false,
                });
            }
        }

        if !missing.is_empty() {
            return Err(AddError::MissingInputs(missing));
        }

        // Check absolute locktime
        let current_mtp = self.compute_mtp(self.store.height());
        crate::validation::check_locktime_for_mempool(tx, current_height, current_mtp)
            .map_err(|e| AddError::Other(format!("locktime not satisfied: {}", e)))?;

        // Check relative locktimes
        let get_mtp_at_height = |h: u32| self.compute_mtp(h as u64);
        crate::validation::check_sequence_locks_for_mempool(
            tx,
            &prevouts,
            current_height,
            current_mtp,
            get_mtp_at_height,
        )
        .map_err(|e| AddError::Other(format!("relative locktime not satisfied: {}", e)))?;

        // Add to mempool
        let utxo_ref = &self.utxo;
        self.mempool
            .add_transaction(tx.clone(), prevouts, |txid, vout| utxo_ref.get(txid, vout))
            .map_err(|e| AddError::Other(e.to_string()))?;

        Ok(())
    }

    /// Process orphan resolution when a parent transaction is added.
    ///
    /// Returns txids of orphans that were successfully added to mempool.
    fn process_orphan_resolution(&mut self, parent_txid: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut resolved = Vec::new();
        let mut to_process = vec![*parent_txid];

        while let Some(parent) = to_process.pop() {
            // Get orphans waiting for this parent
            let waiting = self.orphan_pool.get_orphans_for_parent(&parent);

            for orphan_txid in waiting {
                // Mark this parent as found
                let all_found = self.orphan_pool.parent_found(&parent, &orphan_txid);

                if all_found {
                    // All parents found - try to add to mempool
                    if let Some(entry) = self.orphan_pool.remove_orphan(&orphan_txid) {
                        match self.try_add_to_mempool_with_missing(&entry.tx) {
                            Ok(()) => {
                                resolved.push(orphan_txid);
                                // This resolved orphan might unlock more orphans
                                to_process.push(orphan_txid);
                            }
                            Err(AddError::MissingInputs(missing)) => {
                                // Still missing some parents - re-add as orphan
                                let missing_set: HashSet<[u8; 32]> = missing.into_iter().collect();
                                let _ = self.orphan_pool.add_orphan(
                                    entry.tx,
                                    missing_set,
                                    entry.from_peer,
                                );
                            }
                            Err(_) => {
                                // Invalid for some other reason - drop it
                            }
                        }
                    }
                }
            }
        }

        resolved
    }

    /// Get the number of orphan transactions.
    pub fn orphan_count(&self) -> usize {
        self.orphan_pool.len()
    }

    /// Check if a transaction is in the orphan pool.
    pub fn orphan_contains(&self, txid: &[u8; 32]) -> bool {
        self.orphan_pool.contains(txid)
    }

    /// Remove all orphans from a disconnected peer.
    pub fn remove_orphans_for_peer(&mut self, peer_id: u64) -> Vec<[u8; 32]> {
        self.orphan_pool.remove_for_peer(peer_id)
    }

    pub fn submit_block_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let block = parse_block(bytes)?;
        let block_hash = pow_hash(&block.header)?;
        let block_hash_hex = hex::encode(block_hash);
        let prev_hex = hex::encode(block.header.prev_blockhash);

        // Already have this block?
        if self.chain_index.contains(&block_hash) {
            return Ok(()); // Already processed
        }

        // Verify against checkpoints before storing
        // Height is parent height + 1; if parent unknown, we check later during connect
        if let Some(parent_meta) = self.chain_index.get(&block.header.prev_blockhash) {
            let block_height = parent_meta.height + 1;
            self.checkpoint_verifier.verify(block_height, &block_hash)?;
        }

        // Store block data first
        blockstore::put_block(&self.datadir, &block_hash_hex, bytes)?;

        // Add to chain index
        let is_new_tip = self
            .chain_index
            .add_block(block_hash, block.header.prev_blockhash)?;

        // If parent is unknown, we've stored it as orphan - nothing more to do
        if !self.chain_index.contains(&block.header.prev_blockhash) {
            return Ok(());
        }

        // Check if this extends the current tip directly
        if prev_hex == self.store.tip_hash() {
            // Simple case: extends tip directly
            self.connect_block(&block, &block_hash_hex)?;
        } else if is_new_tip {
            // New tip on a different branch - need to reorg
            self.reorganize_to(&block_hash)?;
        }
        // Otherwise it's a competing block that didn't become tip - just store it

        Ok(())
    }

    /// Connect a block to the active chain (must be direct child of current tip).
    fn connect_block(&mut self, block: &Block, block_hash_hex: &str) -> Result<()> {
        // Build prevouts for each tx
        let mut prevouts_by_tx: Vec<Vec<Prevout>> = Vec::with_capacity(block.txdata.len());
        prevouts_by_tx.push(Vec::new()); // coinbase

        // Collect undo data as we gather prevouts
        let mut undo = UndoData::new();

        let new_height = (self.store.height() + 1) as u32;
        for tx in block.txdata.iter().skip(1) {
            let mut v = Vec::with_capacity(tx.vin.len());
            for txin in &tx.vin {
                let prev = self
                    .utxo
                    .get(&txin.prevout.txid, txin.prevout.vout)
                    .ok_or_else(|| anyhow!("missing prevout"))?;

                // Check coinbase maturity
                if prev.is_coinbase {
                    let confirmations = new_height.saturating_sub(prev.height);
                    if confirmations < COINBASE_MATURITY {
                        anyhow::bail!(
                            "coinbase output not mature: {} confirmations, need {}",
                            confirmations,
                            COINBASE_MATURITY
                        );
                    }
                }

                // Save for undo
                undo.add_spent(txin.prevout.txid, txin.prevout.vout, &prev);
                v.push(prev);
            }
            prevouts_by_tx.push(v);
        }

        // Compute MTP for locktime validation (based on blocks up to parent)
        let current_height = self.store.height();
        let mtp = self.compute_mtp(current_height);

        // For BIP68 time-based relative locks, we need MTP at prevout heights
        let get_mtp_at_height = |h: u32| self.compute_mtp(h as u64);

        validate_block_basic(
            block,
            &prevouts_by_tx,
            WEIGHT_FLOOR_WU,
            WEIGHT_FLOOR_WU,
            !self.no_pow,
            new_height,
            mtp,
            get_mtp_at_height,
        )?;

        // Store undo data before modifying UTXO set
        blockstore::put_undo(&self.datadir, block_hash_hex, &undo.to_bytes())?;

        // Apply spends
        for tx in block.txdata.iter().skip(1) {
            for txin in &tx.vin {
                self.utxo.remove(&txin.prevout.txid, txin.prevout.vout);
            }
        }
        // Add outputs
        for (tx_idx, tx) in block.txdata.iter().enumerate() {
            let txid = tx.txid();
            let is_coinbase = tx_idx == 0;
            for (vout, txout) in tx.vout.iter().enumerate() {
                self.utxo.insert(
                    &txid,
                    vout as u32,
                    txout.value,
                    txout.script_pubkey.clone(),
                    new_height,
                    is_coinbase,
                );
            }
        }
        self.utxo.save(&self.datadir)?;

        // Update state
        self.store.state.height += 1;
        self.store.state.tip_hash_hex = block_hash_hex.to_string();
        self.store.index.hashes.push(block_hash_hex.to_string());
        write_state(&self.store.datadir, &self.store.state, &self.store.index)?;

        // Mark as valid in chain index
        let mut hash = [0u8; 32];
        hex::decode_to_slice(block_hash_hex, &mut hash).ok();
        self.chain_index.mark_valid(&hash);

        // Remove confirmed transactions from mempool
        let confirmed_txids: Vec<[u8; 32]> = block.txdata.iter().map(|tx| tx.txid()).collect();
        self.mempool.remove_confirmed(&confirmed_txids);

        // Persist mempool state
        self.mempool.save(&self.datadir)?;

        // Record fee statistics for fee estimation
        let fee_stats = compute_block_fee_stats(block, &prevouts_by_tx, new_height as u64);
        self.fee_estimator.record_block(fee_stats);

        Ok(())
    }

    /// Disconnect a block from the active chain (must be current tip).
    fn disconnect_block(&mut self, block_hash_hex: &str) -> Result<()> {
        // Load block
        let block_bytes = blockstore::get_block(&self.datadir, block_hash_hex)?
            .ok_or_else(|| anyhow!("block not found: {}", block_hash_hex))?;
        let block = parse_block(&block_bytes)?;

        // Load undo data
        let undo_bytes = blockstore::get_undo(&self.datadir, block_hash_hex)?
            .ok_or_else(|| anyhow!("undo data not found: {}", block_hash_hex))?;
        let undo = UndoData::from_bytes(&undo_bytes)?;

        // Remove outputs added by this block
        for tx in &block.txdata {
            let txid = tx.txid();
            for (vout, _) in tx.vout.iter().enumerate() {
                self.utxo.remove(&txid, vout as u32);
            }
        }

        // Restore spent outputs
        for spent in &undo.spent_outputs {
            self.utxo.insert(
                &spent.txid,
                spent.vout,
                spent.value,
                spent.script_pubkey.clone(),
                spent.height,
                spent.is_coinbase,
            );
        }
        self.utxo.save(&self.datadir)?;

        // Update state
        self.store.state.height -= 1;
        self.store.index.hashes.pop();
        if let Some(prev_hash) = self.store.index.hashes.last() {
            self.store.state.tip_hash_hex = prev_hash.clone();
        }
        write_state(&self.store.datadir, &self.store.state, &self.store.index)?;

        Ok(())
    }

    /// Reorganize the chain to a new tip.
    ///
    /// This performs a full chain reorganization:
    /// 1. Finds the fork point between current and new chain
    /// 2. Disconnects blocks from current tip back to fork point
    /// 3. Connects blocks from fork point to new tip
    /// 4. Restores disconnected transactions to mempool (if still valid)
    fn reorganize_to(&mut self, new_tip: &[u8; 32]) -> Result<()> {
        let current_tip_hex = self.store.tip_hash().to_string();
        let mut current_tip = [0u8; 32];
        hex::decode_to_slice(&current_tip_hex, &mut current_tip)?;

        // Find fork point
        let fork_point = self
            .chain_index
            .find_fork_point(&current_tip, new_tip)
            .ok_or_else(|| anyhow!("no common ancestor found"))?;

        // Get blocks to disconnect (from current tip back to fork point)
        let disconnect_path = self.chain_index.get_path(&fork_point, &current_tip);

        // Get blocks to connect (from fork point to new tip)
        let connect_path = self.chain_index.get_path(&fork_point, new_tip);

        // =====================================================================
        // Pre-validation: Verify reorg is safe before modifying state
        // =====================================================================

        // Check reorg depth limit
        if disconnect_path.len() > MAX_REORG_DEPTH {
            anyhow::bail!(
                "reorg depth {} exceeds maximum {}",
                disconnect_path.len(),
                MAX_REORG_DEPTH
            );
        }

        // Verify all undo data exists for blocks we need to disconnect
        for hash in &disconnect_path {
            let hash_hex = hex::encode(hash);
            if blockstore::get_undo(&self.datadir, &hash_hex)?.is_none() {
                anyhow::bail!("missing undo data for block {}, cannot reorg", hash_hex);
            }
        }

        // Verify all block data exists for blocks we need to connect
        for hash in &connect_path {
            let hash_hex = hex::encode(hash);
            if blockstore::get_block(&self.datadir, &hash_hex)?.is_none() {
                anyhow::bail!("missing block data for {}, cannot reorg", hash_hex);
            }
        }

        // =====================================================================
        // Collect transactions from blocks being disconnected (for mempool)
        // =====================================================================

        let mut disconnected_txs: Vec<Transaction> = Vec::new();
        for hash in &disconnect_path {
            let hash_hex = hex::encode(hash);
            let block_bytes = blockstore::get_block(&self.datadir, &hash_hex)?
                .ok_or_else(|| anyhow!("block not found: {}", hash_hex))?;
            let block = parse_block(&block_bytes)?;
            // Skip coinbase (index 0), collect all other transactions
            for tx in block.txdata.into_iter().skip(1) {
                disconnected_txs.push(tx);
            }
        }

        // =====================================================================
        // Disconnect blocks (in reverse order - newest first)
        // =====================================================================

        for hash in disconnect_path.iter().rev() {
            let hash_hex = hex::encode(hash);
            self.disconnect_block(&hash_hex)?;
        }

        // =====================================================================
        // Connect blocks with rollback on failure
        // =====================================================================

        let mut connected_hashes: Vec<[u8; 32]> = Vec::new();
        let mut confirmed_in_new_chain: HashSet<[u8; 32]> = HashSet::new();

        for hash in &connect_path {
            let hash_hex = hex::encode(hash);
            let block_bytes = blockstore::get_block(&self.datadir, &hash_hex)?
                .ok_or_else(|| anyhow!("block not found: {}", hash_hex))?;
            let block = parse_block(&block_bytes)?;

            // Track txids confirmed in new chain
            for tx in &block.txdata {
                confirmed_in_new_chain.insert(tx.txid());
            }

            match self.connect_block(&block, &hash_hex) {
                Ok(()) => {
                    connected_hashes.push(*hash);
                }
                Err(e) => {
                    // Connection failed - must rollback to original chain
                    eprintln!("reorg failed at block {}: {}, rolling back", hash_hex, e);

                    // Mark the failing block as invalid
                    self.chain_index.mark_invalid(hash);

                    // Disconnect any blocks we just connected
                    for rollback_hash in connected_hashes.iter().rev() {
                        let rollback_hex = hex::encode(rollback_hash);
                        if let Err(re) = self.disconnect_block(&rollback_hex) {
                            eprintln!("rollback disconnect failed: {}", re);
                        }
                    }

                    // Reconnect original chain
                    for original_hash in &disconnect_path {
                        let original_hex = hex::encode(original_hash);
                        if let Ok(Some(bytes)) = blockstore::get_block(&self.datadir, &original_hex)
                            && let Ok(original_block) = parse_block(&bytes)
                            && let Err(re) = self.connect_block(&original_block, &original_hex)
                        {
                            eprintln!("rollback reconnect failed: {}", re);
                        }
                    }

                    // Restore original tip in chain index
                    self.chain_index.set_tip(current_tip);

                    return Err(anyhow!(
                        "reorg failed at {}: {}; rolled back to original chain",
                        hash_hex,
                        e
                    ));
                }
            }
        }

        // =====================================================================
        // Restore disconnected transactions to mempool
        // =====================================================================

        let mut restored_count = 0u32;
        for tx in disconnected_txs {
            let txid = tx.txid();

            // Skip if already confirmed in the new chain
            if confirmed_in_new_chain.contains(&txid) {
                continue;
            }

            // Check for double-spend conflicts with new chain
            let mut conflicts = false;
            for vin in &tx.vin {
                if self.utxo.get(&vin.prevout.txid, vin.prevout.vout).is_none() {
                    conflicts = true;
                    break;
                }
            }

            if conflicts {
                continue;
            }

            // Try to re-add to mempool - ignore errors
            if self.try_add_to_mempool_with_missing(&tx).is_ok() {
                restored_count += 1;
            }
        }

        if restored_count > 0 {
            // Save mempool with restored transactions
            let _ = self.mempool.save(&self.datadir);
        }

        // Update chain index tip
        self.chain_index.set_tip(*new_tip);

        Ok(())
    }

    // ---- P2P Transaction Relay Methods ----

    /// Handle incoming INV message for transactions.
    /// Returns list of txids we want to request (not in our mempool).
    pub fn handle_tx_inv(&self, txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
        txids
            .iter()
            .filter(|txid| !self.mempool.contains(txid))
            .copied()
            .collect()
    }

    /// Handle incoming GETDATA request for transactions.
    /// Returns list of transactions we have in mempool.
    pub fn handle_tx_getdata(&self, txids: &[[u8; 32]]) -> Vec<Transaction> {
        txids
            .iter()
            .filter_map(|txid| self.mempool.get(txid).map(|e| e.tx.clone()))
            .collect()
    }

    /// Handle incoming transaction from a peer.
    /// Returns the txid if accepted, or an error if rejected.
    pub fn handle_incoming_tx(&mut self, tx: Transaction) -> Result<[u8; 32]> {
        self.add_to_mempool(tx)
    }

    /// Estimate fee rate for confirmation within target blocks.
    ///
    /// Returns a fee estimate with the recommended sat/vB rate and
    /// any warnings if estimation data was limited.
    pub fn estimate_smart_fee(&self, conf_target: u64) -> FeeEstimate {
        // Use floor weight as max block weight for capacity calculation
        self.fee_estimator
            .estimate(&self.mempool, conf_target, WEIGHT_FLOOR_WU)
    }

    /// Save node state to disk (called on shutdown).
    ///
    /// Persists mempool transactions so they can be restored on restart.
    pub fn save(&self) -> Result<()> {
        self.mempool.save(&self.datadir)?;
        self.ban_list.save()?;
        self.addr_manager.save()?;
        Ok(())
    }
}

fn populate_utxo_from_block(utxo: &mut UtxoSet, block: &Block, height: u32) {
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        let txid = tx.txid();
        let is_coinbase = tx_idx == 0;
        for (vout, txout) in tx.vout.iter().enumerate() {
            utxo.insert(
                &txid,
                vout as u32,
                txout.value,
                txout.script_pubkey.clone(),
                height,
                is_coinbase,
            );
        }
    }
}

fn build_genesis_block(genesis: &crate::node::chainparams::GenesisParams) -> Result<Block> {
    let header = to_block_header(&genesis.header)?;
    let coinbase = parse_transaction(&hex::decode(&genesis.coinbase_tx_hex)?)?;
    let block = Block {
        header,
        txdata: vec![coinbase],
    };
    // sanity check merkle
    let txid = block.txdata[0].txid();
    if txid != block.header.merkle_root {
        anyhow::bail!("genesis merkle mismatch");
    }
    Ok(block)
}

fn parse_block(bytes: &[u8]) -> Result<Block> {
    let mut cur = Cursor::new(bytes.to_vec());

    let mut vbuf = [0u8; 4];
    cur.read_exact(&mut vbuf)?;
    let version = u32::from_le_bytes(vbuf);

    let mut prev_le = [0u8; 32];
    cur.read_exact(&mut prev_le)?;
    let mut prev_blockhash = [0u8; 32];
    prev_blockhash.copy_from_slice(&prev_le.iter().rev().cloned().collect::<Vec<_>>());

    let mut merkle_le = [0u8; 32];
    cur.read_exact(&mut merkle_le)?;
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_le.iter().rev().cloned().collect::<Vec<_>>());

    let mut tbuf = [0u8; 4];
    cur.read_exact(&mut tbuf)?;
    let time = u32::from_le_bytes(tbuf);
    cur.read_exact(&mut tbuf)?;
    let bits = u32::from_le_bytes(tbuf);
    cur.read_exact(&mut tbuf)?;
    let nonce = u32::from_le_bytes(tbuf);

    let tx_count = read_compact_size(&mut cur)? as usize;
    let mut txdata = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        let tx = parse_transaction_cursor(&mut cur)?;
        txdata.push(tx);
    }

    Ok(Block {
        header: BlockHeader {
            version,
            prev_blockhash,
            merkle_root,
            time,
            bits,
            nonce,
        },
        txdata,
    })
}

/// Parse a raw transaction from bytes.
pub fn parse_transaction(bytes: &[u8]) -> Result<Transaction> {
    let mut cur = Cursor::new(bytes.to_vec());
    parse_transaction_cursor(&mut cur)
}

fn parse_transaction_cursor(cur: &mut Cursor<Vec<u8>>) -> Result<Transaction> {
    let mut vbuf = [0u8; 4];
    cur.read_exact(&mut vbuf)?;
    let version = i32::from_le_bytes(vbuf);

    // SegWit detection (marker + flag)
    let mut marker = [0u8; 1];
    cur.read_exact(&mut marker)?;
    let mut segwit = false;
    if marker[0] == 0x00 {
        let mut flag = [0u8; 1];
        cur.read_exact(&mut flag)?;
        if flag[0] == 0x01 {
            segwit = true;
        } else {
            cur.set_position(cur.position() - 2);
        }
    } else {
        cur.set_position(cur.position() - 1);
    }

    let vin_len = read_compact_size(cur)? as usize;
    let mut vin = Vec::with_capacity(vin_len);
    for _ in 0..vin_len {
        let mut txid_le = [0u8; 32];
        cur.read_exact(&mut txid_le)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_le.iter().rev().cloned().collect::<Vec<_>>());
        let mut voutb = [0u8; 4];
        cur.read_exact(&mut voutb)?;
        let vout = u32::from_le_bytes(voutb);
        let script_len = read_compact_size(cur)? as usize;
        let mut script_sig = vec![0u8; script_len];
        cur.read_exact(&mut script_sig)?;
        cur.read_exact(&mut voutb)?;
        let sequence = u32::from_le_bytes(voutb);
        vin.push(TxIn {
            prevout: OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    let vout_len = read_compact_size(cur)? as usize;
    let mut vout_vec = Vec::with_capacity(vout_len);
    for _ in 0..vout_len {
        let mut valb = [0u8; 8];
        cur.read_exact(&mut valb)?;
        let value = u64::from_le_bytes(valb);
        let spk_len = read_compact_size(cur)? as usize;
        let mut script_pubkey = vec![0u8; spk_len];
        cur.read_exact(&mut script_pubkey)?;
        vout_vec.push(TxOut {
            value,
            script_pubkey,
        });
    }

    if segwit {
        for txin in vin.iter_mut() {
            let items = read_compact_size(cur)? as usize;
            let mut stack = Vec::with_capacity(items);
            for _ in 0..items {
                let len = read_compact_size(cur)? as usize;
                let mut item = vec![0u8; len];
                cur.read_exact(&mut item)?;
                stack.push(item);
            }
            txin.witness = stack;
        }
    }

    let mut ltb = [0u8; 4];
    cur.read_exact(&mut ltb)?;
    let lock_time = u32::from_le_bytes(ltb);

    Ok(Transaction {
        version,
        vin,
        vout: vout_vec,
        lock_time,
    })
}

/// Compute fee statistics for a connected block.
///
/// Calculates minimum and median fee rates from transactions in the block.
/// Used to build historical data for fee estimation.
fn compute_block_fee_stats(
    block: &Block,
    prevouts_by_tx: &[Vec<Prevout>],
    height: u64,
) -> BlockFeeStats {
    // Collect fee rates for non-coinbase transactions (scaled by 1000)
    let mut fee_rates: Vec<u64> = Vec::new();
    let mut total_weight: u32 = 0;

    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx_idx == 0 {
            // Skip coinbase
            continue;
        }

        // Calculate fee from prevouts
        let input_sum: u64 = prevouts_by_tx[tx_idx].iter().map(|p| p.value).sum();
        let output_sum: u64 = tx.vout.iter().map(|o| o.value).sum();
        let fee = input_sum.saturating_sub(output_sum);

        // Calculate weight and vsize (same formula as mempool)
        let base_bytes = tx.serialize(false).len();
        let full_bytes = tx.serialize(true).len();
        let witness_bytes = full_bytes.saturating_sub(base_bytes);
        let weight = (4 * base_bytes + witness_bytes) as u32;
        let vsize = weight.div_ceil(4);
        total_weight = total_weight.saturating_add(weight);

        if vsize > 0 {
            // Fee rate in sat/vB * 1000 for precision
            let fee_rate = fee * 1000 / vsize as u64;
            fee_rates.push(fee_rate);
        }
    }

    // Calculate min and median
    let (min_fee_rate, median_fee_rate) = if fee_rates.is_empty() {
        (0, 0)
    } else {
        fee_rates.sort_unstable();
        let min = fee_rates[0];
        let median = fee_rates[fee_rates.len() / 2];
        (min, median)
    };

    BlockFeeStats {
        height,
        min_fee_rate,
        median_fee_rate,
        block_weight: total_weight,
    }
}
