use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::constants::WEIGHT_FLOOR_WU;
use crate::node::blockstore;
use crate::node::chain::{ChainIndex, UndoData};
use crate::node::chainparams::{
    compute_chain_id, compute_genesis_hash, load_chainparams, select_network, to_block_header,
};
use crate::node::mempool::{Mempool, MempoolInfo};
use crate::node::store::{Store, write_state};
use crate::node::utxo::UtxoSet;
use crate::pow::pow_hash;
use crate::types::{Block, BlockHeader, OutPoint, Prevout, Transaction, TxIn, TxOut};
use crate::validation::validate_block_basic;
use crate::varint::read_compact_size;

#[derive(Debug)]
pub struct Node {
    pub chain: String,
    pub datadir: PathBuf,
    pub store: Store,
    utxo: UtxoSet,
    mempool: Mempool,
    chain_index: ChainIndex,
    #[allow(dead_code)]
    params_path: PathBuf,
    no_pow: bool,
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

        // Ensure genesis block bytes are present in blockstore
        if blockstore::get_block(datadir, &genesis.block_hash_hex)?.is_none() {
            let genesis_block = build_genesis_block(genesis)?;
            let bytes = genesis_block.serialize(true);
            blockstore::put_block(datadir, &genesis.block_hash_hex, &bytes)?;
            if utxo.is_empty() {
                populate_utxo_from_block(&mut utxo, &genesis_block);
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
            mempool: Mempool::new(),
            chain_index,
            params_path,
            no_pow,
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

    pub fn utxo_get(&self, txid: &[u8; 32], vout: u32) -> Option<Prevout> {
        self.utxo.get(txid, vout)
    }

    pub fn no_pow(&self) -> bool {
        self.no_pow
    }

    /// Add a transaction to the mempool.
    pub fn add_to_mempool(&mut self, tx: Transaction) -> Result<[u8; 32]> {
        // Gather prevouts for the transaction
        let mut prevouts = Vec::with_capacity(tx.vin.len());
        for vin in &tx.vin {
            // First check mempool for unconfirmed parents
            if let Some(parent_entry) = self.mempool.get(&vin.prevout.txid) {
                let vout_idx = vin.prevout.vout as usize;
                if vout_idx >= parent_entry.tx.vout.len() {
                    anyhow::bail!("invalid prevout index");
                }
                let txout = &parent_entry.tx.vout[vout_idx];
                prevouts.push(Prevout {
                    value: txout.value,
                    script_pubkey: txout.script_pubkey.clone(),
                });
            } else if let Some(prev) = self.utxo.get(&vin.prevout.txid, vin.prevout.vout) {
                prevouts.push(prev);
            } else {
                anyhow::bail!(
                    "missing prevout: {}:{}",
                    hex::encode(vin.prevout.txid),
                    vin.prevout.vout
                );
            }
        }

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

    /// Select transactions from mempool for block building.
    pub fn mempool_select_for_block(&self, max_weight: u32) -> Vec<Transaction> {
        self.mempool
            .select_for_block(max_weight)
            .into_iter()
            .map(|e| e.tx.clone())
            .collect()
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

        for tx in block.txdata.iter().skip(1) {
            let mut v = Vec::with_capacity(tx.vin.len());
            for txin in &tx.vin {
                let prev = self
                    .utxo
                    .get(&txin.prevout.txid, txin.prevout.vout)
                    .ok_or_else(|| anyhow!("missing prevout"))?;
                // Save for undo
                undo.add_spent(txin.prevout.txid, txin.prevout.vout, &prev);
                v.push(prev);
            }
            prevouts_by_tx.push(v);
        }

        validate_block_basic(
            block,
            &prevouts_by_tx,
            WEIGHT_FLOOR_WU,
            WEIGHT_FLOOR_WU,
            !self.no_pow,
            (self.store.height() + 1) as u32,
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
        for tx in &block.txdata {
            let txid = tx.txid();
            for (vout, txout) in tx.vout.iter().enumerate() {
                self.utxo
                    .insert(&txid, vout as u32, txout.value, txout.script_pubkey.clone());
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

        // Disconnect blocks (in reverse order - newest first)
        for hash in disconnect_path.iter().rev() {
            let hash_hex = hex::encode(hash);
            self.disconnect_block(&hash_hex)?;
        }

        // Connect blocks (in order - oldest first)
        for hash in &connect_path {
            let hash_hex = hex::encode(hash);
            let block_bytes = blockstore::get_block(&self.datadir, &hash_hex)?
                .ok_or_else(|| anyhow!("block not found: {}", hash_hex))?;
            let block = parse_block(&block_bytes)?;
            self.connect_block(&block, &hash_hex)?;
        }

        // Update chain index tip
        self.chain_index.set_tip(*new_tip);

        Ok(())
    }
}

fn populate_utxo_from_block(utxo: &mut UtxoSet, block: &Block) {
    for tx in &block.txdata {
        let txid = tx.txid();
        for (vout, txout) in tx.vout.iter().enumerate() {
            utxo.insert(&txid, vout as u32, txout.value, txout.script_pubkey.clone());
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
