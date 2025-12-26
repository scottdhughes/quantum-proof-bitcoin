use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::constants::WEIGHT_FLOOR_WU;
use crate::node::blockstore;
use crate::node::chainparams::{
    compute_chain_id, compute_genesis_hash, load_chainparams, select_network, to_block_header,
};
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

        Ok(Self {
            chain: chain.to_string(),
            datadir: datadir.to_path_buf(),
            store,
            utxo,
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

    pub fn utxo_get(&self, txid: &[u8; 32], vout: u32) -> Option<Prevout> {
        self.utxo.get(txid, vout)
    }

    pub fn submit_block_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let block = parse_block(bytes)?;

        let prev_hex = hex::encode(block.header.prev_blockhash);
        if prev_hex != self.store.tip_hash() {
            anyhow::bail!("prev block hash does not match tip");
        }

        // Build prevouts for each tx
        let mut prevouts_by_tx: Vec<Vec<Prevout>> = Vec::with_capacity(block.txdata.len());
        prevouts_by_tx.push(Vec::new()); // coinbase
        for tx in block.txdata.iter().skip(1) {
            let mut v = Vec::with_capacity(tx.vin.len());
            for txin in &tx.vin {
                let prev = self
                    .utxo
                    .get(&txin.prevout.txid, txin.prevout.vout)
                    .ok_or_else(|| anyhow!("missing prevout"))?;
                v.push(prev);
            }
            prevouts_by_tx.push(v);
        }

        validate_block_basic(
            &block,
            &prevouts_by_tx,
            WEIGHT_FLOOR_WU,
            WEIGHT_FLOOR_WU,
            !self.no_pow,
            (self.store.height() + 1) as u32,
        )?;

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

        let block_hash = pow_hash(&block.header)?;
        let block_hash_hex = hex::encode(block_hash);
        blockstore::put_block(&self.datadir, &block_hash_hex, bytes)?;

        self.store.state.height += 1;
        self.store.state.tip_hash_hex = block_hash_hex.clone();
        self.store.index.hashes.push(block_hash_hex);
        write_state(&self.store.datadir, &self.store.state, &self.store.index)?;

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

fn parse_transaction(bytes: &[u8]) -> Result<Transaction> {
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
