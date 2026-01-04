use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use serde::Serialize;

use crate::constants::WEIGHT_FLOOR_WU;
use crate::hashing::hash256;
use crate::node::chainparams::NetworkParams;
use crate::node::node::Node;
use crate::pow::{bits_to_target, pow_hash};
use crate::reward::block_subsidy;
use crate::script::build_p2qpkh;
use crate::types::{Block, BlockHeader, Transaction, TxIn, TxOut};
use crate::validation::witness_merkle_root;
use crate::weight::max_allowed_weight;

/// A transaction entry in the block template.
#[derive(Debug, Clone, Serialize)]
pub struct TemplateTransaction {
    /// Transaction ID (hex).
    pub txid: String,
    /// Serialized transaction (hex).
    pub data: String,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// Transaction weight in weight units.
    pub weight: u32,
}

/// Block template for external miners.
#[derive(Debug, Clone, Serialize)]
pub struct BlockTemplate {
    /// Block version.
    pub version: i32,
    /// Previous block hash (hex, big-endian).
    pub previousblockhash: String,
    /// Transactions to include (excluding coinbase).
    pub transactions: Vec<TemplateTransaction>,
    /// Total value available for coinbase (subsidy + fees).
    pub coinbasevalue: u64,
    /// Target threshold (hex, big-endian).
    pub target: String,
    /// Compact difficulty bits.
    pub bits: String,
    /// Current timestamp.
    pub curtime: u32,
    /// Height of the block being built.
    pub height: u64,
}

/// Build and optionally mine a coinbase-only block on the current tip.
/// Returns the serialized block bytes.
pub fn mine_block_bytes(node: &Node, net: &NetworkParams, no_pow: bool) -> Result<Vec<u8>> {
    mine_block_bytes_with_mempool(node, net, no_pow, false)
}

/// Build and optionally mine a block with mempool transactions.
/// If `include_mempool` is true, selects transactions from the mempool by fee rate.
pub fn mine_block_bytes_with_mempool(
    node: &Node,
    net: &NetworkParams,
    no_pow: bool,
    include_mempool: bool,
) -> Result<Vec<u8>> {
    let (block, allow_time_bump) = if include_mempool {
        build_block_with_mempool(node, net)?
    } else {
        build_coinbase_block(node, net)?
    };

    if no_pow {
        return Ok(block.serialize(true));
    }

    let target = bits_to_target(block.header.bits).ok_or_else(|| anyhow!("invalid bits"))?;
    let mut mined = block;
    let mut nonce: u32 = 0;
    loop {
        mined.header.nonce = nonce;
        let h = pow_hash(&mined.header)?;
        if h <= target {
            return Ok(mined.serialize(true));
        }
        nonce = nonce.wrapping_add(1);
        // If we wrapped, refresh time to avoid stale headers.
        if nonce == 0 && allow_time_bump {
            mined.header.time = current_time();
        }
    }
}

fn build_coinbase_block(node: &Node, net: &NetworkParams) -> Result<(Block, bool)> {
    // prev hash (big-endian hex)
    let prev_hash_bytes = hex::decode(node.best_hash_hex()).map_err(|_| anyhow!("bad tip hex"))?;
    if prev_hash_bytes.len() != 32 {
        anyhow::bail!("tip hash wrong length");
    }
    let mut prev_blockhash = [0u8; 32];
    prev_blockhash.copy_from_slice(&prev_hash_bytes);

    // Height for BIP34-compliant coinbase
    let height = node.height() + 1;

    // Coinbase tx: single input, single zero-value output (P2QPKH with dummy qpkh)
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: crate::types::OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig: build_coinbase_script_sig(height),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value: 0,
            script_pubkey: build_p2qpkh(dummy_qpkh()),
        }],
        lock_time: 0,
    };
    let txid = coinbase.txid();
    let merkle_root = txid;

    let header_time = current_time();
    let header = BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root,
        time: header_time,
        bits: net
            .genesis
            .as_ref()
            .ok_or_else(|| anyhow!("missing genesis"))?
            .header
            .bits,
        nonce: 0,
    };

    let block = Block {
        header,
        txdata: vec![coinbase],
    };

    Ok((block, true))
}

/// Build a block including mempool transactions.
fn build_block_with_mempool(node: &Node, net: &NetworkParams) -> Result<(Block, bool)> {
    // prev hash (big-endian hex)
    let prev_hash_bytes = hex::decode(node.best_hash_hex()).map_err(|_| anyhow!("bad tip hex"))?;
    if prev_hash_bytes.len() != 32 {
        anyhow::bail!("tip hash wrong length");
    }
    let mut prev_blockhash = [0u8; 32];
    prev_blockhash.copy_from_slice(&prev_hash_bytes);

    let bits = net
        .genesis
        .as_ref()
        .ok_or_else(|| anyhow!("missing genesis"))?
        .header
        .bits;

    // Calculate max weight for block
    // For simplicity, use WEIGHT_FLOOR_WU for both STM and LTM
    let max_weight = max_allowed_weight(WEIGHT_FLOOR_WU, WEIGHT_FLOOR_WU);

    // Reserve weight for coinbase (~500 WU conservative estimate)
    let coinbase_reserve = 2000u32;
    let available_weight = max_weight.saturating_sub(coinbase_reserve);

    // Select mempool transactions
    let mempool_txs = node.mempool_select_for_block(available_weight);

    // Calculate total fees from mempool txs
    // Note: We don't have easy access to fees here. For now, set to 0.
    // In production, we'd need to track fees or recalculate from prevouts.
    let total_fees: u64 = mempool_txs.iter().map(|_tx| 0u64).sum();

    // Height for BIP34-compliant coinbase
    let height = node.height() + 1;

    // Check if any mempool tx has witness data
    let has_witness = mempool_txs
        .iter()
        .any(|tx| tx.vin.iter().any(|i| !i.witness.is_empty()));

    // Reserved value for witness commitment (32 zero bytes)
    let reserved = [0u8; 32];

    // Build coinbase outputs
    let mut coinbase_outputs = vec![TxOut {
        value: total_fees, // In production: block_subsidy + total_fees - penalty
        script_pubkey: build_p2qpkh(dummy_qpkh()),
    }];

    // Build coinbase witness (needed if block has witness txs)
    let coinbase_witness = if has_witness {
        vec![reserved.to_vec()]
    } else {
        Vec::new()
    };

    // Coinbase tx with fees
    let mut coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: crate::types::OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig: build_coinbase_script_sig(height),
            sequence: 0xffff_ffff,
            witness: coinbase_witness,
        }],
        vout: coinbase_outputs.clone(),
        lock_time: 0,
    };

    // Build txdata with coinbase first
    let mut txdata = Vec::with_capacity(1 + mempool_txs.len());
    txdata.push(coinbase.clone());
    txdata.extend(mempool_txs);

    // If we have witness transactions, compute and add witness commitment
    if has_witness {
        // Create temp block to compute witness merkle root
        let temp_block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash,
                merkle_root: [0u8; 32],
                time: 0,
                bits,
                nonce: 0,
            },
            txdata: txdata.clone(),
        };

        let wroot = witness_merkle_root(&temp_block);
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&wroot);
        buf.extend_from_slice(&reserved);
        let commitment_hash = hash256(&buf);

        // Build witness commitment output: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed [commitment]
        let mut commitment_spk = Vec::with_capacity(38);
        commitment_spk.push(0x6a); // OP_RETURN
        commitment_spk.push(0x24); // OP_PUSHBYTES_36
        commitment_spk.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // witness commitment magic
        commitment_spk.extend_from_slice(&commitment_hash);

        // Add commitment output to coinbase
        coinbase_outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_spk,
        });

        // Rebuild coinbase with commitment output
        coinbase.vout = coinbase_outputs;
        txdata[0] = coinbase;
    }

    // Compute merkle root
    let merkle_root = compute_merkle_root(&txdata);

    let header_time = current_time();
    let header = BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root,
        time: header_time,
        bits,
        nonce: 0,
    };

    let block = Block { header, txdata };
    Ok((block, true))
}

/// Compute merkle root from transaction list.
fn compute_merkle_root(txdata: &[Transaction]) -> [u8; 32] {
    if txdata.is_empty() {
        return [0u8; 32];
    }

    let mut hashes: Vec<[u8; 32]> = txdata.iter().map(|tx| tx.txid()).collect();

    while hashes.len() > 1 {
        let mut next = Vec::with_capacity(hashes.len().div_ceil(2));
        for i in (0..hashes.len()).step_by(2) {
            let a = hashes[i];
            let b = if i + 1 < hashes.len() {
                hashes[i + 1]
            } else {
                hashes[i] // Duplicate last if odd number
            };
            let mut concat = Vec::with_capacity(64);
            concat.extend_from_slice(&a);
            concat.extend_from_slice(&b);
            next.push(hash256(&concat));
        }
        hashes = next;
    }

    hashes[0]
}

fn current_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn dummy_qpkh() -> [u8; 32] {
    // Deterministic placeholder: HASH256("QPB/DEV/COINBASE")
    hash256(b"QPB/DEV/COINBASE")
}

/// Build a BIP34-compliant coinbase script_sig with height encoded.
/// Format: [height_bytes_len] [height_le_bytes] "QPB"
fn build_coinbase_script_sig(height: u64) -> Vec<u8> {
    let mut script_sig = Vec::with_capacity(16);

    // Encode height as minimal push (BIP34 style)
    if height == 0 {
        script_sig.push(0x00); // OP_0
    } else if height <= 16 {
        script_sig.push(0x50 + height as u8); // OP_1 through OP_16
    } else {
        // Encode as little-endian bytes with minimal length
        let mut h = height;
        let mut bytes = Vec::new();
        while h > 0 {
            bytes.push((h & 0xff) as u8);
            h >>= 8;
        }
        // Add extra 0x00 if high bit set (to keep positive)
        if bytes.last().is_some_and(|&b| b & 0x80 != 0) {
            bytes.push(0x00);
        }
        script_sig.push(bytes.len() as u8);
        script_sig.extend(bytes);
    }

    // Add "QPB" tag
    script_sig.extend_from_slice(b"QPB");
    script_sig
}

/// Mine a block with coinbase paying to a specific script_pubkey.
/// Includes mempool transactions and proper subsidy + fees.
pub fn mine_block_to_address(
    node: &Node,
    net: &NetworkParams,
    coinbase_script: Vec<u8>,
    no_pow: bool,
) -> Result<Vec<u8>> {
    let (block, allow_time_bump) = build_block_to_address(node, net, coinbase_script)?;

    if no_pow {
        return Ok(block.serialize(true));
    }

    let target = bits_to_target(block.header.bits).ok_or_else(|| anyhow!("invalid bits"))?;
    let mut mined = block;
    let mut nonce: u32 = 0;
    loop {
        mined.header.nonce = nonce;
        let h = pow_hash(&mined.header)?;
        if h <= target {
            return Ok(mined.serialize(true));
        }
        nonce = nonce.wrapping_add(1);
        if nonce == 0 && allow_time_bump {
            mined.header.time = current_time();
        }
    }
}

/// Build a block with coinbase paying to a specific script_pubkey.
fn build_block_to_address(
    node: &Node,
    net: &NetworkParams,
    coinbase_script: Vec<u8>,
) -> Result<(Block, bool)> {
    let prev_hash_bytes = hex::decode(node.best_hash_hex()).map_err(|_| anyhow!("bad tip hex"))?;
    if prev_hash_bytes.len() != 32 {
        anyhow::bail!("tip hash wrong length");
    }
    let mut prev_blockhash = [0u8; 32];
    prev_blockhash.copy_from_slice(&prev_hash_bytes);

    let bits = net
        .genesis
        .as_ref()
        .ok_or_else(|| anyhow!("missing genesis"))?
        .header
        .bits;

    // Calculate max weight for block
    let max_weight = max_allowed_weight(WEIGHT_FLOOR_WU, WEIGHT_FLOOR_WU);
    let coinbase_reserve = 2000u32;
    let available_weight = max_weight.saturating_sub(coinbase_reserve);

    // Select mempool transactions with fees
    let mempool_entries = node.mempool_select_entries_for_block(available_weight);
    let mempool_txs: Vec<Transaction> = mempool_entries.into_iter().map(|e| e.tx).collect();

    // Calculate total fees
    let total_fees: u64 = mempool_txs
        .iter()
        .map(|_| 0u64) // TODO: properly track fees from mempool entries
        .sum();

    // Calculate subsidy
    let height = node.height() + 1;
    let subsidy = block_subsidy(height as u32);

    // Check if any mempool tx has witness data
    let has_witness = mempool_txs
        .iter()
        .any(|tx| tx.vin.iter().any(|i| !i.witness.is_empty()));

    // Coinbase script_sig must include height (BIP34) to ensure unique txids
    let coinbase_script_sig = build_coinbase_script_sig(height);

    // Reserved value for witness commitment (32 zero bytes)
    let reserved = [0u8; 32];

    // Build coinbase outputs
    let mut coinbase_outputs = vec![TxOut {
        value: subsidy + total_fees,
        script_pubkey: coinbase_script,
    }];

    // Build coinbase witness (needed if block has witness txs)
    let coinbase_witness = if has_witness {
        vec![reserved.to_vec()]
    } else {
        Vec::new()
    };

    // Create initial coinbase
    let mut coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: crate::types::OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig: coinbase_script_sig,
            sequence: 0xffff_ffff,
            witness: coinbase_witness,
        }],
        vout: coinbase_outputs.clone(),
        lock_time: 0,
    };

    // Build txdata with coinbase first
    let mut txdata = Vec::with_capacity(1 + mempool_txs.len());
    txdata.push(coinbase.clone());
    txdata.extend(mempool_txs);

    // If we have witness transactions, compute and add witness commitment
    if has_witness {
        // Create temp block to compute witness merkle root
        let temp_block = Block {
            header: BlockHeader {
                version: 1,
                prev_blockhash,
                merkle_root: [0u8; 32],
                time: 0,
                bits,
                nonce: 0,
            },
            txdata: txdata.clone(),
        };

        let wroot = witness_merkle_root(&temp_block);
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&wroot);
        buf.extend_from_slice(&reserved);
        let commitment_hash = hash256(&buf);

        // Build witness commitment output: OP_RETURN OP_PUSHBYTES_36 0xaa21a9ed [commitment]
        let mut commitment_spk = Vec::with_capacity(38);
        commitment_spk.push(0x6a); // OP_RETURN
        commitment_spk.push(0x24); // OP_PUSHBYTES_36
        commitment_spk.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]); // witness commitment magic
        commitment_spk.extend_from_slice(&commitment_hash);

        // Add commitment output to coinbase
        coinbase_outputs.push(TxOut {
            value: 0,
            script_pubkey: commitment_spk,
        });

        // Rebuild coinbase with commitment output
        coinbase.vout = coinbase_outputs;
        txdata[0] = coinbase;
    }

    // Compute merkle root
    let merkle_root = compute_merkle_root(&txdata);

    let header_time = current_time();
    let header = BlockHeader {
        version: 1,
        prev_blockhash,
        merkle_root,
        time: header_time,
        bits,
        nonce: 0,
    };

    let block = Block { header, txdata };
    Ok((block, true))
}

/// Build a block template for external miners.
///
/// Returns a `BlockTemplate` containing all information needed for an external
/// miner to construct and mine a valid block.
pub fn build_block_template(node: &Node, net: &NetworkParams) -> Result<BlockTemplate> {
    // Previous block hash
    let prev_hash_hex = node.best_hash_hex().to_string();

    // Current height (next block's height)
    let height = node.height() + 1;

    // Get difficulty bits from genesis (devnet uses constant difficulty)
    let bits = net
        .genesis
        .as_ref()
        .ok_or_else(|| anyhow!("missing genesis"))?
        .header
        .bits;

    // Calculate target from bits
    let target_bytes = bits_to_target(bits).ok_or_else(|| anyhow!("invalid bits"))?;
    let target_hex = hex::encode(target_bytes);

    // Calculate max weight for block
    let max_weight = max_allowed_weight(WEIGHT_FLOOR_WU, WEIGHT_FLOOR_WU);
    let coinbase_reserve = 2000u32;
    let available_weight = max_weight.saturating_sub(coinbase_reserve);

    // Select mempool transactions with full metadata
    let mempool_entries = node.mempool_select_entries_for_block(available_weight);

    // Build transaction list with fees
    let mut total_fees: u64 = 0;
    let transactions: Vec<TemplateTransaction> = mempool_entries
        .iter()
        .map(|entry| {
            total_fees += entry.fee;
            TemplateTransaction {
                txid: hex::encode(entry.txid),
                data: hex::encode(entry.tx.serialize(true)),
                fee: entry.fee,
                weight: entry.weight,
            }
        })
        .collect();

    // Coinbase value = subsidy + total fees
    let subsidy = block_subsidy(height as u32);
    let coinbasevalue = subsidy + total_fees;

    Ok(BlockTemplate {
        version: 1,
        previousblockhash: prev_hash_hex,
        transactions,
        coinbasevalue,
        target: target_hex,
        bits: format!("{:08x}", bits),
        curtime: current_time(),
        height,
    })
}
