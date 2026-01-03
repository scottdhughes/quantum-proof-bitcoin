use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

use crate::constants::WEIGHT_FLOOR_WU;
use crate::hashing::hash256;
use crate::node::chainparams::NetworkParams;
use crate::node::node::Node;
use crate::pow::{bits_to_target, pow_hash};
use crate::script::build_p2qpkh;
use crate::types::{Block, BlockHeader, Transaction, TxIn, TxOut};
use crate::weight::max_allowed_weight;

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

    // Coinbase tx: single input, single zero-value output (P2QPKH with dummy qpkh)
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: crate::types::OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig: b"QPB dev coinbase".to_vec(),
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

    // Coinbase tx with fees
    let coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: crate::types::OutPoint {
                txid: [0u8; 32],
                vout: u32::MAX,
            },
            script_sig: b"QPB dev coinbase".to_vec(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value: total_fees, // In production: block_subsidy + total_fees - penalty
            script_pubkey: build_p2qpkh(dummy_qpkh()),
        }],
        lock_time: 0,
    };

    // Build txdata with coinbase first
    let mut txdata = Vec::with_capacity(1 + mempool_txs.len());
    txdata.push(coinbase);
    txdata.extend(mempool_txs);

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
