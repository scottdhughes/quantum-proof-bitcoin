use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};

use crate::hashing::hash256;
use crate::node::chainparams::NetworkParams;
use crate::node::node::Node;
use crate::pow::{bits_to_target, pow_hash};
use crate::script::build_p2qpkh;
use crate::types::{Block, BlockHeader, Transaction, TxIn, TxOut};

/// Build and optionally mine a coinbase-only block on the current tip.
/// Returns the serialized block bytes.
pub fn mine_block_bytes(node: &Node, net: &NetworkParams, no_pow: bool) -> Result<Vec<u8>> {
    let (block, allow_time_bump) = build_coinbase_block(node, net)?;
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
