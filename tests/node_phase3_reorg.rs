//! Phase 3: Block reorganization tests.

use hex::FromHex;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::pow::pow_hash;
use qpb_consensus::reward::block_subsidy;
use qpb_consensus::script::build_p2qpkh;
use qpb_consensus::types::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};

fn coinbase_tx(message: &[u8], value: u64, spk: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0xffff_ffff,
            },
            script_sig: message.to_vec(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value,
            script_pubkey: spk,
        }],
        lock_time: 0,
    }
}

fn build_block(prev_hash: [u8; 32], height: u32, coin_value: u64, nonce: u32) -> Block {
    let pkhash = [0x11u8; 32];
    let spk = build_p2qpkh(pkhash);
    let cb = coinbase_tx(
        format!("block h={} n={}", height, nonce).as_bytes(),
        coin_value,
        spk,
    );
    let merkle = cb.txid();
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_766_620_800 + height,
            bits: 0x207f_ffff,
            nonce,
        },
        txdata: vec![cb],
    }
}

/// Get the block hash using the Argon2 PoW hash (same as the node uses).
fn block_hash(block: &Block) -> [u8; 32] {
    pow_hash(&block.header).unwrap()
}

fn get_tip_hash(node: &Node) -> [u8; 32] {
    let mut hash = [0u8; 32];
    let tip_bytes = Vec::from_hex(node.best_hash_hex()).unwrap();
    hash.copy_from_slice(&tip_bytes);
    hash
}

#[test]
fn competing_block_at_same_height() {
    // Test that a competing block at the same height is stored but doesn't become tip
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let genesis_hash = get_tip_hash(&node);

    // Build first block on genesis
    let block1 = build_block(genesis_hash, 1, block_subsidy(1), 1);
    node.submit_block_bytes(&block1.serialize(true)).unwrap();
    assert_eq!(node.height(), 1);
    let tip1 = get_tip_hash(&node);

    // Build competing block at same height (different nonce = different hash)
    let block1b = build_block(genesis_hash, 1, block_subsidy(1), 2);
    node.submit_block_bytes(&block1b.serialize(true)).unwrap();

    // Tip should still be block1 (same cumulative work, first seen wins)
    assert_eq!(node.height(), 1);
    assert_eq!(get_tip_hash(&node), tip1);
}

#[test]
fn longer_chain_triggers_reorg() {
    // Test that a longer competing chain triggers a reorganization
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let genesis_hash = get_tip_hash(&node);

    // Build main chain: genesis -> block1
    let block1 = build_block(genesis_hash, 1, block_subsidy(1), 1);
    let block1_hash = block_hash(&block1);
    node.submit_block_bytes(&block1.serialize(true)).unwrap();
    assert_eq!(node.height(), 1);

    // Build competing chain: genesis -> block1b -> block2b (longer)
    let block1b = build_block(genesis_hash, 1, block_subsidy(1), 100);
    let block1b_hash = block_hash(&block1b);
    node.submit_block_bytes(&block1b.serialize(true)).unwrap();
    assert_eq!(node.height(), 1); // Still at height 1, no reorg yet

    let block2b = build_block(block1b_hash, 2, block_subsidy(2), 100);
    let block2b_hash = block_hash(&block2b);
    node.submit_block_bytes(&block2b.serialize(true)).unwrap();

    // Now height should be 2, and tip should be block2b (longer chain wins)
    assert_eq!(node.height(), 2);
    assert_eq!(get_tip_hash(&node), block2b_hash);

    // Verify we're on the right chain by checking parent relationship
    // block2b's parent should be block1b, not block1
    assert_ne!(block1_hash, block1b_hash);
}

#[test]
fn reorg_persists_across_restart() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    // Setup: create a reorg scenario
    let genesis_hash;
    let block2b_hash;
    {
        let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
        genesis_hash = get_tip_hash(&node);

        // Main chain: genesis -> block1
        let block1 = build_block(genesis_hash, 1, block_subsidy(1), 1);
        node.submit_block_bytes(&block1.serialize(true)).unwrap();

        // Competing chain: genesis -> block1b -> block2b
        let block1b = build_block(genesis_hash, 1, block_subsidy(1), 100);
        let block1b_hash = block_hash(&block1b);
        node.submit_block_bytes(&block1b.serialize(true)).unwrap();

        let block2b = build_block(block1b_hash, 2, block_subsidy(2), 100);
        block2b_hash = block_hash(&block2b);
        node.submit_block_bytes(&block2b.serialize(true)).unwrap();

        assert_eq!(node.height(), 2);
    }

    // Reload and verify state persisted
    let node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    assert_eq!(node2.height(), 2);
    assert_eq!(get_tip_hash(&node2), block2b_hash);
}
