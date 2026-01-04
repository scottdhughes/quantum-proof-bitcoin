use hex::FromHex;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
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

fn build_block(prev_hash: [u8; 32], height: u32, coin_value: u64) -> Block {
    let pkhash = [0x11u8; 32];
    let spk = build_p2qpkh(pkhash);
    let cb = coinbase_tx(b"phase0b2 test", coin_value, spk);
    let merkle = cb.txid();
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_766_620_800 + height,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txdata: vec![cb],
    }
}

fn serialize_block(block: &Block) -> Vec<u8> {
    block.serialize(true)
}

#[test]
fn submit_block_tip_only_updates_state() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    assert_eq!(node.height(), 0);

    let mut prev = [0u8; 32];
    let tip_bytes = Vec::from_hex(node.best_hash_hex()).unwrap();
    prev.copy_from_slice(&tip_bytes);

    let block = build_block(prev, 1, block_subsidy(1));
    let bytes = serialize_block(&block);

    node.submit_block_bytes(&bytes).unwrap();
    assert_eq!(node.height(), 1);

    // Persisted state survives reload
    let node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    assert_eq!(node2.height(), 1);
    assert_eq!(node.best_hash_hex(), node2.best_hash_hex());
}

#[test]
fn submit_block_orphan_does_not_extend_tip() {
    // When a block with unknown parent is submitted, it's stored as an orphan
    // but doesn't extend the active chain (supports future reorg handling)
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let prev = [1u8; 32]; // Unknown parent
    let block = build_block(prev, 1, block_subsidy(1));
    let bytes = serialize_block(&block);

    // Should succeed (stored as orphan) but not change tip
    node.submit_block_bytes(&bytes).unwrap();
    assert_eq!(node.height(), 0); // Still at genesis
}

fn block_subsidy(height: u32) -> u64 {
    // reuse consensus reward helper to stay consistent
    qpb_consensus::reward::block_subsidy(height)
}
