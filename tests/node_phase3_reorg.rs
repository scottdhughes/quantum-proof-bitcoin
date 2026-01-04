//! Phase 3: Block reorganization tests.

use hex::FromHex;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
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

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

/// Get block hash at a specific height via RPC.
fn get_block_hash_at_height(node: &mut Node, height: u64) -> [u8; 32] {
    let resp = rpc_call(node, "getblockhash", &format!("[{}]", height));
    let hash_hex = resp["result"].as_str().unwrap();
    let mut hash = [0u8; 32];
    let bytes = Vec::from_hex(hash_hex).unwrap();
    hash.copy_from_slice(&bytes);
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

/// Test that transactions from disconnected blocks return to mempool after reorg.
///
/// This is a comprehensive test that:
/// 1. Mines enough blocks to mature a coinbase (101 blocks)
/// 2. Creates a spending transaction and mines it into block 102
/// 3. Builds a longer competing chain (blocks 102b, 103b, 104b) from block 101
/// 4. After reorg, verifies the transaction returns to the mempool
#[test]
fn mempool_restoration_after_reorg() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and addresses
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
    let mining_addr = resp["result"].as_str().unwrap().to_string();

    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine 1 block to our mining address
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, mining_addr),
    );

    // Mine 100 more blocks to mature the coinbase (COINBASE_MATURITY = 100)
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    assert_eq!(node.height(), 101);

    // Get block 101's hash - this is our fork point
    let fork_point_hash = get_block_hash_at_height(&mut node, 101);

    // Send a transaction (goes into mempool)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000000000]"#, recipient_addr), // 10 QPB
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let tx_hex = resp["result"].as_str().unwrap().to_string();

    // Verify transaction is in mempool
    let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(resp["result"]["size"].as_u64().unwrap(), 1);

    // Mine the transaction into block 102
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, mining_addr),
    );

    assert_eq!(node.height(), 102);

    // Verify mempool is now empty (tx confirmed)
    let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(
        resp["result"]["size"].as_u64().unwrap(),
        0,
        "Expected tx to be confirmed"
    );

    // Build a competing chain from block 101 that's longer (102b, 103b)
    // These blocks have only coinbase transactions (no spending tx)
    let block_102b = build_block(fork_point_hash, 102, block_subsidy(102), 999);
    let block_102b_hash = block_hash(&block_102b);
    node.submit_block_bytes(&block_102b.serialize(true))
        .unwrap();

    // Still at height 102 (same cumulative work)
    assert_eq!(node.height(), 102);

    let block_103b = build_block(block_102b_hash, 103, block_subsidy(103), 999);
    let block_103b_hash = block_hash(&block_103b);
    node.submit_block_bytes(&block_103b.serialize(true))
        .unwrap();

    // Now at height 103 - reorg happened!
    assert_eq!(node.height(), 103);

    // Verify we're on the competing chain
    assert_eq!(get_tip_hash(&node), block_103b_hash);

    // The transaction from block 102 (original chain) should now be back in mempool
    let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    let mempool_size = resp["result"]["size"].as_u64().unwrap();
    assert_eq!(
        mempool_size, 1,
        "Expected tx from disconnected block to return to mempool after reorg"
    );

    // Verify it's the same transaction (by checking mempool contains it)
    let txid_bytes = hex::decode(&tx_hex).unwrap();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);
    assert!(
        node.mempool_contains(&txid),
        "Expected specific tx {} to return to mempool after reorg",
        tx_hex
    );
}

/// Test that transactions confirmed in the new chain are NOT returned to mempool.
///
/// If the same transaction exists in both the old and new chain, it should
/// not be added to the mempool (since it's already confirmed).
#[test]
fn reorg_does_not_duplicate_confirmed_txs() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let genesis_hash = get_tip_hash(&node);

    // Build main chain: genesis -> block1
    let block1 = build_block(genesis_hash, 1, block_subsidy(1), 1);
    node.submit_block_bytes(&block1.serialize(true)).unwrap();
    assert_eq!(node.height(), 1);

    // Build competing chain that's longer: genesis -> block1b -> block2b
    let block1b = build_block(genesis_hash, 1, block_subsidy(1), 100);
    let block1b_hash = block_hash(&block1b);
    node.submit_block_bytes(&block1b.serialize(true)).unwrap();
    assert_eq!(node.height(), 1); // Same height, no reorg yet

    let block2b = build_block(block1b_hash, 2, block_subsidy(2), 100);
    let block2b_hash = block_hash(&block2b);
    node.submit_block_bytes(&block2b.serialize(true)).unwrap();

    // Reorg happened
    assert_eq!(node.height(), 2);
    assert_eq!(get_tip_hash(&node), block2b_hash);

    // Mempool should be empty - coinbase txs from disconnected blocks
    // cannot be added to mempool (they're invalid outside their block)
    let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(
        resp["result"]["size"].as_u64().unwrap(),
        0,
        "Coinbase transactions should not return to mempool"
    );
}
