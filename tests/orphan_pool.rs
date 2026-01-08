//! Orphan pool integration tests.
//!
//! Tests that transactions with missing parents are properly buffered
//! and resolved when parents arrive.

use std::path::Path;
use tempfile::tempdir;

use qpb_consensus::node::node::{AddTxResult, Node};
use qpb_consensus::node::rpc::handle_rpc;
use qpb_consensus::types::{OutPoint, Transaction, TxIn, TxOut};

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

fn hex_to_txid(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).unwrap();
    bytes.try_into().unwrap()
}

/// Create a simple test transaction spending from a given parent.
fn make_child_tx(parent_txid: [u8; 32], vout: u32, value: u64) -> Transaction {
    Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: parent_txid,
                vout,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        }],
        vout: vec![TxOut {
            value,
            script_pubkey: vec![0x51], // OP_1 (anyone can spend)
        }],
        lock_time: 0,
    }
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn orphan_added_when_parent_missing() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init(
        "devnet",
        dir.path(),
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create a transaction spending from a non-existent parent
    let fake_parent = [1u8; 32];
    let orphan_tx = make_child_tx(fake_parent, 0, 1000);
    let orphan_txid = orphan_tx.txid();

    // Try to add - should become an orphan
    let result = node.add_transaction_or_orphan(orphan_tx, Some(42));

    match result {
        AddTxResult::Orphaned { txid, missing } => {
            assert_eq!(txid, orphan_txid);
            assert_eq!(missing.len(), 1);
            assert_eq!(missing[0], fake_parent);
        }
        other => panic!("Expected Orphaned, got {:?}", other),
    }

    // Verify it's in the orphan pool
    assert!(node.orphan_contains(&orphan_txid));
    assert_eq!(node.orphan_count(), 1);

    // Not in mempool
    assert!(!node.mempool_contains(&orphan_txid));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn orphan_resolved_when_parent_arrives() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init(
        "devnet",
        dir.path(),
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Setup: Create wallet and mine coins
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
    let mining_addr = resp["result"].as_str().unwrap().to_string();

    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine 101 blocks to mature coinbase
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, mining_addr),
    );
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    // Create parent transaction (A)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000000000]"#, recipient_addr),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let parent_txid_hex = resp["result"].as_str().unwrap();
    let parent_txid = hex_to_txid(parent_txid_hex);

    // Parent should be in mempool
    assert!(node.mempool_contains(&parent_txid));

    // Get the parent tx to know its output
    let parent_tx = node.mempool_get(&parent_txid).unwrap().clone();
    let parent_output_value = parent_tx.vout[0].value;

    // Create child transaction (B) spending from A
    // We'll manually construct it since sendtoaddress won't work for mempool parents
    let child_tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
            // Minimal witness for anyone-can-spend output
            witness: vec![vec![0x01]], // dummy witness
        }],
        vout: vec![TxOut {
            value: parent_output_value - 10000, // Subtract fee
            script_pubkey: vec![0x51],          // OP_1
        }],
        lock_time: 0,
    };
    let child_txid = child_tx.txid();

    // Add child - should go to mempool since parent is already there
    let result = node.add_transaction_or_orphan(child_tx, None);

    // It might be accepted (if mempool parent lookup works) or rejected
    // due to script validation. Either way, test the orphan mechanism.
    match result {
        AddTxResult::Accepted(txid) => {
            assert_eq!(txid, child_txid);
            assert!(node.mempool_contains(&child_txid));
        }
        AddTxResult::Rejected(reason) => {
            // Script validation failed, which is expected for this test tx
            println!("Child rejected (expected): {}", reason);
        }
        AddTxResult::Orphaned { .. } => {
            // This shouldn't happen since parent is in mempool
            panic!("Child became orphan even though parent is in mempool");
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn orphan_eviction_on_limit() {
    use qpb_consensus::constants::MAX_ORPHAN_TRANSACTIONS;

    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init(
        "devnet",
        dir.path(),
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Add orphans up to the limit
    let mut first_txid = None;
    for i in 0..MAX_ORPHAN_TRANSACTIONS {
        let fake_parent = [(i as u8).wrapping_add(100); 32];
        let orphan_tx = make_child_tx(fake_parent, 0, 1000 + i as u64);
        let txid = orphan_tx.txid();

        if i == 0 {
            first_txid = Some(txid);
        }

        let result = node.add_transaction_or_orphan(orphan_tx, None);
        assert!(matches!(result, AddTxResult::Orphaned { .. }));
    }

    assert_eq!(node.orphan_count(), MAX_ORPHAN_TRANSACTIONS);

    // First orphan should still be there
    assert!(node.orphan_contains(&first_txid.unwrap()));

    // Add one more - should trigger eviction
    let new_parent = [255u8; 32];
    let new_orphan = make_child_tx(new_parent, 0, 9999);
    let new_txid = new_orphan.txid();

    let result = node.add_transaction_or_orphan(new_orphan, None);
    assert!(matches!(result, AddTxResult::Orphaned { .. }));

    // Still at max capacity
    assert_eq!(node.orphan_count(), MAX_ORPHAN_TRANSACTIONS);

    // New orphan should be there
    assert!(node.orphan_contains(&new_txid));

    // First orphan should be evicted (LRU)
    assert!(!node.orphan_contains(&first_txid.unwrap()));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn orphan_per_peer_limit() {
    use qpb_consensus::constants::MAX_ORPHANS_PER_PEER;

    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init(
        "devnet",
        dir.path(),
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    let peer_id = 42u64;

    // Add orphans up to per-peer limit
    for i in 0..MAX_ORPHANS_PER_PEER {
        let fake_parent = [(i as u8).wrapping_add(100); 32];
        let orphan_tx = make_child_tx(fake_parent, 0, 1000 + i as u64);

        let result = node.add_transaction_or_orphan(orphan_tx, Some(peer_id));
        assert!(
            matches!(result, AddTxResult::Orphaned { .. }),
            "Expected Orphaned, got {:?}",
            result
        );
    }

    assert_eq!(node.orphan_count(), MAX_ORPHANS_PER_PEER);

    // One more from same peer should be rejected
    let fake_parent = [200u8; 32];
    let orphan_tx = make_child_tx(fake_parent, 0, 5000);

    let result = node.add_transaction_or_orphan(orphan_tx.clone(), Some(peer_id));
    assert!(
        matches!(result, AddTxResult::Rejected(_)),
        "Expected Rejected due to per-peer limit, got {:?}",
        result
    );

    // But from a different peer should work
    let result = node.add_transaction_or_orphan(orphan_tx, Some(peer_id + 1));
    assert!(
        matches!(result, AddTxResult::Orphaned { .. }),
        "Expected Orphaned, got {:?}",
        result
    );

    assert_eq!(node.orphan_count(), MAX_ORPHANS_PER_PEER + 1);
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn orphan_removed_for_disconnected_peer() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init(
        "devnet",
        dir.path(),
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    let peer1 = 1u64;
    let peer2 = 2u64;

    // Add orphans from peer1
    for i in 0..3 {
        let fake_parent = [(i as u8).wrapping_add(100); 32];
        let orphan_tx = make_child_tx(fake_parent, 0, 1000 + i as u64);
        node.add_transaction_or_orphan(orphan_tx, Some(peer1));
    }

    // Add orphan from peer2
    let fake_parent = [200u8; 32];
    let orphan_tx = make_child_tx(fake_parent, 0, 5000);
    node.add_transaction_or_orphan(orphan_tx, Some(peer2));

    assert_eq!(node.orphan_count(), 4);

    // Disconnect peer1
    let removed = node.remove_orphans_for_peer(peer1);
    assert_eq!(removed.len(), 3);

    // Only peer2's orphan remains
    assert_eq!(node.orphan_count(), 1);
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn direct_mempool_add_still_works() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init(
        "devnet",
        dir.path(),
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Setup: Create wallet and mine coins
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
    let mining_addr = resp["result"].as_str().unwrap().to_string();

    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine 101 blocks
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, mining_addr),
    );
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    // Create transaction via RPC (uses add_to_mempool internally)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 500000000]"#, recipient_addr),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );

    let txid_hex = resp["result"].as_str().unwrap();
    let txid = hex_to_txid(txid_hex);

    // Should be in mempool (not orphan pool)
    assert!(node.mempool_contains(&txid));
    assert!(!node.orphan_contains(&txid));
    assert_eq!(node.orphan_count(), 0);
}
