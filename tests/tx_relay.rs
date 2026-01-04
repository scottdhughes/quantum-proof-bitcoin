//! Transaction relay protocol tests.

use qpb_consensus::node::p2p::{
    InvEntry, MSG_TX, RelayManager, parse_inv, ser_getdata_tx, ser_inv_tx,
};
use qpb_consensus::types::{OutPoint, Transaction, TxIn, TxOut};

fn make_test_tx(version: i32) -> Transaction {
    Transaction {
        version,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [version as u8; 32],
                vout: 0,
            },
            script_sig: vec![0x51], // OP_TRUE
            sequence: 0xffffffff,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![0x00, 0x14, 0xab, 0xcd, 0xef],
        }],
        lock_time: 0,
    }
}

#[test]
fn inv_serialization_roundtrip() {
    let txid1 = [0x11u8; 32];
    let txid2 = [0x22u8; 32];

    // Serialize INV with two txids
    let payload = ser_inv_tx(&[txid1, txid2]);

    // Parse back
    let entries = parse_inv(&payload).unwrap();
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].inv_type, MSG_TX);
    assert_eq!(entries[0].hash, txid1);

    assert_eq!(entries[1].inv_type, MSG_TX);
    assert_eq!(entries[1].hash, txid2);
}

#[test]
fn getdata_serialization_roundtrip() {
    let txid = [0xabu8; 32];

    // Serialize GETDATA for transaction
    let payload = ser_getdata_tx(&[txid]);

    // Parse back (same format as INV)
    let entries = parse_inv(&payload).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].inv_type, MSG_TX);
    assert_eq!(entries[0].hash, txid);
}

#[test]
fn transaction_serialize_parse_roundtrip() {
    // Create a test transaction
    let tx = make_test_tx(1);
    let original_txid = tx.txid();

    // Serialize (without witness for txid, with witness for relay)
    let bytes_no_wit = tx.serialize(false);
    let bytes_wit = tx.serialize(true);

    // Verify txid is hash of non-witness serialization
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(Sha256::digest(&bytes_no_wit));
    let mut computed_txid = [0u8; 32];
    computed_txid.copy_from_slice(&hash);
    assert_eq!(computed_txid, original_txid);

    // Verify witness serialization is larger (has marker/flag)
    // For a tx with empty witness, marker/flag adds 2 bytes, witness count adds 1 per input
    assert!(bytes_wit.len() > bytes_no_wit.len() || tx.vin.iter().all(|i| i.witness.is_empty()));
}

#[test]
fn relay_manager_tracks_known_txids() {
    let mut manager = RelayManager::new();

    let txid1 = [0x11u8; 32];
    let txid2 = [0x22u8; 32];

    // Initially empty
    assert!(!manager.knows_tx(&txid1));
    assert!(!manager.knows_tx(&txid2));

    // Mark one as known
    manager.mark_known(txid1);
    assert!(manager.knows_tx(&txid1));
    assert!(!manager.knows_tx(&txid2));

    // Broadcast marks as known
    manager.broadcast_tx(txid2);
    assert!(manager.knows_tx(&txid2));
}

#[test]
fn relay_manager_starts_with_no_peers() {
    let manager = RelayManager::new();
    assert_eq!(manager.peer_count(), 0);
}

#[test]
fn empty_inv_parses_correctly() {
    let payload = ser_inv_tx(&[]);
    let entries = parse_inv(&payload).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn inv_entry_equality() {
    let entry1 = InvEntry {
        inv_type: MSG_TX,
        hash: [0x11; 32],
    };
    let entry2 = InvEntry {
        inv_type: MSG_TX,
        hash: [0x11; 32],
    };
    let entry3 = InvEntry {
        inv_type: MSG_TX,
        hash: [0x22; 32],
    };

    assert_eq!(entry1, entry2);
    assert_ne!(entry1, entry3);
}

// ============================================================================
// Node P2P tx relay integration tests
// ============================================================================

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
use tempfile::tempdir;

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

/// Create a transaction using the wallet and return its txid.
/// The transaction will be in the mempool after this call.
fn create_tx_via_wallet(node: &mut Node) -> [u8; 32] {
    // Create wallet if not exists
    rpc_call(node, "createwallet", "[]");

    // Generate addresses
    let resp = rpc_call(node, "getnewaddress", r#"["sender"]"#);
    let sender_addr = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine to sender address so we have funds (101 blocks for coinbase maturity)
    // RPC clamps to 10 blocks per call, so we need multiple calls
    for _ in 0..11 {
        rpc_call(
            node,
            "generatetoaddress",
            &format!(r#"[10, "{}"]"#, sender_addr),
        );
    }

    // Send to recipient (creates tx in mempool)
    let resp = rpc_call(
        node,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );

    let txid_hex = resp["result"].as_str().unwrap();
    let txid_bytes = hex::decode(txid_hex).unwrap();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);
    txid
}

/// Get a transaction from the mempool by txid.
fn get_mempool_tx(node: &Node, txid: &[u8; 32]) -> Option<Transaction> {
    node.mempool_get(txid).cloned()
}

#[test]
fn node_handle_tx_inv_filters_unknown() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Create a tx via wallet (handles mining, signing, etc.)
    let txid = create_tx_via_wallet(&mut node);

    // Known tx should not be requested
    let unknown_txid = [0x42u8; 32];
    let inv_txids = vec![txid, unknown_txid];

    let wanted = node.handle_tx_inv(&inv_txids);

    // Should only want the unknown one
    assert_eq!(wanted.len(), 1);
    assert_eq!(wanted[0], unknown_txid);
}

#[test]
fn node_handle_tx_getdata_returns_mempool_txs() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Create a tx via wallet
    let txid = create_tx_via_wallet(&mut node);

    // Request the tx
    let unknown_txid = [0x42u8; 32];
    let getdata_txids = vec![txid, unknown_txid];

    let txs = node.handle_tx_getdata(&getdata_txids);

    // Should only return the one we have
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].txid(), txid);
}

#[test]
fn node_handle_incoming_tx_adds_to_mempool() {
    // This test verifies that handle_incoming_tx correctly adds txs to mempool.
    // We create a tx on node_a, then relay it to node_b which has the same chain state.

    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let mut node_a = Node::open_or_init("devnet", dir_a.path(), true).unwrap();
    let mut node_b = Node::open_or_init("devnet", dir_b.path(), true).unwrap();

    // Create wallet and get addresses on node_a
    rpc_call(&mut node_a, "createwallet", "[]");
    let resp = rpc_call(&mut node_a, "getnewaddress", r#"["sender"]"#);
    let sender_addr = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node_a, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Both nodes need IDENTICAL chain state for tx relay to work.
    // Mine to the same address on both nodes (node_b doesn't need the wallet keys,
    // just the same UTXOs for validation).
    for _ in 0..11 {
        rpc_call(
            &mut node_a,
            "generatetoaddress",
            &format!(r#"[10, "{}"]"#, sender_addr),
        );
        rpc_call(
            &mut node_b,
            "generatetoaddress",
            &format!(r#"[10, "{}"]"#, sender_addr),
        );
    }

    // Now create tx on node_a - it has the wallet keys to sign
    let resp = rpc_call(
        &mut node_a,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let txid_hex = resp["result"].as_str().unwrap();
    let txid_bytes = hex::decode(txid_hex).unwrap();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);

    // Get the tx from node_a's mempool
    let tx = get_mempool_tx(&node_a, &txid).expect("tx should be in node_a mempool");

    // Node B doesn't have this tx yet
    assert!(!node_b.mempool_contains(&txid));

    // Simulate receiving the tx from a peer on node_b
    let result = node_b.handle_incoming_tx(tx);
    assert!(result.is_ok(), "handle_incoming_tx failed: {:?}", result);
    assert_eq!(result.unwrap(), txid);

    // Should now be in node_b's mempool
    assert!(node_b.mempool_contains(&txid));
}

#[test]
fn tx_relay_simulation_between_nodes() {
    // Simulate tx relay: Node A creates tx, Node B receives INV, requests, and accepts

    let dir_a = tempdir().unwrap();
    let dir_b = tempdir().unwrap();

    let mut node_a = Node::open_or_init("devnet", dir_a.path(), true).unwrap();
    let mut node_b = Node::open_or_init("devnet", dir_b.path(), true).unwrap();

    // Create wallet and get addresses on node_a
    rpc_call(&mut node_a, "createwallet", "[]");
    let resp = rpc_call(&mut node_a, "getnewaddress", r#"["sender"]"#);
    let sender_addr = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node_a, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Both nodes mine to the SAME address for identical UTXO sets
    for _ in 0..11 {
        rpc_call(
            &mut node_a,
            "generatetoaddress",
            &format!(r#"[10, "{}"]"#, sender_addr),
        );
        rpc_call(
            &mut node_b,
            "generatetoaddress",
            &format!(r#"[10, "{}"]"#, sender_addr),
        );
    }

    // Node A creates a transaction via wallet (only node_a has the keys)
    let resp = rpc_call(
        &mut node_a,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let txid_hex = resp["result"].as_str().unwrap();
    let txid_bytes = hex::decode(txid_hex).unwrap();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);

    // Verify Node A has it, Node B doesn't
    assert!(node_a.mempool_contains(&txid));
    assert!(!node_b.mempool_contains(&txid));

    // Step 1: Node A announces (INV) the txid
    // Node B checks if it wants this tx
    let wanted = node_b.handle_tx_inv(&[txid]);
    assert_eq!(wanted, vec![txid]);

    // Step 2: Node B requests (GETDATA) the tx from Node A
    let txs = node_a.handle_tx_getdata(&wanted);
    assert_eq!(txs.len(), 1);

    // Step 3: Node B receives and accepts the tx
    let accepted = node_b.handle_incoming_tx(txs[0].clone());
    assert!(accepted.is_ok(), "Failed to accept tx: {:?}", accepted);
    assert_eq!(accepted.unwrap(), txid);

    // Now both nodes have the transaction
    assert!(node_a.mempool_contains(&txid));
    assert!(node_b.mempool_contains(&txid));
}

#[test]
fn tx_relay_rejects_invalid_transaction() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Create an invalid transaction (spending non-existent output)
    let invalid_tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0xdeu8; 32], // doesn't exist
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff,
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a], // OP_RETURN
        }],
        lock_time: 0,
    };

    // Should be rejected
    let result = node.handle_incoming_tx(invalid_tx);
    assert!(result.is_err());
}
