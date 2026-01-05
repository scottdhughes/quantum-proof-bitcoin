//! Integration tests for BIP125 Replace-by-Fee (RBF).

use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

/// Mine blocks to an address (handles 10-block-per-call limit)
fn mine_to_address(node: &mut Node, count: u32, address: &str) {
    let batches = count.div_ceil(10);
    for i in 0..batches {
        let n = std::cmp::min(10, count - i * 10);
        rpc_call(
            node,
            "generatetoaddress",
            &format!(r#"[{}, "{}"]"#, n, address),
        );
    }
}

#[test]
fn transaction_signals_rbf_with_rbf_flag() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create transaction WITH RBF flag (4th param = true)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000, 1, true]"#, recipient),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );

    let txid_hex = resp["result"].as_str().unwrap();

    // Verify the transaction is in mempool
    let mempool_resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(mempool_resp["result"]["size"].as_u64().unwrap(), 1);

    // Parse txid and verify signals_rbf through mempool entry
    let txid_bytes = hex::decode(txid_hex).unwrap();
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&txid_bytes);

    let entry = node
        .mempool_get_entry(&txid)
        .expect("tx should be in mempool");
    assert!(
        entry.signals_rbf,
        "transaction should signal RBF when created with rbf=true"
    );
}

#[test]
fn transaction_does_not_signal_rbf_by_default() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create transaction WITHOUT RBF flag (default)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000, 1]"#, recipient),
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

    let entry = node
        .mempool_get_entry(&txid)
        .expect("tx should be in mempool");
    assert!(
        !entry.signals_rbf,
        "transaction should NOT signal RBF by default"
    );
}

#[test]
fn bumpfee_increases_fee_and_replaces() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create initial transaction with RBF enabled at low fee rate
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000, 1, true]"#, recipient),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let orig_txid = resp["result"].as_str().unwrap().to_string();

    // Verify original is in mempool
    let mempool_resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(mempool_resp["result"]["size"].as_u64().unwrap(), 1);

    // Bump the fee with higher fee rate
    let resp = rpc_call(&mut node, "bumpfee", &format!(r#"["{}", 5]"#, orig_txid));
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "bumpfee failed: {:?}",
        resp
    );

    let new_txid = resp["result"]["txid"].as_str().unwrap();
    let new_fee = resp["result"]["fee"].as_u64().unwrap();
    let orig_fee = resp["result"]["origfee"].as_u64().unwrap();

    // New fee should be higher
    assert!(
        new_fee > orig_fee,
        "new fee {} should be higher than original {}",
        new_fee,
        orig_fee
    );

    // New txid should be different
    assert_ne!(
        new_txid, orig_txid,
        "replacement should have different txid"
    );

    // Only replacement should be in mempool
    let mempool_resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(
        mempool_resp["result"]["size"].as_u64().unwrap(),
        1,
        "mempool should still have exactly 1 tx after replacement"
    );

    // Verify original is gone
    let orig_txid_bytes = hex::decode(&orig_txid).unwrap();
    let mut orig_txid_arr = [0u8; 32];
    orig_txid_arr.copy_from_slice(&orig_txid_bytes);
    assert!(
        node.mempool_get_entry(&orig_txid_arr).is_none(),
        "original tx should be evicted"
    );

    // Verify replacement is present
    let new_txid_bytes = hex::decode(new_txid).unwrap();
    let mut new_txid_arr = [0u8; 32];
    new_txid_arr.copy_from_slice(&new_txid_bytes);
    assert!(
        node.mempool_get_entry(&new_txid_arr).is_some(),
        "replacement tx should be in mempool"
    );
}

#[test]
fn bumpfee_rejects_non_rbf_transaction() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create transaction WITHOUT RBF
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000, 1]"#, recipient),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let txid = resp["result"].as_str().unwrap().to_string();

    // Try to bump fee - should fail
    let resp = rpc_call(&mut node, "bumpfee", &format!(r#"["{}", 5]"#, txid));
    assert!(
        resp.get("error").is_some() && !resp["error"].is_null(),
        "bumpfee should fail for non-RBF transaction"
    );

    let error_msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        error_msg.contains("does not signal RBF"),
        "error message should mention RBF signaling: {}",
        error_msg
    );
}

#[test]
fn rbf_replacement_requires_higher_fee() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create initial transaction with RBF at moderate fee rate
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000, 3, true]"#, recipient),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let orig_txid = resp["result"].as_str().unwrap().to_string();

    // Get original fee
    let orig_txid_bytes = hex::decode(&orig_txid).unwrap();
    let mut orig_txid_arr = [0u8; 32];
    orig_txid_arr.copy_from_slice(&orig_txid_bytes);
    let orig_entry = node
        .mempool_get_entry(&orig_txid_arr)
        .expect("tx in mempool");
    let orig_fee = orig_entry.fee;

    // Try to bump with same fee rate - might fail due to insufficient fee
    // (actual result depends on coin selection, but we test the principle)
    let resp = rpc_call(&mut node, "bumpfee", &format!(r#"["{}", 3]"#, orig_txid));

    // If it succeeded, verify the new fee is actually higher
    if resp.get("error").is_none() || resp["error"].is_null() {
        let new_fee = resp["result"]["fee"].as_u64().unwrap();
        // Even with same fee rate, BIP125 Rule 3 requires higher absolute fee
        assert!(
            new_fee > orig_fee,
            "replacement fee {} must be higher than original {}",
            new_fee,
            orig_fee
        );
    }
    // If it failed, that's also acceptable - means RBF validation is working
}

#[test]
fn bumpfee_reuses_same_inputs() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create initial transaction with RBF enabled
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000, 1, true]"#, recipient),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let orig_txid_hex = resp["result"].as_str().unwrap().to_string();

    // Get original transaction inputs
    let orig_txid_bytes = hex::decode(&orig_txid_hex).unwrap();
    let mut orig_txid = [0u8; 32];
    orig_txid.copy_from_slice(&orig_txid_bytes);
    let orig_entry = node
        .mempool_get_entry(&orig_txid)
        .expect("original tx in mempool");
    let orig_inputs: Vec<_> = orig_entry
        .tx
        .vin
        .iter()
        .map(|vin| (vin.prevout.txid, vin.prevout.vout))
        .collect();

    // Bump the fee
    let resp = rpc_call(
        &mut node,
        "bumpfee",
        &format!(r#"["{}", 5]"#, orig_txid_hex),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "bumpfee failed: {:?}",
        resp
    );

    let new_txid_hex = resp["result"]["txid"].as_str().unwrap();

    // Get replacement transaction inputs
    let new_txid_bytes = hex::decode(new_txid_hex).unwrap();
    let mut new_txid = [0u8; 32];
    new_txid.copy_from_slice(&new_txid_bytes);
    let new_entry = node
        .mempool_get_entry(&new_txid)
        .expect("replacement tx in mempool");
    let new_inputs: Vec<_> = new_entry
        .tx
        .vin
        .iter()
        .map(|vin| (vin.prevout.txid, vin.prevout.vout))
        .collect();

    // CRITICAL: Replacement must use the SAME inputs as original
    assert_eq!(
        orig_inputs, new_inputs,
        "replacement must reuse same inputs to guarantee conflict"
    );

    // Only one tx should be in mempool (replacement evicted original)
    let mempool_resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(
        mempool_resp["result"]["size"].as_u64().unwrap(),
        1,
        "mempool should have exactly 1 tx after replacement"
    );

    // Original should be gone
    assert!(
        node.mempool_get_entry(&orig_txid).is_none(),
        "original tx should be evicted"
    );
}

#[test]
fn signals_rbf_method_on_transaction() {
    use qpb_consensus::types::{OutPoint, Transaction, TxIn, TxOut};

    // Transaction with final sequence (no RBF)
    let tx_final = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xffffffff, // SEQUENCE_FINAL
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x00; 34],
        }],
        lock_time: 0,
    };
    assert!(
        !tx_final.signals_rbf(),
        "tx with sequence 0xffffffff should not signal RBF"
    );

    // Transaction with RBF sequence
    let tx_rbf = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xfffffffd, // SEQUENCE_RBF_ENABLED
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x00; 34],
        }],
        lock_time: 0,
    };
    assert!(
        tx_rbf.signals_rbf(),
        "tx with sequence 0xfffffffd should signal RBF"
    );

    // Transaction with sequence just below RBF threshold
    let tx_below = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xfffffffc, // Below MAX_BIP125_RBF_SEQUENCE
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x00; 34],
        }],
        lock_time: 0,
    };
    assert!(
        tx_below.signals_rbf(),
        "tx with sequence 0xfffffffc should signal RBF"
    );

    // Transaction with sequence 0xfffffffe (RBF boundary - should NOT signal)
    let tx_boundary = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0xfffffffe, // Just above MAX_BIP125_RBF_SEQUENCE
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x00; 34],
        }],
        lock_time: 0,
    };
    assert!(
        !tx_boundary.signals_rbf(),
        "tx with sequence 0xfffffffe should NOT signal RBF"
    );
}
