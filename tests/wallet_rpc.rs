//! Wallet RPC integration tests.

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

#[test]
fn createwallet_creates_file() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let resp = rpc_call(&mut node, "createwallet", "[]");

    // Should succeed
    assert!(resp.get("error").is_none() || resp["error"].is_null());
    assert!(resp["result"]["name"].as_str().is_some());

    // Wallet file should exist
    assert!(datadir.join("wallet.json").exists());
}

#[test]
fn getnewaddress_generates_address() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet first
    rpc_call(&mut node, "createwallet", "[]");

    // Generate address
    let resp = rpc_call(&mut node, "getnewaddress", r#"["test-label"]"#);
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    let address = resp["result"].as_str().unwrap();
    // Devnet addresses should start with qpb (HRP from chainparams)
    assert!(address.starts_with("qpb"), "address: {}", address);
}

#[test]
fn getnewaddress_creates_wallet_if_missing() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Don't create wallet first - getnewaddress should auto-create
    let resp = rpc_call(&mut node, "getnewaddress", "[]");
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    let address = resp["result"].as_str().unwrap();
    assert!(address.starts_with("qpb"), "address: {}", address);
}

#[test]
fn getbalance_returns_zero_for_empty_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and generate an address
    rpc_call(&mut node, "createwallet", "[]");
    rpc_call(&mut node, "getnewaddress", "[]");

    // Balance should be 0 (no UTXOs for this address yet)
    let resp = rpc_call(&mut node, "getbalance", "[]");
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    let balance = resp["result"].as_u64().unwrap();
    assert_eq!(balance, 0);
}

#[test]
fn listunspent_returns_empty_for_new_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet
    rpc_call(&mut node, "createwallet", "[]");
    rpc_call(&mut node, "getnewaddress", "[]");

    // List unspent should return empty array
    let resp = rpc_call(&mut node, "listunspent", "[]");
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    let utxos = resp["result"].as_array().unwrap();
    assert!(utxos.is_empty());
}

#[test]
fn listaddresses_returns_generated_addresses() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet
    rpc_call(&mut node, "createwallet", "[]");

    // Generate 3 addresses
    let addr1 = rpc_call(&mut node, "getnewaddress", r#"["addr1"]"#)["result"]
        .as_str()
        .unwrap()
        .to_string();
    let addr2 = rpc_call(&mut node, "getnewaddress", r#"["addr2"]"#)["result"]
        .as_str()
        .unwrap()
        .to_string();
    let addr3 = rpc_call(&mut node, "getnewaddress", r#"["addr3"]"#)["result"]
        .as_str()
        .unwrap()
        .to_string();

    // List addresses
    let resp = rpc_call(&mut node, "listaddresses", "[]");
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    let addresses: Vec<String> = resp["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert_eq!(addresses.len(), 3);
    assert!(addresses.contains(&addr1));
    assert!(addresses.contains(&addr2));
    assert!(addresses.contains(&addr3));
}

#[test]
fn getbalance_requires_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Try to get balance without creating wallet
    let resp = rpc_call(&mut node, "getbalance", "[]");

    // Should return error
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("wallet not found"));
}

#[test]
fn wallet_persists_across_reloads() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let addr1;
    {
        let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
        rpc_call(&mut node, "createwallet", "[]");
        addr1 = rpc_call(&mut node, "getnewaddress", r#"["persist"]"#)["result"]
            .as_str()
            .unwrap()
            .to_string();
    }

    // Reload node and check addresses
    {
        let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
        let resp = rpc_call(&mut node, "listaddresses", "[]");
        let addresses: Vec<String> = resp["result"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], addr1);
    }
}

#[test]
fn sendtoaddress_requires_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Try to send without wallet
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        r#"["qpb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqqdcmcq", 1000]"#,
    );

    // Should fail - no wallet
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("wallet not found"));
}

#[test]
fn sendtoaddress_fails_with_no_utxos() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and generate addresses
    rpc_call(&mut node, "createwallet", "[]");
    let sender_addr = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#)["result"]
        .as_str()
        .unwrap()
        .to_string();
    let recipient_addr = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#)["result"]
        .as_str()
        .unwrap()
        .to_string();

    // Try to send - should fail because no UTXOs for sender
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );

    // Should fail - no UTXOs
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("no UTXOs") || msg.contains("insufficient"),
        "unexpected error: {}",
        msg
    );

    // Verify sender address exists (for clarity)
    assert!(!sender_addr.is_empty());
}

#[test]
fn sendtoaddress_validates_address() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet
    rpc_call(&mut node, "createwallet", "[]");

    // Try to send to invalid address
    let resp = rpc_call(&mut node, "sendtoaddress", r#"["invalid-address", 1000]"#);

    // Should fail - invalid address
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("invalid address") || msg.contains("address"));
}
