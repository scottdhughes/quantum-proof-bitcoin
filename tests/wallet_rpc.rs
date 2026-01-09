//! Wallet RPC integration tests.

use std::path::Path;
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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn createwallet_creates_file() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    let resp = rpc_call(&mut node, "createwallet", "[]");

    // Should succeed
    assert!(resp.get("error").is_none() || resp["error"].is_null());
    assert!(resp["result"]["name"].as_str().is_some());

    // Wallet file should exist
    assert!(datadir.join("wallet.json").exists());
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn getnewaddress_generates_address() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn getnewaddress_creates_wallet_if_missing() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Don't create wallet first - getnewaddress should auto-create
    let resp = rpc_call(&mut node, "getnewaddress", "[]");
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    let address = resp["result"].as_str().unwrap();
    assert!(address.starts_with("qpb"), "address: {}", address);
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn getbalance_returns_zero_for_empty_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn listunspent_returns_empty_for_new_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn listaddresses_returns_generated_addresses() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn getbalance_requires_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Try to get balance without creating wallet
    let resp = rpc_call(&mut node, "getbalance", "[]");

    // Should return error
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("wallet not found"));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn wallet_persists_across_reloads() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let addr1;
    {
        let mut node = Node::open_or_init(
            "devnet",
            datadir,
            Path::new("docs/chain/chainparams.json"),
            true,
            false,
        )
        .unwrap();
        rpc_call(&mut node, "createwallet", "[]");
        addr1 = rpc_call(&mut node, "getnewaddress", r#"["persist"]"#)["result"]
            .as_str()
            .unwrap()
            .to_string();
    }

    // Reload node and check addresses
    {
        let mut node = Node::open_or_init(
            "devnet",
            datadir,
            Path::new("docs/chain/chainparams.json"),
            true,
            false,
        )
        .unwrap();
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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn sendtoaddress_requires_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

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
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn sendtoaddress_fails_with_no_utxos() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

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

    // Should fail - no UTXOs or no confirmed spendable UTXOs
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("no UTXOs")
            || msg.contains("no mature UTXOs")
            || msg.contains("no confirmed spendable UTXOs")
            || msg.contains("insufficient"),
        "unexpected error: {}",
        msg
    );

    // Verify sender address exists (for clarity)
    assert!(!sender_addr.is_empty());
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn sendtoaddress_validates_address() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet
    rpc_call(&mut node, "createwallet", "[]");

    // Try to send to invalid address
    let resp = rpc_call(&mut node, "sendtoaddress", r#"["invalid-address", 1000]"#);

    // Should fail - invalid address
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("invalid address") || msg.contains("address"));
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn fanout_creates_multiple_utxos() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet
    let resp = rpc_call(&mut node, "createwallet", "[]");
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "createwallet failed: {:?}",
        resp
    );

    let resp = rpc_call(&mut node, "getnewaddress", r#"["miner"]"#);
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "getnewaddress failed: {:?}",
        resp
    );
    let miner_addr = resp["result"].as_str().unwrap().to_string();

    // Mine to maturity (101 blocks for coinbase maturity)
    // generatetoaddress has a limit of 10 blocks per call, so we loop
    for i in 0..11 {
        let count = if i < 10 { 10 } else { 1 }; // 10*10 + 1 = 101
        let resp = rpc_call(
            &mut node,
            "generatetoaddress",
            &format!(r#"[{}, "{}"]"#, count, miner_addr),
        );
        assert!(
            resp.get("error").is_none() || resp["error"].is_null(),
            "generatetoaddress batch {} failed: {:?}",
            i,
            resp
        );
    }

    // Call fanout to create 20 outputs of 1 QPB each (100_000_000 sats)
    let resp = rpc_call(&mut node, "fanout", "[20, 100000000]");
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "fanout failed: {:?}",
        resp
    );

    let outputs_created = resp["result"]["outputs_created"].as_u64().unwrap();
    // Fanout creates count outputs + possibly 1 change output
    assert!(
        outputs_created >= 20,
        "should create at least 20 outputs, got {}",
        outputs_created
    );

    // Mine 1 block to confirm the fanout transaction
    let resp = rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, miner_addr),
    );
    assert!(resp.get("error").is_none() || resp["error"].is_null());

    // Now immediately call sendtoaddress 10 times without mining between
    // Each send should succeed because fanout created confirmed UTXOs
    let recipient = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#)["result"]
        .as_str()
        .unwrap()
        .to_string();

    for i in 0..10 {
        let resp = rpc_call(
            &mut node,
            "sendtoaddress",
            // Send 0.1 QPB (10_000_000 sats) each time
            &format!(r#"["{}", 10000000]"#, recipient),
        );
        assert!(
            resp.get("error").is_none() || resp["error"].is_null(),
            "sendtoaddress {} failed: {:?}",
            i + 1,
            resp
        );
    }

    // All 10 sends succeeded - proves fanout created confirmed spendable UTXOs
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn fanout_validates_count_limits() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Create wallet
    rpc_call(&mut node, "createwallet", "[]");

    // Try count=0 - should fail
    let resp = rpc_call(&mut node, "fanout", "[0, 100000000]");
    assert!(resp["error"].is_object(), "count=0 should fail");

    // Try count > 500 - should fail
    let resp = rpc_call(&mut node, "fanout", "[501, 100000000]");
    assert!(resp["error"].is_object(), "count>500 should fail");
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn fanout_requires_wallet() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Try to fanout without creating wallet
    let resp = rpc_call(&mut node, "fanout", "[10, 100000000]");

    // Should fail - no wallet
    assert!(resp["error"].is_object());
    let msg = resp["error"]["message"].as_str().unwrap();
    assert!(msg.contains("wallet not found"));
}
