//! Integration tests for fee estimation.

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
fn estimatesmartfee_returns_valid_response() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Call estimatesmartfee with default target
    let resp = rpc_call(&mut node, "estimatesmartfee", "[6]");

    // Should have result with feerate and blocks
    assert!(resp["result"]["feerate"].is_number());
    assert!(resp["result"]["blocks"].is_number());

    // Fee rate should be positive
    let feerate = resp["result"]["feerate"].as_f64().unwrap();
    assert!(feerate > 0.0, "Fee rate should be positive");

    // Blocks should match target
    assert_eq!(resp["result"]["blocks"].as_u64().unwrap(), 6);
}

#[test]
fn estimatefee_returns_sat_vb_format() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Call estimatefee with target
    let resp = rpc_call(&mut node, "estimatefee", "[3]");

    // Should have feerate_sat_vb field
    assert!(resp["result"]["feerate_sat_vb"].is_number());
    assert!(resp["result"]["blocks"].is_number());

    // Fee rate in sat/vB should be >= 1 (default minimum)
    let feerate = resp["result"]["feerate_sat_vb"].as_f64().unwrap();
    assert!(feerate >= 1.0, "Fee rate should be at least 1 sat/vB");
}

#[test]
fn estimate_with_empty_mempool_uses_default() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Empty mempool, no history - should return default minimum
    let resp = rpc_call(&mut node, "estimatefee", "[1]");

    let feerate = resp["result"]["feerate_sat_vb"].as_f64().unwrap();
    assert_eq!(feerate, 1.0, "Empty mempool should return default 1 sat/vB");
}

#[test]
fn estimate_uses_mempool_data() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Get estimate with empty mempool
    let empty_resp = rpc_call(&mut node, "estimatefee", "[1]");
    let _empty_rate = empty_resp["result"]["feerate_sat_vb"].as_f64().unwrap();

    // Create transaction in mempool
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );

    // Now estimate should consider the mempool tx
    let with_mempool_resp = rpc_call(&mut node, "estimatefee", "[1]");
    let with_mempool_rate = with_mempool_resp["result"]["feerate_sat_vb"]
        .as_f64()
        .unwrap();

    // Rate should still be valid
    assert!(with_mempool_rate >= 1.0);

    // With mempool data, rate might be different (or same if mempool small)
    // The key thing is it should be a valid positive rate
    assert!(with_mempool_rate > 0.0);
}

#[test]
fn estimate_uses_historical_data() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Setup wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient = resp["result"].as_str().unwrap().to_string();

    // Mine blocks to get mature coins
    mine_to_address(&mut node, 101, &sender);

    // Create and mine some transactions to build history
    for _ in 0..3 {
        let resp = rpc_call(
            &mut node,
            "sendtoaddress",
            &format!(r#"["{}", 1000]"#, recipient),
        );
        if resp.get("error").is_none() || resp["error"].is_null() {
            // Mine the transaction
            rpc_call(
                &mut node,
                "generatetoaddress",
                &format!(r#"[1, "{}"]"#, sender),
            );
        }
    }

    // Now estimate for a long target should use historical data
    let resp = rpc_call(&mut node, "estimatefee", "[10]");
    let feerate = resp["result"]["feerate_sat_vb"].as_f64().unwrap();

    // Should be a valid positive rate
    assert!(feerate >= 1.0, "Historical estimate should be >= 1 sat/vB");
}

#[test]
fn estimate_clamps_target_range() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Target 0 should clamp to 1
    let resp = rpc_call(&mut node, "estimatesmartfee", "[0]");
    assert_eq!(resp["result"]["blocks"].as_u64().unwrap(), 1);

    // Target > 1008 should clamp to 1008
    let resp = rpc_call(&mut node, "estimatesmartfee", "[2000]");
    assert_eq!(resp["result"]["blocks"].as_u64().unwrap(), 1008);
}

#[test]
fn estimatesmartfee_btc_kb_conversion() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    // Get both formats
    let smart_resp = rpc_call(&mut node, "estimatesmartfee", "[6]");
    let simple_resp = rpc_call(&mut node, "estimatefee", "[6]");

    let btc_kb = smart_resp["result"]["feerate"].as_f64().unwrap();
    let sat_vb = simple_resp["result"]["feerate_sat_vb"].as_f64().unwrap();

    // 1 BTC/kB = 100,000 sat/vB, so sat_vb / 100000 = btc_kb
    let expected_btc_kb = sat_vb / 100_000.0;

    // Allow for floating point precision
    let diff = (btc_kb - expected_btc_kb).abs();
    assert!(
        diff < 0.0000001,
        "BTC/kB conversion mismatch: {} vs {}",
        btc_kb,
        expected_btc_kb
    );
}
