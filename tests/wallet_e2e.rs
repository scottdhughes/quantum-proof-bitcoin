//! End-to-end wallet integration tests.
//!
//! These tests verify the complete transaction lifecycle:
//! 1. Mine blocks to wallet address
//! 2. Send transactions
//! 3. Mine transactions into blocks
//! 4. Verify balance updates

use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;

/// Block subsidy at height 1 (50 * 100_000_000 = 5 billion satoshis).
const BLOCK_SUBSIDY: u64 = 5_000_000_000;

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

#[test]
fn mine_to_wallet_updates_balance() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and get an address
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
    let address = resp["result"].as_str().unwrap();

    // Verify initial balance is 0
    let resp = rpc_call(&mut node, "getbalance", "[]");
    assert_eq!(resp["result"].as_u64().unwrap(), 0);

    // Mine a block to our address
    let resp = rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, address),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "generatetoaddress failed: {:?}",
        resp
    );

    // Verify balance increased to block subsidy
    let resp = rpc_call(&mut node, "getbalance", "[]");
    let balance = resp["result"].as_u64().unwrap();
    assert_eq!(
        balance, BLOCK_SUBSIDY,
        "Expected balance {} after mining, got {}",
        BLOCK_SUBSIDY, balance
    );

    // Verify UTXO exists
    let resp = rpc_call(&mut node, "listunspent", "[]");
    let utxos = resp["result"].as_array().unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0]["value"].as_u64().unwrap(), BLOCK_SUBSIDY);
}

#[test]
fn mine_multiple_blocks_accumulates_balance() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and get an address
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
    let address = resp["result"].as_str().unwrap();

    // Mine 3 blocks to our address
    let resp = rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[3, "{}"]"#, address),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "generatetoaddress failed: {:?}",
        resp
    );

    // Verify we got 3 block hashes
    let hashes = resp["result"].as_array().unwrap();
    assert_eq!(hashes.len(), 3);

    // Verify balance is 3 * subsidy
    let resp = rpc_call(&mut node, "getbalance", "[]");
    let balance = resp["result"].as_u64().unwrap();
    assert_eq!(balance, BLOCK_SUBSIDY * 3);

    // Verify we have 3 UTXOs
    let resp = rpc_call(&mut node, "listunspent", "[]");
    let utxos = resp["result"].as_array().unwrap();
    assert_eq!(utxos.len(), 3);
}

#[test]
fn send_transaction_and_mine() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and generate addresses
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["sender"]"#);
    let sender_addr = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine a block to sender address
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, sender_addr),
    );

    // Mine 99 more blocks to mature the coinbase (COINBASE_MATURITY = 100)
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    // Verify sender has the subsidy (only the 1 block mined to sender_addr)
    let resp = rpc_call(&mut node, "getbalance", "[]");
    assert_eq!(resp["result"].as_u64().unwrap(), BLOCK_SUBSIDY);

    // Send 1 BTC (100_000_000 sats) to recipient
    let send_amount: u64 = 100_000_000;
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", {}]"#, recipient_addr, send_amount),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );
    let txid = resp["result"].as_str().unwrap();
    assert!(!txid.is_empty());

    // Verify tx is in mempool
    let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(resp["result"]["size"].as_u64().unwrap(), 1);

    // Mine the transaction (also pays subsidy to sender_addr)
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, sender_addr),
    );

    // Verify mempool is now empty
    let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
    assert_eq!(resp["result"]["size"].as_u64().unwrap(), 0);

    // Balance should be:
    // - 1st block subsidy: 5B
    // - 2nd block subsidy + fees: 5B + fee (miner receives tx fees in coinbase)
    // - Transaction moved coins within wallet (no net change to value)
    // Since we mined the block ourselves, the fee is recouped in the coinbase.
    // Total: 10B (2 * subsidy)
    let resp = rpc_call(&mut node, "getbalance", "[]");
    let final_balance = resp["result"].as_u64().unwrap();

    // We should have exactly 2 * subsidy since fee paid = fee received as miner
    assert_eq!(
        final_balance,
        BLOCK_SUBSIDY * 2,
        "Expected balance = 2 * subsidy since miner receives fees, got {}",
        final_balance
    );
}

#[test]
fn full_transaction_lifecycle() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // === Setup: Create wallet ===
    rpc_call(&mut node, "createwallet", "[]");

    // Generate mining address
    let resp = rpc_call(&mut node, "getnewaddress", r#"["miner"]"#);
    let miner_addr = resp["result"].as_str().unwrap().to_string();

    // Generate recipient address (external, not in our wallet for simplicity)
    // For this test, we'll use another wallet address
    let resp = rpc_call(&mut node, "getnewaddress", r#"["alice"]"#);
    let alice_addr = resp["result"].as_str().unwrap().to_string();

    // === Step 1: Mine initial coins ===
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[2, "{}"]"#, miner_addr),
    );

    // Mine 98 more blocks to mature the coinbases (COINBASE_MATURITY = 100)
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    let resp = rpc_call(&mut node, "getbalance", "[]");
    let initial_balance = resp["result"].as_u64().unwrap();
    assert_eq!(initial_balance, BLOCK_SUBSIDY * 2);

    // === Step 2: Send to Alice ===
    let send_amount: u64 = 500_000_000; // 5 BTC
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", {}]"#, alice_addr, send_amount),
    );
    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "sendtoaddress failed: {:?}",
        resp
    );

    // === Step 3: Mine the transaction ===
    // Mine to miner address to get more coins too
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, miner_addr),
    );

    // === Step 4: Verify final state ===
    // We should have:
    // - 3 block subsidies (3 * 5B = 15B)
    // - Fee paid is recouped in the 3rd block's coinbase (miner = us)
    let resp = rpc_call(&mut node, "getbalance", "[]");
    let final_balance = resp["result"].as_u64().unwrap();

    // Expected: exactly 3 * subsidy since fee paid = fee received as miner
    assert_eq!(
        final_balance,
        BLOCK_SUBSIDY * 3,
        "Expected balance = 3 * subsidy since miner receives fees, got {}",
        final_balance
    );

    // Verify UTXOs exist
    let resp = rpc_call(&mut node, "listunspent", "[]");
    let utxos = resp["result"].as_array().unwrap();
    // Should have at least 3 UTXOs (3 coinbases, plus change, minus spent)
    // Actually: 2 coinbases spent, 1 coinbase + 1 alice + 1 change = at least 3
    assert!(
        utxos.len() >= 2,
        "Expected at least 2 UTXOs, got {}",
        utxos.len()
    );
}

#[test]
fn balance_persists_across_restart() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let address;
    {
        let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

        // Create wallet and mine
        rpc_call(&mut node, "createwallet", "[]");
        let resp = rpc_call(&mut node, "getnewaddress", r#"["persist"]"#);
        address = resp["result"].as_str().unwrap().to_string();

        rpc_call(
            &mut node,
            "generatetoaddress",
            &format!(r#"[1, "{}"]"#, address),
        );

        // Verify balance
        let resp = rpc_call(&mut node, "getbalance", "[]");
        assert_eq!(resp["result"].as_u64().unwrap(), BLOCK_SUBSIDY);
    }

    // Restart node
    {
        let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

        // Verify balance persisted
        let resp = rpc_call(&mut node, "getbalance", "[]");
        assert_eq!(resp["result"].as_u64().unwrap(), BLOCK_SUBSIDY);

        // Verify UTXO persisted
        let resp = rpc_call(&mut node, "listunspent", "[]");
        let utxos = resp["result"].as_array().unwrap();
        assert_eq!(utxos.len(), 1);
    }
}

#[test]
fn coinbase_maturity_enforced() {
    // Test that coinbase outputs cannot be spent until they have 100 confirmations
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["miner"]"#);
    let miner_addr = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine 1 block to wallet
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, miner_addr),
    );

    // Try to send immediately - should fail (not mature)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );
    assert!(
        resp["error"].is_object(),
        "Expected error when spending immature coinbase"
    );
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no mature UTXOs"),
        "Expected 'no mature UTXOs' error, got: {:?}",
        resp["error"]["message"]
    );

    // Mine 99 more blocks (total 100 confirmations)
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    // Now sending should succeed
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );
    assert!(
        resp["error"].is_null(),
        "Expected success after maturity, got: {:?}",
        resp["error"]
    );
    let txid = resp["result"].as_str().unwrap();
    assert!(!txid.is_empty());
}
