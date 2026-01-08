//! Mempool persistence integration tests.
//!
//! Tests that mempool transactions are properly saved and restored
//! across node restarts.

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

fn hex_to_txid(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).unwrap();
    bytes.try_into().unwrap()
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn mempool_persists_across_restart() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    // Phase 1: Create node, wallet, mine coins, send transaction
    let tx_to_persist: String;
    {
        let mut node = Node::open_or_init("devnet", datadir, true, false).unwrap();

        // Create wallet and get addresses
        rpc_call(&mut node, "createwallet", "[]");
        let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
        let mining_addr = resp["result"].as_str().unwrap().to_string();

        let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
        let recipient_addr = resp["result"].as_str().unwrap().to_string();

        // Mine 1 block to our address
        let resp = rpc_call(
            &mut node,
            "generatetoaddress",
            &format!(r#"[1, "{}"]"#, mining_addr),
        );
        assert!(resp.get("error").is_none() || resp["error"].is_null());

        // Mine 100 more blocks to mature the coinbase (COINBASE_MATURITY = 100)
        for _ in 0..10 {
            rpc_call(&mut node, "generatenextblock", "[10]");
        }

        // Verify we have spendable balance
        let resp = rpc_call(&mut node, "getbalance", "[]");
        let balance = resp["result"].as_u64().unwrap();
        assert!(
            balance > 0,
            "Expected positive balance after mining, got {}",
            balance
        );

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
        tx_to_persist = resp["result"].as_str().unwrap().to_string();

        // Verify transaction is in mempool
        let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
        let mempool_size = resp["result"]["size"].as_u64().unwrap();
        assert_eq!(mempool_size, 1, "Expected 1 tx in mempool");

        // Explicitly save node state (simulates graceful shutdown)
        node.save().unwrap();
    }

    // Phase 2: Restart node and verify mempool was restored
    {
        let mut node = Node::open_or_init("devnet", datadir, true, false).unwrap();

        // Verify transaction is still in mempool after restart
        let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
        let mempool_size = resp["result"]["size"].as_u64().unwrap();
        assert_eq!(
            mempool_size, 1,
            "Expected mempool to persist across restart"
        );

        // Verify it's the same transaction
        let txid = hex_to_txid(&tx_to_persist);
        assert!(
            node.mempool_contains(&txid),
            "Expected specific tx {} to persist",
            tx_to_persist
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)] // Integration test uses wallet FFI
fn mempool_drops_confirmed_transactions_on_load() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    // Phase 1: Create node, send tx, save
    {
        let mut node = Node::open_or_init("devnet", datadir, true, false).unwrap();

        // Create wallet and addresses
        rpc_call(&mut node, "createwallet", "[]");
        let resp = rpc_call(&mut node, "getnewaddress", r#"["mining"]"#);
        let mining_addr = resp["result"].as_str().unwrap().to_string();

        let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
        let recipient_addr = resp["result"].as_str().unwrap().to_string();

        // Mine 1 block to our address
        rpc_call(
            &mut node,
            "generatetoaddress",
            &format!(r#"[1, "{}"]"#, mining_addr),
        );

        // Mine 100 more blocks to mature the coinbase
        for _ in 0..10 {
            rpc_call(&mut node, "generatenextblock", "[10]");
        }

        // Send transaction
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

        // Verify in mempool
        let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
        assert_eq!(resp["result"]["size"].as_u64().unwrap(), 1);

        // Save mempool
        node.save().unwrap();

        // Now mine the transaction into a block
        rpc_call(
            &mut node,
            "generatetoaddress",
            &format!(r#"[1, "{}"]"#, mining_addr),
        );

        // Verify mempool is now empty (tx was confirmed)
        let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
        assert_eq!(resp["result"]["size"].as_u64().unwrap(), 0);
    }

    // Phase 2: Restart - the saved mempool.json still has the tx,
    // but it should be dropped because its inputs are spent
    {
        let mut node = Node::open_or_init("devnet", datadir, true, false).unwrap();

        // Mempool should be empty because the tx was confirmed
        let resp = rpc_call(&mut node, "getmempoolinfo", "[]");
        let mempool_size = resp["result"]["size"].as_u64().unwrap();
        assert_eq!(
            mempool_size, 0,
            "Confirmed tx should not be reloaded into mempool"
        );
    }
}
