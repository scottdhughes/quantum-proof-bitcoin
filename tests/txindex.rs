//! Integration tests for transaction indexing (--txindex).

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
use qpb_consensus::types::Transaction;
use serde_json::json;
use tempfile::TempDir;

/// Parse a block hex and extract the first transaction's txid (coinbase).
fn extract_coinbase_txid(block_hex: &str) -> String {
    let block_bytes = hex::decode(block_hex).expect("valid hex");

    // Skip 80-byte header
    let mut pos = 80;

    // Read varint for tx count
    let (tx_count, varint_len) = read_varint(&block_bytes[pos..]);
    pos += varint_len;
    assert!(tx_count >= 1, "block must have at least coinbase");

    // Parse first transaction and compute txid
    let tx = parse_transaction(&block_bytes, &mut pos);
    let txid = tx.txid();
    hex::encode(txid)
}

fn read_varint(data: &[u8]) -> (usize, usize) {
    if data[0] < 0xfd {
        (data[0] as usize, 1)
    } else if data[0] == 0xfd {
        let val = u16::from_le_bytes([data[1], data[2]]) as usize;
        (val, 3)
    } else if data[0] == 0xfe {
        let val = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        (val, 5)
    } else {
        let val = u64::from_le_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]) as usize;
        (val, 9)
    }
}

fn parse_transaction(data: &[u8], pos: &mut usize) -> Transaction {
    use qpb_consensus::types::{OutPoint, TxIn, TxOut};

    let version = i32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;

    // Check for witness marker
    let has_witness = data[*pos] == 0 && data[*pos + 1] != 0;
    if has_witness {
        *pos += 2; // skip marker and flag
    }

    // Parse inputs
    let (input_count, len) = read_varint(&data[*pos..]);
    *pos += len;

    let mut vin = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[*pos..*pos + 32]);
        *pos += 32;

        let vout = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;

        let (script_len, len) = read_varint(&data[*pos..]);
        *pos += len;
        let script_sig = data[*pos..*pos + script_len].to_vec();
        *pos += script_len;

        let sequence =
            u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;

        vin.push(TxIn {
            prevout: OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    // Parse outputs
    let (output_count, len) = read_varint(&data[*pos..]);
    *pos += len;

    let mut vout = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = u64::from_le_bytes([
            data[*pos],
            data[*pos + 1],
            data[*pos + 2],
            data[*pos + 3],
            data[*pos + 4],
            data[*pos + 5],
            data[*pos + 6],
            data[*pos + 7],
        ]);
        *pos += 8;

        let (script_len, len) = read_varint(&data[*pos..]);
        *pos += len;
        let script_pubkey = data[*pos..*pos + script_len].to_vec();
        *pos += script_len;

        vout.push(TxOut {
            value,
            script_pubkey,
        });
    }

    // Skip witness if present (we don't need it for txid)
    if has_witness {
        for _ in 0..input_count {
            let (witness_count, len) = read_varint(&data[*pos..]);
            *pos += len;
            for _ in 0..witness_count {
                let (item_len, len) = read_varint(&data[*pos..]);
                *pos += len;
                *pos += item_len;
            }
        }
    }

    let lock_time =
        u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;

    Transaction {
        version,
        vin,
        vout,
        lock_time,
    }
}

fn rpc(node: &mut Node, method: &str, params: serde_json::Value) -> serde_json::Value {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp = handle_rpc(node, &req.to_string());
    serde_json::from_str(&resp).expect("json parse")
}

#[test]
fn gettxindexinfo_disabled_by_default() {
    let dir = TempDir::new().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    let result = rpc(&mut node, "gettxindexinfo", json!([]));
    assert_eq!(result["result"]["enabled"], false);
    assert_eq!(result["result"]["txcount"], 0);
}

#[test]
fn gettxindexinfo_enabled_when_flag_set() {
    let dir = TempDir::new().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, true).unwrap();

    let result = rpc(&mut node, "gettxindexinfo", json!([]));
    assert_eq!(result["result"]["enabled"], true);
    // Genesis block is created during init, not via connect_block,
    // so it doesn't get indexed. txcount starts at 0.
    assert_eq!(result["result"]["txcount"].as_u64().unwrap(), 0);
}

#[test]
fn getrawtransaction_error_when_txindex_disabled() {
    let dir = TempDir::new().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, false).unwrap();

    // Use a random txid that won't be in mempool
    let fake_txid = "0000000000000000000000000000000000000000000000000000000000000001";
    let result = rpc(&mut node, "getrawtransaction", json!([fake_txid]));

    let error = result["error"]["message"].as_str().unwrap();
    assert!(error.contains("txindex not enabled"));
}

#[test]
fn getrawtransaction_finds_confirmed_tx_with_txindex() {
    let dir = TempDir::new().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, true).unwrap();

    // Mine a block to create a coinbase transaction
    let mine_result = rpc(&mut node, "generatenextblock", json!([1]));
    assert!(mine_result["error"].is_null());

    // Get the block hash
    let block_hash = mine_result["result"].as_str().unwrap();

    // Get the block hex and extract the coinbase txid
    let block_result = rpc(&mut node, "getblock", json!([block_hash]));
    let block_hex = block_result["result"].as_str().unwrap();
    let coinbase_txid = extract_coinbase_txid(block_hex);

    // Now lookup the coinbase transaction via getrawtransaction
    let tx_result = rpc(&mut node, "getrawtransaction", json!([coinbase_txid, true]));

    // Should return the tx with confirmations >= 1
    assert!(
        tx_result["error"].is_null(),
        "error: {:?}",
        tx_result["error"]
    );
    assert_eq!(tx_result["result"]["txid"], coinbase_txid);
    assert_eq!(tx_result["result"]["blockhash"], block_hash);
    assert!(tx_result["result"]["confirmations"].as_i64().unwrap() >= 1);
}

#[test]
fn getrawtransaction_nonverbose_returns_hex() {
    let dir = TempDir::new().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, true).unwrap();

    // Mine a block
    let mine_result = rpc(&mut node, "generatenextblock", json!([1]));
    let block_hash = mine_result["result"].as_str().unwrap();

    // Get coinbase txid
    let block_result = rpc(&mut node, "getblock", json!([block_hash]));
    let block_hex = block_result["result"].as_str().unwrap();
    let coinbase_txid = extract_coinbase_txid(block_hex);

    // Get raw transaction without verbose flag (default)
    let tx_result = rpc(&mut node, "getrawtransaction", json!([coinbase_txid]));

    // Should return just the hex string
    assert!(
        tx_result["error"].is_null(),
        "error: {:?}",
        tx_result["error"]
    );
    let hex = tx_result["result"].as_str().unwrap();
    assert!(!hex.is_empty());
    // Should be valid hex (even length, only hex chars)
    assert!(hex.len().is_multiple_of(2));
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn txindex_count_increases_with_blocks() {
    let dir = TempDir::new().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true, true).unwrap();

    let info1 = rpc(&mut node, "gettxindexinfo", json!([]));
    let count1 = info1["result"]["txcount"].as_u64().unwrap();

    // Mine a block (adds 1 coinbase tx)
    rpc(&mut node, "generatenextblock", json!([1]));

    let info2 = rpc(&mut node, "gettxindexinfo", json!([]));
    let count2 = info2["result"]["txcount"].as_u64().unwrap();

    assert!(
        count2 > count1,
        "txindex count should increase after mining"
    );
}

#[test]
fn txindex_persists_across_restart() {
    let dir = TempDir::new().unwrap();
    let datadir = dir.path();

    // First session: mine some blocks with txindex enabled
    {
        let mut node = Node::open_or_init("devnet", datadir, true, true).unwrap();
        rpc(&mut node, "generatenextblock", json!([3]));

        let info = rpc(&mut node, "gettxindexinfo", json!([]));
        // 3 blocks mined, each with 1 coinbase = 3 indexed transactions
        // (genesis isn't indexed because it's created during init, not connect_block)
        assert!(info["result"]["txcount"].as_u64().unwrap() >= 3);

        node.save().unwrap();
    }

    // Second session: verify txindex persisted
    {
        let mut node = Node::open_or_init("devnet", datadir, true, true).unwrap();

        let info = rpc(&mut node, "gettxindexinfo", json!([]));
        // Should still have the same tx count
        assert!(info["result"]["txcount"].as_u64().unwrap() >= 3);
    }
}
