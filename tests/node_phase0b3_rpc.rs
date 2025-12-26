use hex::FromHex;
use serde_json::json;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
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

fn build_block(prev_hash: [u8; 32], height: u32, coin_value: u64) -> Block {
    let pkhash = [0x11u8; 32];
    let spk = build_p2qpkh(pkhash);
    let cb = coinbase_tx(b"phase0b3 rpc", coin_value, spk);
    let merkle = cb.txid();
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_766_620_800 + height,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txdata: vec![cb],
    }
}

fn serialize_block(block: &Block) -> Vec<u8> {
    block.serialize(true)
}

fn rpc(id: i32, method: &str, params: serde_json::Value, node: &mut Node) -> serde_json::Value {
    let req = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let resp = handle_rpc(node, &req.to_string());
    serde_json::from_str(&resp).expect("resp json")
}

#[test]
fn rpc_basic_queries() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    let r = rpc(1, "getblockcount", json!([]), &mut node);
    assert_eq!(r["result"], 0);

    let best = rpc(2, "getbestblockhash", json!([]), &mut node);
    let genesis = best["result"].as_str().unwrap();

    let h0 = rpc(3, "getblockhash", json!([0]), &mut node);
    assert_eq!(h0["result"].as_str().unwrap(), genesis);

    let blk = rpc(4, "getblock", json!([genesis]), &mut node);
    let blk_hex = blk["result"].as_str().unwrap();
    assert!(!blk_hex.is_empty());
}

#[test]
fn rpc_submit_block_success_and_state() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    let mut prev = [0u8; 32];
    let tip_bytes = Vec::from_hex(node.best_hash_hex()).unwrap();
    prev.copy_from_slice(&tip_bytes);

    let block = build_block(prev, 1, qpb_consensus::reward::block_subsidy(1));
    let bytes = serialize_block(&block);
    let blk_hex = hex::encode(bytes);

    let resp = rpc(1, "submitblock", json!([blk_hex]), &mut node);
    assert_eq!(resp["result"], "accepted");
    assert_eq!(node.height(), 1);

    // verify state persists
    let mut node2 = Node::open_or_init("devnet", datadir, true).unwrap();
    assert_eq!(node2.height(), 1);
}

#[test]
fn rpc_submit_block_rejects_bad_hex() {
    let dir = tempdir().unwrap();
    let mut node = Node::open_or_init("devnet", dir.path(), true).unwrap();

    let resp = rpc(1, "submitblock", json!(["zzzz"]), &mut node);
    assert!(resp["error"].is_object());
}
