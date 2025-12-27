use serde_json::json;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;

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
fn rpc_generate_next_block_increments_tip() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();
    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let tip0 = node.best_hash_hex().to_string();
    let r = rpc(1, "generatenextblock", json!([]), &mut node);
    let tip1 = r["result"].as_str().unwrap().to_string();
    assert_ne!(tip0, tip1);
    assert_eq!(node.height(), 1);

    // getblock should return bytes
    let blk = rpc(2, "getblock", json!([tip1]), &mut node);
    let blk_hex = blk["result"].as_str().unwrap();
    assert!(!blk_hex.is_empty());
}
