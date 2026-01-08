use serde_json::json;
use std::path::Path;
use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::{RpcAction, handle_rpc_action};

fn rpc(
    id: i32,
    method: &str,
    params: serde_json::Value,
    node: &mut Node,
) -> (serde_json::Value, RpcAction) {
    let req = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    });
    let (resp, action) = handle_rpc_action(node, &req.to_string());
    let val: serde_json::Value = serde_json::from_str(&resp).expect("json");
    (val, action)
}

#[test]
fn rpc_stop_returns_action() {
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
    let (resp, action) = rpc(1, "stop", json!([]), &mut node);
    assert_eq!(action, RpcAction::Stop);
    assert_eq!(resp["result"].as_str().unwrap(), "stopping");
}
