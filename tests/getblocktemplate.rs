//! Tests for the getblocktemplate RPC.

use tempfile::tempdir;

use qpb_consensus::node::chainparams::{load_chainparams, select_network};
use qpb_consensus::node::miner::build_block_template;
use qpb_consensus::node::node::Node;
use qpb_consensus::reward::block_subsidy;

fn load_devnet_params() -> qpb_consensus::node::chainparams::NetworkParams {
    let cp = load_chainparams(std::path::Path::new("docs/chain/chainparams.json")).unwrap();
    select_network(&cp, "devnet").unwrap().clone()
}

#[test]
fn template_empty_mempool() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let node = Node::open_or_init("devnet", datadir, true).unwrap();
    let net = load_devnet_params();

    let template = build_block_template(&node, &net).unwrap();

    // Empty mempool = no transactions in template
    assert!(template.transactions.is_empty());

    // Height should be 1 (next block after genesis)
    assert_eq!(template.height, 1);

    // Coinbase value should be just the subsidy (no fees)
    let expected_subsidy = block_subsidy(1);
    assert_eq!(template.coinbasevalue, expected_subsidy);

    // Version should be 1
    assert_eq!(template.version, 1);

    // Bits should be hex formatted
    assert!(!template.bits.is_empty());

    // Target should be 32-byte hex (64 chars)
    assert_eq!(template.target.len(), 64);
}

#[test]
fn template_has_correct_prev_hash() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let node = Node::open_or_init("devnet", datadir, true).unwrap();
    let net = load_devnet_params();

    // Get genesis hash
    let genesis_hash = node.best_hash_hex();

    let template = build_block_template(&node, &net).unwrap();

    // Previous block hash should match genesis
    assert_eq!(template.previousblockhash, genesis_hash);
}

#[test]
fn template_height_increments_after_block() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    let net = load_devnet_params();

    // Template for block 1
    let template1 = build_block_template(&node, &net).unwrap();
    assert_eq!(template1.height, 1);

    // Mine a block using generatenextblock-style approach
    let bytes = qpb_consensus::node::miner::mine_block_bytes(&node, &net, true).unwrap();
    node.submit_block_bytes(&bytes).unwrap();

    // Now template should be for block 2
    let template2 = build_block_template(&node, &net).unwrap();
    assert_eq!(template2.height, 2);

    // Previous hash should have changed
    assert_ne!(template1.previousblockhash, template2.previousblockhash);
}

#[test]
fn template_coinbase_value_includes_subsidy() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let node = Node::open_or_init("devnet", datadir, true).unwrap();
    let net = load_devnet_params();

    let template = build_block_template(&node, &net).unwrap();

    // With empty mempool, coinbase = subsidy
    let subsidy = block_subsidy(template.height as u32);
    assert_eq!(template.coinbasevalue, subsidy);
}

#[test]
fn template_serializes_to_json() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let node = Node::open_or_init("devnet", datadir, true).unwrap();
    let net = load_devnet_params();

    let template = build_block_template(&node, &net).unwrap();

    // Should serialize to valid JSON
    let json = serde_json::to_value(&template).unwrap();

    // Check all expected fields are present
    assert!(json.get("version").is_some());
    assert!(json.get("previousblockhash").is_some());
    assert!(json.get("transactions").is_some());
    assert!(json.get("coinbasevalue").is_some());
    assert!(json.get("target").is_some());
    assert!(json.get("bits").is_some());
    assert!(json.get("curtime").is_some());
    assert!(json.get("height").is_some());
}
