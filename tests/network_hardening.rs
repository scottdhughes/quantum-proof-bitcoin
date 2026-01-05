//! Integration tests for network hardening features:
//! - Ban list management (setban, listbanned, clearbanned)
//! - Checkpoint verification (getcheckpoints)

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
use serde_json::{Value, json};
use tempfile::TempDir;

fn setup_node() -> (Node, TempDir) {
    let tmpdir = TempDir::new().unwrap();
    let node = Node::open_or_init("devnet", tmpdir.path(), true, false).unwrap();
    (node, tmpdir)
}

fn rpc_call(node: &mut Node, method: &str, params: Vec<Value>) -> Value {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });
    let resp = handle_rpc(node, &req.to_string());
    let parsed: Value = serde_json::from_str(&resp).unwrap();
    parsed
}

// ============================================================================
// Ban Management Tests
// ============================================================================

#[test]
fn setban_add_and_list() {
    let (mut node, _tmpdir) = setup_node();

    // Initially no bans
    let resp = rpc_call(&mut node, "listbanned", vec![]);
    let bans = resp["result"].as_array().unwrap();
    assert!(bans.is_empty());

    // Add a ban
    let resp = rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.1".into(), "add".into()],
    );
    assert!(resp["result"]["banned"].as_bool().unwrap());

    // Verify it's in the list
    let resp = rpc_call(&mut node, "listbanned", vec![]);
    let bans = resp["result"].as_array().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0]["address"].as_str().unwrap(), "192.168.1.1");
    assert!(bans[0]["unban_time"].as_u64().unwrap() > 0);
}

#[test]
fn setban_with_custom_duration_and_reason() {
    let (mut node, _tmpdir) = setup_node();

    // Ban with custom duration (1 hour) and reason
    let resp = rpc_call(
        &mut node,
        "setban",
        vec![
            "10.0.0.1".into(),
            "add".into(),
            json!(3600),
            "spamming".into(),
        ],
    );
    assert!(resp["result"]["banned"].as_bool().unwrap());

    // Verify reason was stored
    let resp = rpc_call(&mut node, "listbanned", vec![]);
    let bans = resp["result"].as_array().unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0]["reason"].as_str().unwrap(), "spamming");
}

#[test]
fn setban_remove() {
    let (mut node, _tmpdir) = setup_node();

    // Add a ban
    rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.1".into(), "add".into()],
    );

    // Remove the ban
    let resp = rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.1".into(), "remove".into()],
    );
    assert!(resp["result"]["removed"].as_bool().unwrap());

    // Verify it's gone
    let resp = rpc_call(&mut node, "listbanned", vec![]);
    let bans = resp["result"].as_array().unwrap();
    assert!(bans.is_empty());
}

#[test]
fn setban_remove_nonexistent() {
    let (mut node, _tmpdir) = setup_node();

    // Try to remove a ban that doesn't exist
    let resp = rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.1".into(), "remove".into()],
    );
    // Should return removed: false (not an error)
    assert!(!resp["result"]["removed"].as_bool().unwrap());
}

#[test]
fn clearbanned_removes_all() {
    let (mut node, _tmpdir) = setup_node();

    // Add multiple bans
    rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.1".into(), "add".into()],
    );
    rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.2".into(), "add".into()],
    );
    rpc_call(&mut node, "setban", vec!["10.0.0.1".into(), "add".into()]);

    // Verify 3 bans
    let resp = rpc_call(&mut node, "listbanned", vec![]);
    assert_eq!(resp["result"].as_array().unwrap().len(), 3);

    // Clear all bans
    let resp = rpc_call(&mut node, "clearbanned", vec![]);
    assert!(resp["result"]["cleared"].as_bool().unwrap());

    // Verify empty
    let resp = rpc_call(&mut node, "listbanned", vec![]);
    assert!(resp["result"].as_array().unwrap().is_empty());
}

#[test]
fn ban_list_persists_across_node_restart() {
    let tmpdir = TempDir::new().unwrap();

    // Create node and add ban
    {
        let mut node = Node::open_or_init("devnet", tmpdir.path(), true, false).unwrap();
        rpc_call(
            &mut node,
            "setban",
            vec!["192.168.1.100".into(), "add".into()],
        );

        // Verify ban exists
        let resp = rpc_call(&mut node, "listbanned", vec![]);
        assert_eq!(resp["result"].as_array().unwrap().len(), 1);
    }
    // Node dropped, data saved

    // Reopen node
    {
        let mut node = Node::open_or_init("devnet", tmpdir.path(), true, false).unwrap();

        // Ban should still exist
        let resp = rpc_call(&mut node, "listbanned", vec![]);
        let bans = resp["result"].as_array().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0]["address"].as_str().unwrap(), "192.168.1.100");
    }
}

#[test]
fn setban_missing_params() {
    let (mut node, _tmpdir) = setup_node();

    // Missing action
    let resp = rpc_call(&mut node, "setban", vec!["192.168.1.1".into()]);
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("missing action")
    );

    // Missing address
    let resp = rpc_call(&mut node, "setban", vec![]);
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("missing address")
    );
}

#[test]
fn setban_invalid_action() {
    let (mut node, _tmpdir) = setup_node();

    let resp = rpc_call(
        &mut node,
        "setban",
        vec!["192.168.1.1".into(), "invalid".into()],
    );
    assert!(
        resp["error"]["message"]
            .as_str()
            .unwrap()
            .contains("add' or 'remove")
    );
}

// ============================================================================
// Checkpoint Tests
// ============================================================================

#[test]
fn getcheckpoints_devnet_empty() {
    let (mut node, _tmpdir) = setup_node();

    // Devnet should have no checkpoints (for flexible testing)
    let resp = rpc_call(&mut node, "getcheckpoints", vec![]);
    let result = &resp["result"];

    let checkpoints = result["checkpoints"].as_array().unwrap();
    assert!(checkpoints.is_empty());
    assert_eq!(result["max_height"].as_u64().unwrap(), 0);
}

#[test]
fn checkpoint_verifier_accessible() {
    let (node, _tmpdir) = setup_node();

    // The checkpoint verifier should be accessible
    let verifier = node.checkpoint_verifier();
    assert!(!verifier.has_checkpoints()); // devnet has no checkpoints
    assert_eq!(verifier.max_checkpoint_height(), 0);
}

// ============================================================================
// Peer Scoring Unit Tests (via direct struct access)
// ============================================================================

#[test]
fn peer_score_accumulation() {
    use qpb_consensus::node::peer::{Misbehavior, PeerScore};

    let mut score = PeerScore::new();
    assert_eq!(score.current_score(), 0);

    score.record(Misbehavior::Timeout);
    assert_eq!(score.current_score(), 5);

    score.record(Misbehavior::InvalidTransaction);
    assert_eq!(score.current_score(), 15);
}

#[test]
fn peer_score_ban_threshold() {
    use qpb_consensus::constants::PEER_BAN_THRESHOLD;
    use qpb_consensus::node::peer::{Misbehavior, PeerScore};

    let mut score = PeerScore::new();

    // InvalidBlock (100 points) should exceed threshold immediately
    score.record(Misbehavior::InvalidBlock);
    assert!(score.current_score() >= PEER_BAN_THRESHOLD);
    assert!(score.should_ban());
}

#[test]
fn rate_limiter_allows_within_limit() {
    use qpb_consensus::node::peer::RateLimiter;

    let mut limiter = RateLimiter::new(10, 10); // 10 tokens, 10/sec refill

    // Should allow 10 requests
    for _ in 0..10 {
        assert!(limiter.try_consume(1));
    }

    // 11th should fail (no refill time passed)
    assert!(!limiter.try_consume(1));
}

#[test]
fn connection_limiter_enforces_limits() {
    use qpb_consensus::constants::{
        MAX_CONNECTIONS_PER_IP, MAX_CONNECTIONS_PER_SUBNET, MAX_OUTBOUND_CONNECTIONS,
    };
    use qpb_consensus::node::peer::ConnectionLimiter;

    let mut limiter = ConnectionLimiter::new();

    // First connection should succeed
    assert!(limiter.can_connect("192.168.1.1", None).is_ok());
    limiter.add_connection("192.168.1.1");

    // Add connections up to the per-IP limit (or total limit, whichever is lower)
    let per_ip_limit = MAX_CONNECTIONS_PER_IP.min(MAX_OUTBOUND_CONNECTIONS);
    for _ in 1..per_ip_limit {
        limiter.add_connection("192.168.1.1");
    }

    // Next connection from same IP should fail (either MaxPerIP or MaxConnections)
    assert!(limiter.can_connect("192.168.1.1", None).is_err());

    // Reset limiter for subnet test
    let mut limiter = ConnectionLimiter::new();

    // Add connections from different IPs in same /16 subnet up to limit
    let per_subnet_limit = MAX_CONNECTIONS_PER_SUBNET.min(MAX_OUTBOUND_CONNECTIONS);
    for i in 0..per_subnet_limit {
        limiter.add_connection(&format!("10.0.{}.1", i));
    }

    // Next from same subnet should fail (either MaxPerSubnet or MaxConnections)
    assert!(limiter.can_connect("10.0.99.1", None).is_err());

    // Track disconnection
    let mut limiter = ConnectionLimiter::new();
    limiter.add_connection("192.168.1.1");
    limiter.remove_connection("192.168.1.1");
    assert!(limiter.can_connect("192.168.1.1", None).is_ok()); // Can connect again
}
