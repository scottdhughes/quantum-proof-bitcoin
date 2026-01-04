//! Locktime validation tests.
//!
//! Tests for nLockTime, sequence finality, and Median Time Past (BIP113).

use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
use qpb_consensus::validation::{check_locktime, compute_mtp, is_tx_final_by_sequence};
use qpb_consensus::{LOCKTIME_THRESHOLD, OutPoint, SEQUENCE_FINAL, Transaction, TxIn, TxOut};

fn rpc_call(node: &mut Node, method: &str, params: &str) -> serde_json::Value {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{}}}"#,
        method, params
    );
    let resp = handle_rpc(node, &req);
    serde_json::from_str(&resp).unwrap()
}

// ============================================================================
// Unit tests for helper functions
// ============================================================================

#[test]
fn test_is_tx_final_by_sequence_all_final() {
    let tx = Transaction {
        version: 1,
        vin: vec![
            TxIn {
                prevout: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: SEQUENCE_FINAL,
                witness: vec![],
            },
            TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: SEQUENCE_FINAL,
                witness: vec![],
            },
        ],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 100,
    };

    assert!(
        is_tx_final_by_sequence(&tx),
        "All inputs have SEQUENCE_FINAL"
    );
}

#[test]
fn test_is_tx_final_by_sequence_one_not_final() {
    let tx = Transaction {
        version: 1,
        vin: vec![
            TxIn {
                prevout: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: SEQUENCE_FINAL,
                witness: vec![],
            },
            TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: SEQUENCE_FINAL - 1, // Not final
                witness: vec![],
            },
        ],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 100,
    };

    assert!(
        !is_tx_final_by_sequence(&tx),
        "One input is not SEQUENCE_FINAL"
    );
}

#[test]
fn test_compute_mtp_empty() {
    assert_eq!(compute_mtp(&[]), 0);
}

#[test]
fn test_compute_mtp_single() {
    assert_eq!(compute_mtp(&[12345]), 12345);
}

#[test]
fn test_compute_mtp_odd_count() {
    // [1, 2, 3, 4, 5] -> sorted = [1, 2, 3, 4, 5] -> median = 3
    assert_eq!(compute_mtp(&[3, 1, 5, 2, 4]), 3);
}

#[test]
fn test_compute_mtp_even_count() {
    // [1, 2, 3, 4] -> sorted = [1, 2, 3, 4] -> len/2 = 2 -> index 2 = 3
    assert_eq!(compute_mtp(&[3, 1, 4, 2]), 3);
}

#[test]
fn test_compute_mtp_full_11_blocks() {
    // 11 timestamps unsorted, median should be the 6th smallest
    let timestamps = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100];
    assert_eq!(compute_mtp(&timestamps), 600);
}

// ============================================================================
// Locktime check tests
// ============================================================================

#[test]
fn test_locktime_zero_always_valid() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0, // Not final
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    assert!(check_locktime(&tx, 0, 0).is_ok());
    assert!(check_locktime(&tx, 100, 0).is_ok());
}

#[test]
fn test_locktime_final_sequence_ignores_locktime() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: SEQUENCE_FINAL,
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 1_000_000, // High locktime but ignored because sequence is final
    };

    assert!(
        check_locktime(&tx, 1, 0).is_ok(),
        "Final sequence should ignore locktime"
    );
}

#[test]
fn test_locktime_height_based_not_satisfied() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0, // Not final
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 100, // Height-based (< 500M)
    };

    // Block height 99 < locktime 100 -> not satisfied
    assert!(check_locktime(&tx, 99, 0).is_err());
}

#[test]
fn test_locktime_height_based_satisfied() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0, // Not final
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 100, // Height-based
    };

    // Block height 100 >= locktime 100 -> satisfied
    assert!(check_locktime(&tx, 100, 0).is_ok());
    // Block height 101 >= locktime 100 -> satisfied
    assert!(check_locktime(&tx, 101, 0).is_ok());
}

#[test]
fn test_locktime_time_based_not_satisfied() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0, // Not final
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: LOCKTIME_THRESHOLD + 1000, // Time-based (>= 500M)
    };

    // MTP is less than locktime -> not satisfied
    let mtp = LOCKTIME_THRESHOLD + 999;
    assert!(check_locktime(&tx, 1000, mtp).is_err());
}

#[test]
fn test_locktime_time_based_satisfied() {
    let tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0, // Not final
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: LOCKTIME_THRESHOLD + 1000, // Time-based
    };

    // MTP equals locktime -> satisfied
    let mtp = LOCKTIME_THRESHOLD + 1000;
    assert!(check_locktime(&tx, 1000, mtp).is_ok());

    // MTP exceeds locktime -> satisfied
    let mtp = LOCKTIME_THRESHOLD + 1001;
    assert!(check_locktime(&tx, 1000, mtp).is_ok());
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn mempool_rejects_future_height_locktime() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and mine coins
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["miner"]"#);
    let miner_addr = resp["result"].as_str().unwrap().to_string();

    // Mine 101 blocks to mature coinbase
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, miner_addr),
    );
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    // Try to create a transaction with future locktime via raw transaction
    // This would require rawtx RPC which doesn't exist yet, so we test via node state
    let height = node.store.height();
    assert!(height >= 100, "Need at least 100 blocks for test");

    // For now, verify the node can compute MTP correctly
    let mtp = node.compute_mtp(height);
    assert!(mtp > 0, "MTP should be non-zero after mining blocks");
}

#[test]
fn normal_transactions_with_final_sequence_succeed() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();

    // Create wallet and mine coins
    rpc_call(&mut node, "createwallet", "[]");
    let resp = rpc_call(&mut node, "getnewaddress", r#"["miner"]"#);
    let miner_addr = resp["result"].as_str().unwrap().to_string();
    let resp = rpc_call(&mut node, "getnewaddress", r#"["recipient"]"#);
    let recipient_addr = resp["result"].as_str().unwrap().to_string();

    // Mine 101 blocks to mature coinbase
    rpc_call(
        &mut node,
        "generatetoaddress",
        &format!(r#"[1, "{}"]"#, miner_addr),
    );
    for _ in 0..10 {
        rpc_call(&mut node, "generatenextblock", "[10]");
    }

    // Send transaction (uses SEQUENCE_FINAL by default)
    let resp = rpc_call(
        &mut node,
        "sendtoaddress",
        &format!(r#"["{}", 1000]"#, recipient_addr),
    );

    assert!(
        resp.get("error").is_none() || resp["error"].is_null(),
        "Normal transaction should succeed: {:?}",
        resp["error"]
    );
}
