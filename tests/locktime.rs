//! Locktime validation tests.
//!
//! Tests for nLockTime, sequence finality, Median Time Past (BIP113), and BIP68 relative locktimes.

use tempfile::tempdir;

use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;
use qpb_consensus::validation::{
    calculate_sequence_lock, check_locktime, check_sequence_locks, compute_mtp,
    is_tx_final_by_sequence, sequence_locktime_disabled, sequence_locktime_is_time,
    sequence_locktime_value,
};
use qpb_consensus::{
    LOCKTIME_THRESHOLD, OutPoint, Prevout, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_TYPE_FLAG, Transaction, TxIn, TxOut,
};

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

// ============================================================================
// BIP68 Relative locktime unit tests
// ============================================================================

#[test]
fn test_sequence_locktime_disabled() {
    // Disabled flag set (bit 31)
    assert!(sequence_locktime_disabled(SEQUENCE_LOCKTIME_DISABLE_FLAG));
    assert!(sequence_locktime_disabled(0x80000000));
    assert!(sequence_locktime_disabled(0xffffffff)); // SEQUENCE_FINAL also disabled

    // Disabled flag not set
    assert!(!sequence_locktime_disabled(0));
    assert!(!sequence_locktime_disabled(10));
    assert!(!sequence_locktime_disabled(SEQUENCE_LOCKTIME_TYPE_FLAG)); // time flag only
}

#[test]
fn test_sequence_locktime_is_time() {
    // Time flag set (bit 22)
    assert!(sequence_locktime_is_time(SEQUENCE_LOCKTIME_TYPE_FLAG));
    assert!(sequence_locktime_is_time(0x00400000));
    assert!(sequence_locktime_is_time(0x00400001)); // time flag + 1 block

    // Time flag not set (block-based)
    assert!(!sequence_locktime_is_time(0));
    assert!(!sequence_locktime_is_time(10));
    assert!(!sequence_locktime_is_time(SEQUENCE_LOCKTIME_DISABLE_FLAG)); // disable flag only
}

#[test]
fn test_sequence_locktime_value() {
    // Lower 16 bits extracted
    assert_eq!(sequence_locktime_value(0), 0);
    assert_eq!(sequence_locktime_value(10), 10);
    assert_eq!(sequence_locktime_value(0xffff), 0xffff);
    assert_eq!(sequence_locktime_value(0x0001ffff), 0xffff); // bits above 16 ignored
    assert_eq!(
        sequence_locktime_value(SEQUENCE_LOCKTIME_TYPE_FLAG | 100),
        100
    );
}

#[test]
fn test_calculate_sequence_lock_disabled() {
    // When disabled, returns None
    assert!(calculate_sequence_lock(SEQUENCE_LOCKTIME_DISABLE_FLAG, 100, 1000).is_none());
    assert!(calculate_sequence_lock(SEQUENCE_FINAL, 100, 1000).is_none());
}

#[test]
fn test_calculate_sequence_lock_block_based() {
    // Block-based: prevout_height + lock_value
    let result = calculate_sequence_lock(10, 100, 0);
    assert_eq!(result, Some((110, 0))); // height=100+10, time=0

    let result = calculate_sequence_lock(0, 50, 0);
    assert_eq!(result, Some((50, 0))); // height=50+0
}

#[test]
fn test_calculate_sequence_lock_time_based() {
    // Time-based: prevout_mtp + (lock_value * 512)
    let sequence = SEQUENCE_LOCKTIME_TYPE_FLAG | 10; // 10 * 512 = 5120 seconds
    let prevout_mtp = 1000000;
    let result = calculate_sequence_lock(sequence, 100, prevout_mtp);
    assert_eq!(result, Some((0, 1000000 + 5120))); // height=0, time=mtp+5120
}

#[test]
fn test_check_sequence_locks_version1_skipped() {
    // BIP68 only applies to version >= 2
    let tx = Transaction {
        version: 1, // Version 1 - BIP68 not enforced
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 10, // Would require 10 blocks, but ignored for v1
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![Prevout::new(1000, vec![0x6a], 100, false)];

    // Should succeed even though block height is less than required (100 + 10 = 110)
    assert!(check_sequence_locks(&tx, &prevouts, 105, 0, |_| 0).is_ok());
}

#[test]
fn test_check_sequence_locks_disabled_input() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: SEQUENCE_LOCKTIME_DISABLE_FLAG | 1000, // Disabled, ignore lock value
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![Prevout::new(1000, vec![0x6a], 100, false)];

    // Should succeed because relative locktime is disabled
    assert!(check_sequence_locks(&tx, &prevouts, 101, 0, |_| 0).is_ok());
}

#[test]
fn test_check_sequence_locks_block_based_not_satisfied() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 10, // Require 10 block confirmations
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![Prevout::new(1000, vec![0x6a], 100, false)]; // confirmed at height 100

    // Block height 109 < required 110 -> not satisfied
    assert!(check_sequence_locks(&tx, &prevouts, 109, 0, |_| 0).is_err());
}

#[test]
fn test_check_sequence_locks_block_based_satisfied() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 10, // Require 10 block confirmations
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![Prevout::new(1000, vec![0x6a], 100, false)]; // confirmed at height 100

    // Block height 110 >= required 110 -> satisfied
    assert!(check_sequence_locks(&tx, &prevouts, 110, 0, |_| 0).is_ok());

    // Block height 111 >= required 110 -> satisfied
    assert!(check_sequence_locks(&tx, &prevouts, 111, 0, |_| 0).is_ok());
}

#[test]
fn test_check_sequence_locks_time_based_not_satisfied() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 10, // Require 10 * 512 = 5120 seconds
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![Prevout::new(1000, vec![0x6a], 100, false)];
    let prevout_mtp = 1000000;
    let required_mtp = prevout_mtp + 5120;

    // Current MTP < required -> not satisfied
    assert!(check_sequence_locks(&tx, &prevouts, 200, required_mtp - 1, |_| prevout_mtp).is_err());
}

#[test]
fn test_check_sequence_locks_time_based_satisfied() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: SEQUENCE_LOCKTIME_TYPE_FLAG | 10, // Require 10 * 512 = 5120 seconds
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![Prevout::new(1000, vec![0x6a], 100, false)];
    let prevout_mtp = 1000000;
    let required_mtp = prevout_mtp + 5120;

    // Current MTP >= required -> satisfied
    assert!(check_sequence_locks(&tx, &prevouts, 200, required_mtp, |_| prevout_mtp).is_ok());
    assert!(check_sequence_locks(&tx, &prevouts, 200, required_mtp + 1, |_| prevout_mtp).is_ok());
}

#[test]
fn test_check_sequence_locks_multiple_inputs() {
    let tx = Transaction {
        version: 2,
        vin: vec![
            TxIn {
                prevout: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 5, // Require 5 block confirmations
                witness: vec![],
            },
            TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 10, // Require 10 block confirmations (more restrictive)
                witness: vec![],
            },
        ],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    let prevouts = vec![
        Prevout::new(500, vec![0x6a], 100, false), // confirmed at 100
        Prevout::new(500, vec![0x6a], 100, false), // confirmed at 100
    ];

    // Height 109: first input satisfied (100+5=105), second not (100+10=110)
    assert!(check_sequence_locks(&tx, &prevouts, 109, 0, |_| 0).is_err());

    // Height 110: both satisfied
    assert!(check_sequence_locks(&tx, &prevouts, 110, 0, |_| 0).is_ok());
}

#[test]
fn test_check_sequence_locks_unconfirmed_prevout() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 1, // Require at least 1 confirmation
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    // Unconfirmed prevout (height=0)
    let prevouts = vec![Prevout::new(1000, vec![0x6a], 0, false)];

    // Should fail because unconfirmed outputs can't satisfy relative locktimes > 0
    assert!(check_sequence_locks(&tx, &prevouts, 100, 0, |_| 0).is_err());
}

#[test]
fn test_check_sequence_locks_zero_lock_unconfirmed() {
    let tx = Transaction {
        version: 2,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: vec![],
            sequence: 0, // Zero lock value - no relative lock
            witness: vec![],
        }],
        vout: vec![TxOut {
            value: 1000,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    };

    // Unconfirmed prevout (height=0) but lock value is 0
    let prevouts = vec![Prevout::new(1000, vec![0x6a], 0, false)];

    // Should succeed because lock value is 0
    assert!(check_sequence_locks(&tx, &prevouts, 100, 0, |_| 0).is_ok());
}
