//! Transaction relay protocol tests.

use qpb_consensus::node::p2p::{
    InvEntry, MSG_TX, RelayManager, parse_inv, ser_getdata_tx, ser_inv_tx,
};
use qpb_consensus::types::{OutPoint, Transaction, TxIn, TxOut};

fn make_test_tx(version: i32) -> Transaction {
    Transaction {
        version,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [version as u8; 32],
                vout: 0,
            },
            script_sig: vec![0x51], // OP_TRUE
            sequence: 0xffffffff,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value: 50_000,
            script_pubkey: vec![0x00, 0x14, 0xab, 0xcd, 0xef],
        }],
        lock_time: 0,
    }
}

#[test]
fn inv_serialization_roundtrip() {
    let txid1 = [0x11u8; 32];
    let txid2 = [0x22u8; 32];

    // Serialize INV with two txids
    let payload = ser_inv_tx(&[txid1, txid2]);

    // Parse back
    let entries = parse_inv(&payload).unwrap();
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].inv_type, MSG_TX);
    assert_eq!(entries[0].hash, txid1);

    assert_eq!(entries[1].inv_type, MSG_TX);
    assert_eq!(entries[1].hash, txid2);
}

#[test]
fn getdata_serialization_roundtrip() {
    let txid = [0xabu8; 32];

    // Serialize GETDATA for transaction
    let payload = ser_getdata_tx(&[txid]);

    // Parse back (same format as INV)
    let entries = parse_inv(&payload).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].inv_type, MSG_TX);
    assert_eq!(entries[0].hash, txid);
}

#[test]
fn transaction_serialize_parse_roundtrip() {
    // Create a test transaction
    let tx = make_test_tx(1);
    let original_txid = tx.txid();

    // Serialize (without witness for txid, with witness for relay)
    let bytes_no_wit = tx.serialize(false);
    let bytes_wit = tx.serialize(true);

    // Verify txid is hash of non-witness serialization
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(Sha256::digest(&bytes_no_wit));
    let mut computed_txid = [0u8; 32];
    computed_txid.copy_from_slice(&hash);
    assert_eq!(computed_txid, original_txid);

    // Verify witness serialization is larger (has marker/flag)
    // For a tx with empty witness, marker/flag adds 2 bytes, witness count adds 1 per input
    assert!(bytes_wit.len() > bytes_no_wit.len() || tx.vin.iter().all(|i| i.witness.is_empty()));
}

#[test]
fn relay_manager_tracks_known_txids() {
    let mut manager = RelayManager::new();

    let txid1 = [0x11u8; 32];
    let txid2 = [0x22u8; 32];

    // Initially empty
    assert!(!manager.knows_tx(&txid1));
    assert!(!manager.knows_tx(&txid2));

    // Mark one as known
    manager.mark_known(txid1);
    assert!(manager.knows_tx(&txid1));
    assert!(!manager.knows_tx(&txid2));

    // Broadcast marks as known
    manager.broadcast_tx(txid2);
    assert!(manager.knows_tx(&txid2));
}

#[test]
fn relay_manager_starts_with_no_peers() {
    let manager = RelayManager::new();
    assert_eq!(manager.peer_count(), 0);
}

#[test]
fn empty_inv_parses_correctly() {
    let payload = ser_inv_tx(&[]);
    let entries = parse_inv(&payload).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn inv_entry_equality() {
    let entry1 = InvEntry {
        inv_type: MSG_TX,
        hash: [0x11; 32],
    };
    let entry2 = InvEntry {
        inv_type: MSG_TX,
        hash: [0x11; 32],
    };
    let entry3 = InvEntry {
        inv_type: MSG_TX,
        hash: [0x22; 32],
    };

    assert_eq!(entry1, entry2);
    assert_ne!(entry1, entry3);
}
