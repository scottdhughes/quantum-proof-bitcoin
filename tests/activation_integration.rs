//! Integration tests for SHRINCS activation height boundaries.
//!
//! These tests verify that the consensus rules correctly enforce algorithm
//! activation at the appropriate block heights on each network.
//!
//! Run with: `cargo test --features shrincs-dev activation_integration`

#![cfg(feature = "shrincs-dev")]

use qpb_consensus::{
    OutPoint, Prevout, Transaction, TxIn, TxOut,
    activation::{
        MEMPOOL_PRE_ACTIVATION_BLOCKS, Network, is_algorithm_active,
        should_accept_shrincs_to_mempool,
    },
    constants::SHRINCS_ALG_ID,
    mldsa_keypair, mldsa_sign, qpb_sighash, shrincs_keypair, shrincs_sign,
    validate_transaction_basic,
};

// ============================================================================
// Helper functions
// ============================================================================

/// Build a P2QPKH scriptPubKey from an algorithm-prefixed public key.
fn build_p2qpkh_spk(pk_ser: &[u8]) -> Vec<u8> {
    let qpkh = qpb_consensus::qpkh32(pk_ser);
    qpb_consensus::build_p2qpkh(qpkh)
}

/// Create a signed ML-DSA-65 transaction for testing.
fn create_mldsa_tx() -> (Transaction, Vec<Prevout>) {
    let (pk_bytes, sk_bytes) = mldsa_keypair();
    let mut pk_ser = Vec::with_capacity(1 + pk_bytes.len());
    pk_ser.push(0x11); // ML-DSA-65 algorithm ID
    pk_ser.extend_from_slice(&pk_bytes);

    let spk = build_p2qpkh_spk(&pk_ser);
    let prevouts = vec![Prevout::regular(50_0000_0000, spk.clone())];

    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: vec![Vec::new(), pk_ser.clone()],
        }],
        vout: vec![TxOut {
            value: 49_0000_0000,
            script_pubkey: spk.clone(),
        }],
        lock_time: 0,
    };

    // Sign
    let msg = qpb_sighash(&tx, 0, &prevouts, 0x01, 0x00, None).unwrap();
    let mut sig_ser = mldsa_sign(&sk_bytes, &msg).expect("ml-dsa sign");
    sig_ser.push(0x01); // SIGHASH_ALL
    tx.vin[0].witness = vec![sig_ser, pk_ser];

    (tx, prevouts)
}

/// Create a signed SHRINCS transaction for testing.
fn create_shrincs_tx() -> (Transaction, Vec<Prevout>) {
    let (pk_ser, key_material, mut state) = shrincs_keypair().expect("shrincs keygen");

    let spk = build_p2qpkh_spk(&pk_ser);
    let prevouts = vec![Prevout::regular(50_0000_0000, spk.clone())];

    let mut tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: vec![Vec::new(), pk_ser.clone()],
        }],
        vout: vec![TxOut {
            value: 49_0000_0000,
            script_pubkey: spk.clone(),
        }],
        lock_time: 0,
    };

    // Sign
    let msg = qpb_sighash(&tx, 0, &prevouts, 0x01, 0x00, None).unwrap();
    let sig_ser = shrincs_sign(&key_material, &mut state, &msg, 0x01).expect("shrincs sign");
    tx.vin[0].witness = vec![sig_ser, pk_ser];

    (tx, prevouts)
}

// ============================================================================
// Activation boundary tests
// ============================================================================

/// Test that SHRINCS transactions are rejected on mainnet (no activation height).
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_shrincs_rejected_on_mainnet() {
    let (tx, prevouts) = create_shrincs_tx();

    // Mainnet has no SHRINCS activation - should fail at any height
    for height in [0, 100, 1000, 1_000_000] {
        let result = validate_transaction_basic(&tx, &prevouts, height, Network::Mainnet);
        assert!(
            result.is_err(),
            "SHRINCS should be rejected on mainnet at height {}",
            height
        );
    }
}

/// Test that SHRINCS transactions are accepted on devnet (activation at height 0).
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_shrincs_accepted_on_devnet() {
    let (tx, prevouts) = create_shrincs_tx();

    // Devnet has immediate SHRINCS activation - should succeed at any height
    for height in [0, 1, 100, 1000] {
        let result = validate_transaction_basic(&tx, &prevouts, height, Network::Devnet);
        assert!(
            result.is_ok(),
            "SHRINCS should be accepted on devnet at height {}: {:?}",
            height,
            result.err()
        );
        // SHRINCS costs 2 PQSigCheck units
        assert_eq!(result.unwrap(), 2);
    }
}

/// Test that SHRINCS transactions are accepted on testnet (activation at height 0).
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_shrincs_accepted_on_testnet() {
    let (tx, prevouts) = create_shrincs_tx();

    // Testnet has immediate SHRINCS activation - should succeed at any height
    let result = validate_transaction_basic(&tx, &prevouts, 0, Network::Testnet);
    assert!(
        result.is_ok(),
        "SHRINCS should be accepted on testnet: {:?}",
        result.err()
    );
}

/// Test that ML-DSA-65 transactions work on all networks at all heights.
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_mldsa_always_accepted() {
    let (tx, prevouts) = create_mldsa_tx();

    // ML-DSA-65 is genesis algorithm - always valid
    for network in [Network::Devnet, Network::Testnet, Network::Mainnet] {
        for height in [0, 100, 1_000_000] {
            let result = validate_transaction_basic(&tx, &prevouts, height, network);
            assert!(
                result.is_ok(),
                "ML-DSA-65 should be accepted on {:?} at height {}: {:?}",
                network,
                height,
                result.err()
            );
            // ML-DSA-65 costs 1 PQSigCheck unit
            assert_eq!(result.unwrap(), 1);
        }
    }
}

// ============================================================================
// Algorithm activation unit tests
// ============================================================================

#[test]
fn test_is_algorithm_active_shrincs_per_network() {
    // Devnet: SHRINCS active from block 0
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Devnet));
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 1000, Network::Devnet));

    // Testnet: SHRINCS active from block 0
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Testnet));
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 1000, Network::Testnet));

    // Mainnet: SHRINCS never active (None)
    assert!(!is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Mainnet));
    assert!(!is_algorithm_active(
        SHRINCS_ALG_ID,
        1_000_000,
        Network::Mainnet
    ));
}

#[test]
fn test_regtest_same_as_devnet() {
    // Regtest should have same activation as devnet
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Regtest));
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 100, Network::Regtest));
}

// ============================================================================
// Mempool policy tests
// ============================================================================

#[test]
fn test_mempool_acceptance_devnet() {
    // Devnet has activation at 0, so always accept
    assert!(should_accept_shrincs_to_mempool(0, Network::Devnet));
    assert!(should_accept_shrincs_to_mempool(100, Network::Devnet));
    assert!(should_accept_shrincs_to_mempool(1000, Network::Devnet));
}

#[test]
fn test_mempool_acceptance_mainnet() {
    // Mainnet has no activation, so never accept
    assert!(!should_accept_shrincs_to_mempool(0, Network::Mainnet));
    assert!(!should_accept_shrincs_to_mempool(
        1_000_000,
        Network::Mainnet
    ));
}

#[test]
fn test_mempool_pre_activation_window_constant() {
    // Verify the pre-activation window constant
    assert_eq!(MEMPOOL_PRE_ACTIVATION_BLOCKS, 100);
}

// ============================================================================
// Mixed algorithm tests
// ============================================================================

/// Test that both ML-DSA-65 and SHRINCS transactions validate correctly
/// when both algorithms are active.
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_mixed_algorithm_transactions() {
    let (mldsa_tx, mldsa_prevouts) = create_mldsa_tx();
    let (shrincs_tx, shrincs_prevouts) = create_shrincs_tx();

    // On devnet, both should validate
    let mldsa_result = validate_transaction_basic(&mldsa_tx, &mldsa_prevouts, 100, Network::Devnet);
    let shrincs_result =
        validate_transaction_basic(&shrincs_tx, &shrincs_prevouts, 100, Network::Devnet);

    assert!(mldsa_result.is_ok(), "ML-DSA-65 should validate");
    assert!(shrincs_result.is_ok(), "SHRINCS should validate");

    // Verify correct costs
    assert_eq!(mldsa_result.unwrap(), 1, "ML-DSA-65 costs 1 unit");
    assert_eq!(shrincs_result.unwrap(), 2, "SHRINCS costs 2 units");
}

/// Test that ML-DSA-65 works on mainnet while SHRINCS is rejected.
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_mainnet_algorithm_disparity() {
    let (mldsa_tx, mldsa_prevouts) = create_mldsa_tx();
    let (shrincs_tx, shrincs_prevouts) = create_shrincs_tx();

    // On mainnet at height 0
    let mldsa_result = validate_transaction_basic(&mldsa_tx, &mldsa_prevouts, 0, Network::Mainnet);
    let shrincs_result =
        validate_transaction_basic(&shrincs_tx, &shrincs_prevouts, 0, Network::Mainnet);

    assert!(mldsa_result.is_ok(), "ML-DSA-65 should work on mainnet");
    assert!(
        shrincs_result.is_err(),
        "SHRINCS should be rejected on mainnet"
    );
}

// ============================================================================
// Cost accounting tests
// ============================================================================

#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_pqsigcheck_costs() {
    let (mldsa_tx, mldsa_prevouts) = create_mldsa_tx();
    let (shrincs_tx, shrincs_prevouts) = create_shrincs_tx();

    // ML-DSA-65: 1 PQSigCheck unit
    let mldsa_cost =
        validate_transaction_basic(&mldsa_tx, &mldsa_prevouts, 0, Network::Devnet).unwrap();
    assert_eq!(mldsa_cost, 1, "ML-DSA-65 should cost 1 PQSigCheck unit");

    // SHRINCS: 2 PQSigCheck units (hash-based is ~2x slower)
    let shrincs_cost =
        validate_transaction_basic(&shrincs_tx, &shrincs_prevouts, 0, Network::Devnet).unwrap();
    assert_eq!(shrincs_cost, 2, "SHRINCS should cost 2 PQSigCheck units");
}
