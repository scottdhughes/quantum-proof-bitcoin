//! Integration tests for SHRINCS activation.
//!
//! These tests verify that SHRINCS is the sole post-quantum algorithm and is
//! active from genesis on all networks.
//!
//! Run with: `cargo test --features shrincs-dev activation_integration`

#![cfg(feature = "shrincs-dev")]

use qpb_consensus::{
    OutPoint, Prevout, Transaction, TxIn, TxOut,
    activation::{
        Network, is_algorithm_active,
        should_accept_shrincs_to_mempool,
    },
    constants::SHRINCS_ALG_ID,
    qpb_sighash, shrincs_keypair, shrincs_sign,
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
// SHRINCS is always active (genesis algorithm)
// ============================================================================

/// Test that SHRINCS transactions are accepted on all networks from genesis.
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_shrincs_accepted_on_all_networks() {
    let (tx, prevouts) = create_shrincs_tx();

    // SHRINCS is the genesis algorithm - should succeed on all networks at any height
    for network in [Network::Devnet, Network::Testnet, Network::Mainnet, Network::Regtest] {
        for height in [0, 1, 100, 1000, 1_000_000] {
            let result = validate_transaction_basic(&tx, &prevouts, height, network);
            assert!(
                result.is_ok(),
                "SHRINCS should be accepted on {:?} at height {}: {:?}",
                network,
                height,
                result.err()
            );
            // SHRINCS costs 2 PQSigCheck units
            assert_eq!(result.unwrap(), 2);
        }
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

/// Test that SHRINCS transactions are accepted on testnet.
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_shrincs_accepted_on_testnet() {
    let (tx, prevouts) = create_shrincs_tx();

    let result = validate_transaction_basic(&tx, &prevouts, 0, Network::Testnet);
    assert!(
        result.is_ok(),
        "SHRINCS should be accepted on testnet: {:?}",
        result.err()
    );
}

/// Test that SHRINCS transactions are accepted on mainnet.
#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_shrincs_accepted_on_mainnet() {
    let (tx, prevouts) = create_shrincs_tx();

    let result = validate_transaction_basic(&tx, &prevouts, 0, Network::Mainnet);
    assert!(
        result.is_ok(),
        "SHRINCS should be accepted on mainnet: {:?}",
        result.err()
    );
}

// ============================================================================
// Algorithm activation unit tests
// ============================================================================

#[test]
fn test_is_algorithm_active_shrincs_all_networks() {
    // SHRINCS is active from genesis on all networks
    for network in [Network::Devnet, Network::Testnet, Network::Mainnet, Network::Regtest] {
        assert!(
            is_algorithm_active(SHRINCS_ALG_ID, 0, network),
            "SHRINCS should be active at height 0 on {:?}",
            network
        );
        assert!(
            is_algorithm_active(SHRINCS_ALG_ID, 1_000_000, network),
            "SHRINCS should be active at height 1M on {:?}",
            network
        );
    }
}

#[test]
fn test_regtest_same_as_devnet() {
    // Regtest should have same activation as devnet
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Regtest));
    assert!(is_algorithm_active(SHRINCS_ALG_ID, 100, Network::Regtest));
}

#[test]
fn test_unknown_algorithms_rejected() {
    // Unknown algorithm IDs should be rejected
    let unknown_algs = [0x00, 0x11, 0x21, 0xFF]; // 0x11 was ML-DSA-65, 0x21 is reserved
    for alg_id in unknown_algs {
        for network in [Network::Devnet, Network::Testnet, Network::Mainnet] {
            assert!(
                !is_algorithm_active(alg_id, 0, network),
                "Algorithm 0x{:02x} should be rejected on {:?}",
                alg_id,
                network
            );
        }
    }
}

// ============================================================================
// Mempool policy tests
// ============================================================================

#[test]
fn test_mempool_always_accepts_shrincs() {
    // SHRINCS is the genesis algorithm - mempool always accepts it
    for network in [Network::Devnet, Network::Testnet, Network::Mainnet, Network::Regtest] {
        assert!(
            should_accept_shrincs_to_mempool(0, network),
            "Mempool should accept SHRINCS at height 0 on {:?}",
            network
        );
        assert!(
            should_accept_shrincs_to_mempool(1_000_000, network),
            "Mempool should accept SHRINCS at height 1M on {:?}",
            network
        );
    }
}

// ============================================================================
// Cost accounting tests
// ============================================================================

#[test]
#[cfg_attr(miri, ignore)] // Miri cannot execute through pqcrypto C FFI boundary
fn test_pqsigcheck_costs() {
    let (shrincs_tx, shrincs_prevouts) = create_shrincs_tx();

    // SHRINCS: 2 PQSigCheck units (hash-based signatures are more expensive)
    let shrincs_cost =
        validate_transaction_basic(&shrincs_tx, &shrincs_prevouts, 0, Network::Devnet).unwrap();
    assert_eq!(shrincs_cost, 2, "SHRINCS should cost 2 PQSigCheck units");
}
