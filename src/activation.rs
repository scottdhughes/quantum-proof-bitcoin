//! Hard fork activation parameters for signature algorithms.
//!
//! This module defines block heights at which signature algorithms become
//! consensus-valid on each network. Before activation, transactions using
//! inactive algorithms are rejected at the consensus layer.
//!
//! # Design
//!
//! SHRINCS is the sole post-quantum signature algorithm, active from genesis.
//! Per the Delving Bitcoin specification:
//! https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158
//!
//! # SHRINCS Fallback
//!
//! SHRINCS has a SPHINCS+ stateless fallback that is always valid. This allows
//! emergency recovery when stateful signing state is corrupted or lost.

use crate::constants::{SHRINCS_ALG_ID, SLH_DSA_ALG_ID};

/// Activation heights for signature algorithms on a specific network.
#[derive(Debug, Clone, Copy)]
pub struct ActivationHeights {
    /// SLH-DSA (0x21) activation height (None = never active, reserved for future)
    pub slh_dsa: Option<u32>,
}

impl ActivationHeights {
    /// Devnet: SHRINCS active from genesis.
    pub const DEVNET: Self = Self { slh_dsa: None };

    /// Testnet: SHRINCS active from genesis.
    pub const TESTNET: Self = Self { slh_dsa: None };

    /// Mainnet: SHRINCS active from genesis.
    pub const MAINNET: Self = Self { slh_dsa: None };
}

/// Network type for activation checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Production network
    Mainnet,
    /// Public test network
    Testnet,
    /// Local development network
    Devnet,
    /// Regression test network (same as devnet)
    Regtest,
}

impl Network {
    /// Parse network name from string.
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mainnet" | "main" => Self::Mainnet,
            "testnet" | "test" => Self::Testnet,
            "devnet" | "dev" => Self::Devnet,
            "regtest" | "local" => Self::Regtest,
            _ => Self::Mainnet, // Default to most restrictive
        }
    }

    /// Get activation heights for this network.
    pub fn activation_heights(&self) -> ActivationHeights {
        match self {
            Self::Devnet | Self::Regtest => ActivationHeights::DEVNET,
            Self::Testnet => ActivationHeights::TESTNET,
            Self::Mainnet => ActivationHeights::MAINNET,
        }
    }
}

/// Check if an algorithm is active at a given block height.
///
/// # Arguments
/// - `alg_id`: Algorithm identifier byte (0x30 for SHRINCS)
/// - `height`: Block height at which to check activation
/// - `network`: Network type
///
/// # Returns
/// `true` if the algorithm is valid for use at this height, `false` otherwise.
pub fn is_algorithm_active(alg_id: u8, height: u32, network: Network) -> bool {
    let heights = network.activation_heights();

    match alg_id {
        // SHRINCS is always active (genesis algorithm)
        SHRINCS_ALG_ID => true,

        // SLH-DSA requires activation check (reserved for future)
        SLH_DSA_ALG_ID => heights.slh_dsa.is_some_and(|h| height >= h),

        // Unknown algorithms are never active
        _ => false,
    }
}

/// Check if SPHINCS+ fallback signatures are valid.
///
/// By design decision, SPHINCS+ fallback signatures (signature type 0x01) are
/// always valid. This provides emergency recovery capability for wallets that
/// have lost their stateful signing state.
///
/// Note: This function always returns true per the design decision.
#[inline]
pub const fn is_fallback_valid(_height: u32, _network: Network) -> bool {
    true
}

/// Mempool policy: SHRINCS is always accepted (genesis algorithm).
///
/// Unlike soft-fork activations, SHRINCS doesn't need a pre-activation window
/// since it's valid from block 0.
pub fn should_accept_shrincs_to_mempool(_current_height: u32, _network: Network) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrincs_always_active() {
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Mainnet));
        assert!(is_algorithm_active(
            SHRINCS_ALG_ID,
            1_000_000,
            Network::Mainnet
        ));
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Testnet));
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Devnet));
    }

    #[test]
    fn fallback_always_valid() {
        assert!(is_fallback_valid(0, Network::Mainnet));
        assert!(is_fallback_valid(0, Network::Testnet));
        assert!(is_fallback_valid(1_000_000, Network::Mainnet));
    }

    #[test]
    fn unknown_algorithm_inactive() {
        assert!(!is_algorithm_active(0xFF, 0, Network::Devnet));
        assert!(!is_algorithm_active(0x00, 100, Network::Mainnet));
        assert!(!is_algorithm_active(0x11, 0, Network::Mainnet)); // Old ML-DSA-65 ID
    }

    #[test]
    fn network_parse() {
        assert_eq!(Network::parse("mainnet"), Network::Mainnet);
        assert_eq!(Network::parse("TESTNET"), Network::Testnet);
        assert_eq!(Network::parse("devnet"), Network::Devnet);
        assert_eq!(Network::parse("regtest"), Network::Regtest);
        assert_eq!(Network::parse("unknown"), Network::Mainnet); // Default
    }

    #[test]
    fn mempool_always_accepts_shrincs() {
        assert!(should_accept_shrincs_to_mempool(0, Network::Devnet));
        assert!(should_accept_shrincs_to_mempool(100, Network::Devnet));
        assert!(should_accept_shrincs_to_mempool(0, Network::Mainnet));
        assert!(should_accept_shrincs_to_mempool(
            1_000_000,
            Network::Mainnet
        ));
    }
}
