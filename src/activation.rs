//! Hard fork activation parameters for signature algorithms.
//!
//! This module defines block heights at which signature algorithms become
//! consensus-valid on each network. Before activation, transactions using
//! inactive algorithms are rejected at the consensus layer.
//!
//! # Design
//!
//! - **Devnet/Regtest:** Immediate activation (height 0) for development
//! - **Testnet:** Immediate activation for testing
//! - **Mainnet:** Pending external audit (currently disabled)
//!
//! # SHRINCS Special Case
//!
//! SHRINCS has a SPHINCS+ stateless fallback that is always valid. This allows
//! emergency recovery even before SHRINCS activation, since the fallback uses
//! a different algorithm ID embedded in the signature prefix.

#[cfg(feature = "shrincs-dev")]
use crate::constants::SHRINCS_ALG_ID;
use crate::constants::{MLDSA65_ALG_ID, SLH_DSA_ALG_ID};

/// Activation heights for signature algorithms on a specific network.
#[derive(Debug, Clone, Copy)]
pub struct ActivationHeights {
    /// SHRINCS (0x30) activation height (None = never active)
    pub shrincs: Option<u32>,
    /// SLH-DSA (0x21) activation height (None = never active)
    pub slh_dsa: Option<u32>,
}

impl ActivationHeights {
    /// Devnet: immediate activation for development.
    pub const DEVNET: Self = Self {
        shrincs: Some(0), // Active from genesis
        slh_dsa: None,
    };

    /// Testnet: immediate activation for testing.
    pub const TESTNET: Self = Self {
        shrincs: Some(0), // Active from genesis (per design decision)
        slh_dsa: None,
    };

    /// Mainnet: TBD after external audit.
    pub const MAINNET: Self = Self {
        shrincs: None, // Not yet scheduled - requires audit
        slh_dsa: None,
    };
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
/// - `alg_id`: Algorithm identifier byte (e.g., 0x11 for ML-DSA-65, 0x30 for SHRINCS)
/// - `height`: Block height at which to check activation
/// - `network`: Network type
///
/// # Returns
/// `true` if the algorithm is valid for use at this height, `false` otherwise.
pub fn is_algorithm_active(alg_id: u8, height: u32, network: Network) -> bool {
    let heights = network.activation_heights();

    match alg_id {
        // ML-DSA-65 is always active (genesis algorithm)
        MLDSA65_ALG_ID => true,

        // SHRINCS requires activation check
        #[cfg(feature = "shrincs-dev")]
        SHRINCS_ALG_ID => heights.shrincs.is_some_and(|h| height >= h),

        // SLH-DSA requires activation check
        SLH_DSA_ALG_ID => heights.slh_dsa.is_some_and(|h| height >= h),

        // Unknown algorithms are never active
        _ => false,
    }
}

/// Check if SPHINCS+ fallback signatures are valid.
///
/// By design decision, SPHINCS+ fallback signatures (signature type 0x01) are
/// always valid, even before SHRINCS activation. This provides emergency
/// recovery capability for wallets that have exhausted their stateful key pool
/// before activation.
///
/// Note: This function always returns true per the design decision.
#[inline]
pub const fn is_fallback_valid(_height: u32, _network: Network) -> bool {
    true
}

/// Mempool policy: blocks before activation at which to start accepting txs.
///
/// Transactions spending SHRINCS outputs are only accepted into the mempool
/// when the current tip is within this many blocks of the activation height.
/// This prevents premature mempool flooding while allowing tx propagation
/// before activation.
pub const MEMPOOL_PRE_ACTIVATION_BLOCKS: u32 = 100;

/// Check if SHRINCS-spending transactions should be accepted to mempool.
///
/// Policy is more restrictive than consensus: we reject until close to activation
/// to prevent mempool from filling with currently-invalid transactions.
pub fn should_accept_shrincs_to_mempool(current_height: u32, network: Network) -> bool {
    let heights = network.activation_heights();

    match heights.shrincs {
        Some(0) => true, // Already active from genesis
        Some(activation) => {
            // Accept if within pre-activation window
            current_height + MEMPOOL_PRE_ACTIVATION_BLOCKS >= activation
        }
        None => false, // Never active on this network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mldsa65_always_active() {
        assert!(is_algorithm_active(MLDSA65_ALG_ID, 0, Network::Mainnet));
        assert!(is_algorithm_active(
            MLDSA65_ALG_ID,
            1_000_000,
            Network::Mainnet
        ));
        assert!(is_algorithm_active(MLDSA65_ALG_ID, 0, Network::Testnet));
        assert!(is_algorithm_active(MLDSA65_ALG_ID, 0, Network::Devnet));
    }

    #[cfg(feature = "shrincs-dev")]
    #[test]
    fn shrincs_devnet_immediate() {
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Devnet));
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 100, Network::Devnet));
    }

    #[cfg(feature = "shrincs-dev")]
    #[test]
    fn shrincs_testnet_immediate() {
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Testnet));
        assert!(is_algorithm_active(SHRINCS_ALG_ID, 100, Network::Testnet));
    }

    #[cfg(feature = "shrincs-dev")]
    #[test]
    fn shrincs_mainnet_inactive() {
        // Mainnet has no SHRINCS activation height yet
        assert!(!is_algorithm_active(SHRINCS_ALG_ID, 0, Network::Mainnet));
        assert!(!is_algorithm_active(
            SHRINCS_ALG_ID,
            1_000_000,
            Network::Mainnet
        ));
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
    }

    #[test]
    fn network_parse() {
        assert_eq!(Network::parse("mainnet"), Network::Mainnet);
        assert_eq!(Network::parse("TESTNET"), Network::Testnet);
        assert_eq!(Network::parse("devnet"), Network::Devnet);
        assert_eq!(Network::parse("regtest"), Network::Regtest);
        assert_eq!(Network::parse("unknown"), Network::Mainnet); // Default
    }

    #[cfg(feature = "shrincs-dev")]
    #[test]
    fn mempool_policy_devnet() {
        // Devnet has immediate activation (height 0)
        assert!(should_accept_shrincs_to_mempool(0, Network::Devnet));
        assert!(should_accept_shrincs_to_mempool(100, Network::Devnet));
    }

    #[cfg(feature = "shrincs-dev")]
    #[test]
    fn mempool_policy_mainnet() {
        // Mainnet has no activation - never accept
        assert!(!should_accept_shrincs_to_mempool(0, Network::Mainnet));
        assert!(!should_accept_shrincs_to_mempool(
            1_000_000,
            Network::Mainnet
        ));
    }
}
