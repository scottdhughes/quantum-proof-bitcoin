//! SHRINCS: Stateful Hash-based Resilient INtegrity-preserving Compact Signatures
//!
//! A hybrid post-quantum signature scheme combining:
//! - **Stateful path**: Unbalanced XMSS tree with WOTS+C one-time signatures
//! - **Stateless fallback**: SPHINCS+ variant for emergency recovery
//!
//! # Security Level
//!
//! This implementation targets **NIST Level 3 (192-bit)** post-quantum security:
//! - Hash output: 24 bytes (n = 24)
//! - Winternitz parameter: w = 256
//! - Chains: l = 24
//!
//! # Signature Sizes
//!
//! Stateful signatures grow with usage:
//! - First signature (q=1): 636 bytes
//! - Tenth signature (q=10): 852 bytes
//! - Formula: `612 + q × 24` bytes
//!
//! # Status
//!
//! **PENDING REFERENCE IMPLEMENTATION**
//!
//! This module defines the API and types for SHRINCS integration.
//! Actual cryptographic operations await Jonas Nick's reference implementation.
//! See: <https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158>
//!
//! # Consensus
//!
//! SHRINCS (alg_id 0x30) is **reserved but inactive** at genesis.
//! Activation requires a coordinated hard fork after security audit.

pub mod api;
pub mod error;
pub mod params;
pub mod state;
pub mod types;

// Re-exports for convenient access
pub use api::{ShrincsSign, ShrincsVerify};
pub use error::ShrincsError;
pub use params::{ShrincsParams, LEVEL3};
pub use state::{SigningState, StateManager};
pub use types::{ShrincsPublicKey, ShrincsSecretKey, ShrincsSignature};
