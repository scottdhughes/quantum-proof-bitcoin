#![allow(clippy::module_inception)]
//! SHRINCS: Stateful Hash-based Resilient INtegrity-preserving Compact Signatures
//!
//! A hybrid post-quantum signature scheme combining:
//! - **Stateful path**: Unbalanced XMSS tree with WOTS+C one-time signatures
//! - **Stateless fallback**: SPHINCS+-128s for emergency recovery
//!
//! # Security Level
//!
//! This implementation targets **NIST Level 1 (128-bit)** post-quantum security
//! per the Delving Bitcoin SHRINCS spec:
//! - Hash output: 16 bytes (n = 16)
//! - Winternitz parameter: w = 256
//! - Chains: l = 16
//! - Public key: 16 bytes (composite hash commitment)
//!
//! # Signature Sizes
//!
//! Stateful signatures grow with usage:
//! - First signature (q=1): 308 bytes
//! - Second signature (q=2): 324 bytes (matches proposal title!)
//! - Formula: `292 + q × 16` bytes
//!
//! Fallback signatures: ~7,856 bytes (SPHINCS+-128s)
//!
//! # Reference
//!
//! See: <https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158>
//!
//! # Consensus
//!
//! SHRINCS (alg_id 0x30) is the sole post-quantum algorithm, active from genesis.

pub mod api;
pub mod error;
pub mod params;
pub mod pors;
pub mod shrincs;
pub mod sphincs_fallback;
pub mod state;
pub mod tree;
pub mod types;
pub mod wots;

// Re-exports for convenient access
pub use api::{ShrincsSign, ShrincsVerify};
pub use error::ShrincsError;
pub use params::{LEVEL1, ShrincsParams};
pub use state::{SigningState, StateManager};
pub use types::{ShrincsPublicKey, ShrincsSecretKey, ShrincsSignature};
