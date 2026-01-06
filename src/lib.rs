//! QPB consensus scaffolding library.
//!
//! Implements the core data types, serialization, hashing, sighash,
//! PQ signature stubs, and block weight/penalty logic for the
//! Quantum Proof Bitcoin (QPB) specification (v1.1 genesis draft).

pub mod activation;
pub mod address;
pub mod constants;
pub mod errors;
pub mod hashing;
pub mod mining;
pub mod node;
pub mod pow;
pub mod pq;
pub mod reward;
pub mod script;
pub mod shrincs;
pub mod shrincs_proto;
pub mod sighash;
pub mod types;
pub mod validation;
pub mod varint;
pub mod weight;

// Re-exports for convenient crate users.
pub use constants::*;
pub use errors::*;
pub use hashing::*;
pub use mining::*;
pub use pow::*;
pub use pq::*;
pub use reward::*;
pub use script::*;
pub use sighash::*;
pub use types::*;
pub use validation::*;
pub use varint::*;
pub use weight::*;
