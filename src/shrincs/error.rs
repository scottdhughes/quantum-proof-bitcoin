//! SHRINCS error types.

use std::fmt;

/// Errors that can occur during SHRINCS operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShrincsError {
    /// State file is corrupted or unreadable.
    StateCorrupted(String),

    /// State file not found (first-time use or lost).
    StateNotFound,

    /// Attempted to use an already-used leaf index.
    LeafAlreadyUsed(u64),

    /// All stateful leaves have been exhausted.
    StateExhausted,

    /// Invalid signature format or length.
    InvalidSignature(String),

    /// Invalid public key format or length.
    InvalidPublicKey(String),

    /// Signature verification failed.
    VerificationFailed,

    /// Invalid parameter configuration.
    InvalidParams(String),

    /// Cryptographic operation failed.
    CryptoError(String),

    /// I/O error during state persistence.
    IoError(String),

    /// Reference implementation not available.
    NotImplemented(&'static str),
}

impl fmt::Display for ShrincsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StateCorrupted(msg) => write!(f, "state corrupted: {}", msg),
            Self::StateNotFound => write!(f, "state file not found"),
            Self::LeafAlreadyUsed(idx) => write!(f, "leaf {} already used", idx),
            Self::StateExhausted => write!(f, "all stateful leaves exhausted"),
            Self::InvalidSignature(msg) => write!(f, "invalid signature: {}", msg),
            Self::InvalidPublicKey(msg) => write!(f, "invalid public key: {}", msg),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::InvalidParams(msg) => write!(f, "invalid parameters: {}", msg),
            Self::CryptoError(msg) => write!(f, "cryptographic error: {}", msg),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::NotImplemented(feature) => {
                write!(f, "not implemented: {} (awaiting reference impl)", feature)
            }
        }
    }
}

impl std::error::Error for ShrincsError {}

impl From<std::io::Error> for ShrincsError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}
