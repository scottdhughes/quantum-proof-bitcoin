//! SHRINCS API trait definitions.
//!
//! These traits define the interface that reference implementations will fill.
//! Current implementations return `NotImplemented` errors.

use crate::shrincs::error::ShrincsError;
use crate::shrincs::params::ShrincsParams;
use crate::shrincs::state::SigningState;
use crate::shrincs::types::{ShrincsPublicKey, ShrincsSecretKey, ShrincsSignature};

/// Trait for SHRINCS signing operations.
pub trait ShrincsSign {
    /// Generate a new SHRINCS keypair.
    ///
    /// # Arguments
    /// * `params` - Parameter set (Level 1 or Level 3)
    ///
    /// # Returns
    /// * Secret key, public key, and initial signing state
    fn keygen(
        params: &ShrincsParams,
    ) -> Result<(ShrincsSecretKey, ShrincsPublicKey, SigningState), ShrincsError>;

    /// Sign a message using the stateful path.
    ///
    /// # Arguments
    /// * `msg` - 32-byte message hash to sign
    /// * `sk` - Secret key
    /// * `state` - Mutable signing state (will be updated)
    /// * `params` - Parameter set
    ///
    /// # Returns
    /// * Signature on success
    /// * `ShrincsError::StateExhausted` if no leaves remain (use `sign_fallback`)
    fn sign(
        msg: &[u8; 32],
        sk: &ShrincsSecretKey,
        state: &mut SigningState,
        params: &ShrincsParams,
    ) -> Result<ShrincsSignature, ShrincsError>;

    /// Sign a message using the stateless fallback (SPHINCS+).
    ///
    /// Use this when:
    /// - State is lost/corrupted
    /// - All stateful leaves are exhausted
    /// - Explicitly requested for compatibility
    ///
    /// # Arguments
    /// * `msg` - 32-byte message hash to sign
    /// * `sk` - Secret key
    /// * `params` - Parameter set
    ///
    /// # Returns
    /// * Fallback signature (larger than stateful)
    fn sign_fallback(
        msg: &[u8; 32],
        sk: &ShrincsSecretKey,
        params: &ShrincsParams,
    ) -> Result<ShrincsSignature, ShrincsError>;
}

/// Trait for SHRINCS verification operations.
pub trait ShrincsVerify {
    /// Verify a SHRINCS signature.
    ///
    /// Handles both stateful and fallback signature types automatically.
    ///
    /// # Arguments
    /// * `msg` - 32-byte message hash that was signed
    /// * `sig` - Signature to verify
    /// * `pk` - Public key
    /// * `params` - Parameter set
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(ShrincsError::VerificationFailed)` if invalid
    fn verify(
        msg: &[u8; 32],
        sig: &ShrincsSignature,
        pk: &ShrincsPublicKey,
        params: &ShrincsParams,
    ) -> Result<(), ShrincsError>;
}

/// Placeholder implementation (returns NotImplemented).
///
/// This will be replaced when reference implementation is available.
pub struct ShrincsPlaceholder;

impl ShrincsSign for ShrincsPlaceholder {
    fn keygen(
        _params: &ShrincsParams,
    ) -> Result<(ShrincsSecretKey, ShrincsPublicKey, SigningState), ShrincsError> {
        Err(ShrincsError::NotImplemented("keygen"))
    }

    fn sign(
        _msg: &[u8; 32],
        _sk: &ShrincsSecretKey,
        _state: &mut SigningState,
        _params: &ShrincsParams,
    ) -> Result<ShrincsSignature, ShrincsError> {
        Err(ShrincsError::NotImplemented("sign"))
    }

    fn sign_fallback(
        _msg: &[u8; 32],
        _sk: &ShrincsSecretKey,
        _params: &ShrincsParams,
    ) -> Result<ShrincsSignature, ShrincsError> {
        Err(ShrincsError::NotImplemented("sign_fallback"))
    }
}

impl ShrincsVerify for ShrincsPlaceholder {
    fn verify(
        _msg: &[u8; 32],
        _sig: &ShrincsSignature,
        _pk: &ShrincsPublicKey,
        _params: &ShrincsParams,
    ) -> Result<(), ShrincsError> {
        Err(ShrincsError::NotImplemented("verify"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shrincs::params::LEVEL1;

    #[test]
    fn placeholder_returns_not_implemented() {
        let result = ShrincsPlaceholder::keygen(&LEVEL1);
        assert!(matches!(result, Err(ShrincsError::NotImplemented(_))));
    }
}
