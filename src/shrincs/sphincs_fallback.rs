//! SPHINCS+ Fallback Implementation
//!
//! Provides stateless fallback signing when the stateful XMSS tree is exhausted
//! or state is corrupted/lost.
//!
//! Uses SPHINCS+-SHA2-128s-simple (NIST Level 1, ~7.8KB signatures)
//!
//! # Security
//!
//! SPHINCS+ is a stateless hash-based signature scheme standardized as
//! SLH-DSA in FIPS 205. The 128s variant provides:
//! - NIST Level 1 security (128-bit post-quantum)
//! - Small signatures (~7,856 bytes)
//! - Slower signing (acceptable for emergency fallback)

use crate::shrincs::error::ShrincsError;
use sha2::{Digest, Sha256};

// Conditional imports when feature is enabled
#[cfg(feature = "shrincs-dev")]
use pqcrypto_sphincsplus::sphincssha2128ssimple::{
    DetachedSignature, PublicKey, SecretKey, detached_sign, keypair, verify_detached_signature,
};

#[cfg(feature = "shrincs-dev")]
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};

/// SPHINCS+-128s public key size (32 bytes)
pub const SPHINCS_PK_BYTES: usize = 32;

/// SPHINCS+-128s secret key size (64 bytes)
pub const SPHINCS_SK_BYTES: usize = 64;

/// SPHINCS+-128s signature size (~7,856 bytes)
pub const SPHINCS_SIG_BYTES: usize = 7856;

/// Generate SPHINCS+ keypair for fallback signing.
///
/// # Returns
/// * `(pk, sk)` - Public key and secret key as byte vectors
#[cfg(feature = "shrincs-dev")]
pub fn sphincs_keygen() -> Result<(Vec<u8>, Vec<u8>), ShrincsError> {
    let (pk, sk) = keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Sign a message using SPHINCS+ (stateless fallback).
///
/// # Arguments
/// * `msg` - 32-byte message (typically a transaction hash)
/// * `sk_bytes` - Secret key bytes (64 bytes)
///
/// # Returns
/// * Detached signature (~7,856 bytes)
#[cfg(feature = "shrincs-dev")]
pub fn sphincs_sign(msg: &[u8; 32], sk_bytes: &[u8]) -> Result<Vec<u8>, ShrincsError> {
    if sk_bytes.len() != SPHINCS_SK_BYTES {
        return Err(ShrincsError::CryptoError(format!(
            "SPHINCS+ sk wrong size: {} vs expected {}",
            sk_bytes.len(),
            SPHINCS_SK_BYTES
        )));
    }

    let sk = SecretKey::from_bytes(sk_bytes)
        .map_err(|_| ShrincsError::CryptoError("Invalid SPHINCS+ secret key format".into()))?;

    let sig = detached_sign(msg, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify a SPHINCS+ signature.
///
/// # Arguments
/// * `msg` - Original 32-byte message
/// * `sig_bytes` - Signature bytes (~7,856 bytes)
/// * `pk_bytes` - Public key bytes (32 bytes)
///
/// # Returns
/// * `Ok(())` on valid signature
/// * `Err(VerificationFailed)` on invalid signature
#[cfg(feature = "shrincs-dev")]
pub fn sphincs_verify(
    msg: &[u8; 32],
    sig_bytes: &[u8],
    pk_bytes: &[u8],
) -> Result<(), ShrincsError> {
    if pk_bytes.len() != SPHINCS_PK_BYTES {
        return Err(ShrincsError::InvalidPublicKey(format!(
            "SPHINCS+ pk wrong size: {} vs expected {}",
            pk_bytes.len(),
            SPHINCS_PK_BYTES
        )));
    }

    let pk = PublicKey::from_bytes(pk_bytes)
        .map_err(|_| ShrincsError::InvalidPublicKey("Invalid SPHINCS+ public key format".into()))?;

    let sig = DetachedSignature::from_bytes(sig_bytes)
        .map_err(|_| ShrincsError::InvalidSignature("Invalid SPHINCS+ signature format".into()))?;

    verify_detached_signature(&sig, msg, &pk).map_err(|_| ShrincsError::VerificationFailed)
}

/// Compute SHA-256 hash of SPHINCS+ public key.
///
/// This hash is embedded in the 64-byte ShrincsPublicKey (bytes 32-64)
/// to allow verification that a provided SPHINCS+ pk matches the stored hash.
pub fn sphincs_pk_hash(pk_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SHRINCS_SPHINCS_PK");
    hasher.update(pk_bytes);
    hasher.finalize().into()
}

// ============================================================================
// Stub implementations when feature is disabled
// ============================================================================

#[cfg(not(feature = "shrincs-dev"))]
pub fn sphincs_keygen() -> Result<(Vec<u8>, Vec<u8>), ShrincsError> {
    Err(ShrincsError::NotImplemented(
        "sphincs_keygen requires shrincs-dev feature",
    ))
}

#[cfg(not(feature = "shrincs-dev"))]
pub fn sphincs_sign(_msg: &[u8; 32], _sk_bytes: &[u8]) -> Result<Vec<u8>, ShrincsError> {
    Err(ShrincsError::NotImplemented(
        "sphincs_sign requires shrincs-dev feature",
    ))
}

#[cfg(not(feature = "shrincs-dev"))]
pub fn sphincs_verify(
    _msg: &[u8; 32],
    _sig_bytes: &[u8],
    _pk_bytes: &[u8],
) -> Result<(), ShrincsError> {
    Err(ShrincsError::NotImplemented(
        "sphincs_verify requires shrincs-dev feature",
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_pk_hash_deterministic() {
        let pk = vec![0xABu8; 32];
        let hash1 = sphincs_pk_hash(&pk);
        let hash2 = sphincs_pk_hash(&pk);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sphincs_pk_hash_different_keys() {
        let pk1 = vec![0xABu8; 32];
        let pk2 = vec![0xCDu8; 32];
        let hash1 = sphincs_pk_hash(&pk1);
        let hash2 = sphincs_pk_hash(&pk2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sphincs_keygen() {
        let (pk, sk) = sphincs_keygen().expect("keygen should succeed");
        assert_eq!(pk.len(), SPHINCS_PK_BYTES);
        assert_eq!(sk.len(), SPHINCS_SK_BYTES);
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sphincs_sign_verify_roundtrip() {
        let (pk, sk) = sphincs_keygen().unwrap();
        let msg = [0xABu8; 32];

        let sig = sphincs_sign(&msg, &sk).expect("signing should succeed");
        assert_eq!(sig.len(), SPHINCS_SIG_BYTES);

        let result = sphincs_verify(&msg, &sig, &pk);
        assert!(result.is_ok(), "verification should succeed");
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sphincs_wrong_message_fails() {
        let (pk, sk) = sphincs_keygen().unwrap();
        let msg = [0xABu8; 32];
        let wrong_msg = [0xCDu8; 32];

        let sig = sphincs_sign(&msg, &sk).unwrap();

        let result = sphincs_verify(&wrong_msg, &sig, &pk);
        assert!(result.is_err(), "wrong message should fail verification");
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sphincs_wrong_key_fails() {
        let (pk1, sk1) = sphincs_keygen().unwrap();
        let (pk2, _sk2) = sphincs_keygen().unwrap();
        let msg = [0xABu8; 32];

        let sig = sphincs_sign(&msg, &sk1).unwrap();

        // Verify with wrong key should fail
        let result = sphincs_verify(&msg, &sig, &pk2);
        assert!(result.is_err(), "wrong key should fail verification");

        // Verify with correct key should succeed
        let result = sphincs_verify(&msg, &sig, &pk1);
        assert!(result.is_ok(), "correct key should succeed");
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sphincs_invalid_sk_size() {
        let msg = [0xABu8; 32];
        let bad_sk = vec![0u8; 32]; // Wrong size

        let result = sphincs_sign(&msg, &bad_sk);
        assert!(result.is_err(), "wrong sk size should fail");
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sphincs_invalid_pk_size() {
        let msg = [0xABu8; 32];
        let sig = vec![0u8; SPHINCS_SIG_BYTES];
        let bad_pk = vec![0u8; 16]; // Wrong size

        let result = sphincs_verify(&msg, &sig, &bad_pk);
        assert!(result.is_err(), "wrong pk size should fail");
    }
}
