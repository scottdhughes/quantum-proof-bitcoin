//! SHRINCS key and signature types.
//!
//! These types define the wire format for SHRINCS keys and signatures.
//! Actual cryptographic operations are pending reference implementation.

use crate::shrincs::params::ShrincsParams;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SHRINCS public key (64 bytes).
///
/// Structure:
/// - bytes[0..32]: XMSS root hash (stateful component)
/// - bytes[32..64]: SPHINCS+ public key hash (stateless fallback)
#[derive(Clone, PartialEq, Eq)]
pub struct ShrincsPublicKey {
    /// Raw public key bytes
    pub bytes: [u8; 64],
}

impl ShrincsPublicKey {
    /// Public key size in bytes.
    pub const SIZE: usize = 64;

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }

    /// Get the XMSS root hash (stateful component).
    pub fn xmss_root(&self) -> &[u8; 32] {
        self.bytes[0..32].try_into().unwrap()
    }

    /// Get the SPHINCS+ public key hash (stateless fallback).
    pub fn sphincs_pk_hash(&self) -> &[u8; 32] {
        self.bytes[32..64].try_into().unwrap()
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }
}

impl std::fmt::Debug for ShrincsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShrincsPublicKey({:?}...)", &self.bytes[..8])
    }
}

/// SHRINCS secret key.
///
/// Contains material for both stateful and stateless signing:
/// - XMSS secret seed for deriving WOTS+ keys
/// - SPHINCS+ secret key for fallback signing
/// - PRF key for randomness generation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ShrincsSecretKey {
    /// XMSS secret seed (32 bytes)
    pub xmss_seed: [u8; 32],
    /// XMSS public seed for address tweaking (32 bytes)
    pub xmss_pk_seed: [u8; 32],
    /// SPHINCS+ secret key (variable size, stored as Vec)
    pub sphincs_sk: Vec<u8>,
    /// PRF key for signature randomness (32 bytes)
    pub prf_key: [u8; 32],
}

impl std::fmt::Debug for ShrincsSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShrincsSecretKey([REDACTED])")
    }
}

/// Signature type indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignatureType {
    /// Stateful XMSS/WOTS+C signature (compact)
    Stateful = 0x00,
    /// Stateless SPHINCS+ fallback signature (larger)
    Fallback = 0x01,
}

impl SignatureType {
    /// Parse from flag byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Stateful),
            0x01 => Some(Self::Fallback),
            _ => None,
        }
    }
}

/// SHRINCS signature.
///
/// Wire format:
/// ```text
/// Stateful:  [0x00] [leaf_idx: 4B] [wots_sig: var] [auth_path: var]
/// Fallback:  [0x01] [reserved: 4B] [sphincs_sig: var]
/// ```
#[derive(Clone)]
pub struct ShrincsSignature {
    /// Signature type (stateful or fallback)
    pub sig_type: SignatureType,
    /// Leaf index for stateful signatures (0 for fallback)
    pub leaf_index: u32,
    /// Raw signature bytes (excluding type flag and index)
    pub sig_bytes: Vec<u8>,
}

impl ShrincsSignature {
    /// Create a stateful signature.
    pub fn stateful(leaf_index: u32, wots_sig: Vec<u8>, auth_path: Vec<u8>) -> Self {
        let mut sig_bytes = wots_sig;
        sig_bytes.extend_from_slice(&auth_path);
        Self {
            sig_type: SignatureType::Stateful,
            leaf_index,
            sig_bytes,
        }
    }

    /// Create a fallback signature.
    pub fn fallback(sphincs_sig: Vec<u8>) -> Self {
        Self {
            sig_type: SignatureType::Fallback,
            leaf_index: 0,
            sig_bytes: sphincs_sig,
        }
    }

    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.sig_bytes.len());
        out.push(self.sig_type as u8);
        out.extend_from_slice(&self.leaf_index.to_be_bytes());
        out.extend_from_slice(&self.sig_bytes);
        out
    }

    /// Parse from wire format.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 5 {
            return None;
        }
        let sig_type = SignatureType::from_byte(bytes[0])?;
        let leaf_index = u32::from_be_bytes(bytes[1..5].try_into().ok()?);
        let sig_bytes = bytes[5..].to_vec();
        Some(Self {
            sig_type,
            leaf_index,
            sig_bytes,
        })
    }

    /// Check if this is a stateful signature.
    pub fn is_stateful(&self) -> bool {
        self.sig_type == SignatureType::Stateful
    }

    /// Check if this is a fallback signature.
    pub fn is_fallback(&self) -> bool {
        self.sig_type == SignatureType::Fallback
    }

    /// Get total serialized size.
    pub fn serialized_size(&self) -> usize {
        5 + self.sig_bytes.len()
    }

    /// Estimate signature size for a given parameter set and leaf index.
    pub fn estimate_size(params: &ShrincsParams, leaf_index: u32) -> usize {
        // 1 byte type + 4 bytes index + signature
        5 + params.signature_size(leaf_index.saturating_add(1)) - params.auth_node_bytes
            + (leaf_index as usize + 1) * params.auth_node_bytes
    }
}

impl std::fmt::Debug for ShrincsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ShrincsSignature {{ type: {:?}, leaf: {}, size: {} }}",
            self.sig_type,
            self.leaf_index,
            self.serialized_size()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_structure() {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&[1u8; 32]);
        bytes[32..64].copy_from_slice(&[2u8; 32]);

        let pk = ShrincsPublicKey::from_bytes(bytes);
        assert_eq!(pk.xmss_root(), &[1u8; 32]);
        assert_eq!(pk.sphincs_pk_hash(), &[2u8; 32]);
    }

    #[test]
    fn signature_roundtrip() {
        let sig = ShrincsSignature::stateful(42, vec![1, 2, 3], vec![4, 5, 6]);
        let bytes = sig.to_bytes();
        let parsed = ShrincsSignature::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.sig_type, SignatureType::Stateful);
        assert_eq!(parsed.leaf_index, 42);
        assert_eq!(parsed.sig_bytes, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn fallback_signature() {
        let sig = ShrincsSignature::fallback(vec![0xAB; 100]);
        assert!(sig.is_fallback());
        assert!(!sig.is_stateful());
        assert_eq!(sig.leaf_index, 0);
    }
}
