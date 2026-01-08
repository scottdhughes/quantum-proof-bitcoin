//! Post-quantum signature verification.
//!
//! This module implements SHRINCS as the sole post-quantum signature scheme,
//! following the Delving Bitcoin specification:
//! https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158

use crate::activation::{Network, is_algorithm_active};
use crate::constants::SHRINCS_ALG_ID;
#[cfg(feature = "shrincs-dev")]
use crate::constants::SHRINCS_PUBKEY_LEN;
use crate::errors::ConsensusError;

#[cfg(feature = "shrincs-ffi")]
use libloading::Library;
#[cfg(feature = "shrincs-ffi")]
use once_cell::sync::OnceCell;
#[cfg(feature = "shrincs-ffi")]
use std::env;
#[cfg(feature = "shrincs-ffi")]
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmId {
    /// SHRINCS: Hybrid stateful/stateless hash-based signatures
    SHRINCS,
}

impl AlgorithmId {
    /// Parse algorithm ID from byte (no activation check).
    ///
    /// Use `from_byte_at_height` for consensus validation with activation checks.
    pub fn from_byte(b: u8) -> Result<Self, ConsensusError> {
        match b {
            SHRINCS_ALG_ID => Ok(AlgorithmId::SHRINCS),
            _ => Err(ConsensusError::InactiveAlgorithm),
        }
    }

    /// Parse algorithm ID with activation check.
    ///
    /// Returns an error if the algorithm is not active at the given height
    /// on the specified network. Use this for consensus validation.
    pub fn from_byte_at_height(
        b: u8,
        height: u32,
        network: Network,
    ) -> Result<Self, ConsensusError> {
        // First check if algorithm is active at this height
        if !is_algorithm_active(b, height, network) {
            return Err(ConsensusError::InactiveAlgorithm);
        }

        // Then parse as normal
        Self::from_byte(b)
    }

    pub fn as_byte(self) -> u8 {
        match self {
            AlgorithmId::SHRINCS => SHRINCS_ALG_ID,
        }
    }
}

/// PQSigCheck cost units per algorithm.
/// Hash-based signatures have higher verification cost.
pub fn pqsig_cost(alg: AlgorithmId) -> u32 {
    match alg {
        AlgorithmId::SHRINCS => 2,
    }
}

#[cfg(feature = "shrincs-ffi")]
#[allow(dead_code)]
struct ShrincsFfi {
    #[allow(dead_code)]
    lib: Library,
    verify: libloading::Symbol<
        'static,
        unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32,
    >,
    keygen: Option<libloading::Symbol<'static, unsafe extern "C" fn(*mut u8, usize) -> i32>>,
    sign: Option<
        libloading::Symbol<
            'static,
            unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> i32,
        >,
    >,
}

#[cfg(feature = "shrincs-ffi")]
#[allow(dead_code)]
static SHRINCS_FFI: OnceCell<Option<ShrincsFfi>> = OnceCell::new();

#[cfg(feature = "shrincs-ffi")]
#[allow(dead_code)]
fn load_shrincs() -> Option<&'static ShrincsFfi> {
    SHRINCS_FFI
        .get_or_init(|| {
            let path = env::var("SHRINCS_LIB_PATH").unwrap_or_else(|_| "libshrincs.so".to_string());
            if !Path::new(&path).exists() {
                return None;
            }
            unsafe {
                Library::new(&path).ok().and_then(|lib| {
                    let verify = lib
                        .get::<unsafe extern "C" fn(
                            *const u8,
                            usize,
                            *const u8,
                            usize,
                            *const u8,
                            usize,
                        ) -> i32>(b"shrincs_verify\0")
                        .ok()?;
                    let keygen = lib
                        .get::<unsafe extern "C" fn(*mut u8, usize) -> i32>(b"shrincs_keygen\0")
                        .ok();
                    let sign = lib
                        .get::<unsafe extern "C" fn(
                            *const u8,
                            usize,
                            *const u8,
                            usize,
                            *mut u8,
                            usize,
                        ) -> i32>(b"shrincs_sign\0")
                        .ok();
                    // transmute symbol lifetime to 'static, safe because lib lives in struct
                    let verify: libloading::Symbol<'static, _> = std::mem::transmute(verify);
                    let keygen: Option<libloading::Symbol<'static, _>> =
                        keygen.map(|s| std::mem::transmute(s));
                    let sign: Option<libloading::Symbol<'static, _>> =
                        sign.map(|s| std::mem::transmute(s));
                    Some(ShrincsFfi {
                        lib,
                        verify,
                        keygen,
                        sign,
                    })
                })
            }
        })
        .as_ref()
}

/// Verify a post-quantum signature.
///
/// Currently only supports SHRINCS (alg_id 0x30).
pub fn verify_pq(
    alg: AlgorithmId,
    pk: &[u8],
    msg32: &[u8],
    sig: &[u8],
) -> Result<(), ConsensusError> {
    match alg {
        AlgorithmId::SHRINCS => {
            #[cfg(feature = "shrincs-dev")]
            {
                verify_shrincs(pk, msg32, sig)
            }
            #[cfg(not(feature = "shrincs-dev"))]
            {
                let _ = (pk, msg32, sig);
                Err(ConsensusError::InactiveAlgorithm)
            }
        }
    }
}

/// Verify a SHRINCS signature (stateful or fallback).
///
/// # Signature Formats
///
/// **Stateful (0x00):** `[type(1) || full_pk(64) || sig_data]`
/// - full_pk: `[pk_seed(32) || pors_root(16) || hypertree_root(16)]`
/// - Verification checks that `H(full_pk)` matches the 16-byte on-chain commitment
///
/// **Fallback (0x01):** `[type(1) || reserved(4) || sphincs_sig]`
/// - pk must be 48 bytes: `[commitment(16) || sphincs_pk(32)]`
#[cfg(feature = "shrincs-dev")]
fn verify_shrincs(pk: &[u8], msg32: &[u8], sig: &[u8]) -> Result<(), ConsensusError> {
    use crate::constants::{SHRINCS_FALLBACK_PUBKEY_LEN, SPHINCS_PK_LEN};
    use crate::shrincs::shrincs::{ShrincsFullParams, ShrincsFullPublicKey, verify};
    use crate::shrincs::sphincs_fallback::sphincs_verify;

    if msg32.len() != 32 {
        return Err(ConsensusError::InvalidSignature);
    }
    if sig.is_empty() {
        return Err(ConsensusError::InvalidSignature);
    }

    let msg: [u8; 32] = msg32
        .try_into()
        .map_err(|_| ConsensusError::InvalidSignature)?;
    let params = ShrincsFullParams::LEVEL1_2_30;

    // Parse and verify based on signature type prefix
    match sig[0] {
        0x00 => {
            // Stateful signature
            // pk is 16-byte on-chain commitment
            // sig contains full_pk (64 bytes) + sig_data
            if pk.len() != SHRINCS_PUBKEY_LEN {
                return Err(ConsensusError::InvalidPublicKey);
            }

            // Signature must contain full_pk (64 bytes) after type prefix
            let full_pk_len = 32 + params.n * 2; // pk_seed(32) + roots(2n)
            if sig.len() < 1 + full_pk_len {
                return Err(ConsensusError::InvalidSignature);
            }

            // Extract full_pk from signature
            let full_pk_bytes = &sig[1..1 + full_pk_len];
            let full_pk = ShrincsFullPublicKey::from_bytes(full_pk_bytes, params)
                .ok_or(ConsensusError::InvalidPublicKey)?;

            // Verify the commitment matches the on-chain pk
            let commitment: [u8; 16] = pk
                .try_into()
                .map_err(|_| ConsensusError::InvalidPublicKey)?;
            if !full_pk.matches_commitment(&commitment) {
                return Err(ConsensusError::InvalidPublicKey);
            }

            // Parse signature data after full_pk
            let sig_data = &sig[1 + full_pk_len..];
            let full_sig =
                crate::shrincs::shrincs::ShrincsFullSignature::from_bytes(sig_data, params)
                    .ok_or(ConsensusError::InvalidSignature)?;

            verify(&msg, &full_sig, &full_pk).map_err(|_| ConsensusError::PQSignatureInvalid)
        }
        0x01 => {
            // Fallback signature - pk must be extended (16 + 32 = 48 bytes)
            // Extended pk format: [composite_hash(16) || sphincs_pk(32)]
            if pk.len() != SHRINCS_FALLBACK_PUBKEY_LEN {
                return Err(ConsensusError::InvalidPublicKey);
            }

            // Extract SPHINCS+ pk from extended pk (last 32 bytes)
            let sphincs_pk = &pk[SHRINCS_PUBKEY_LEN..SHRINCS_PUBKEY_LEN + SPHINCS_PK_LEN];

            // Parse SPHINCS+ signature (skip type prefix and reserved bytes)
            // Fallback sig format: [type(1) || reserved(4) || sphincs_sig]
            if sig.len() < 5 {
                return Err(ConsensusError::InvalidSignature);
            }
            let sphincs_sig = &sig[5..];

            // Verify with SPHINCS+
            sphincs_verify(&msg, sphincs_sig, sphincs_pk)
                .map_err(|_| ConsensusError::PQSignatureInvalid)
        }
        _ => Err(ConsensusError::InvalidSignature),
    }
}

/// SHRINCS keypair generation (returns serialized pk with algorithm prefix).
///
/// Returns:
/// - `pk_ser`: Algorithm-prefixed public key commitment (1 + 16 bytes)
/// - `key_material`: Stateful key material for signing (includes full pk)
/// - `state`: Signing state (must be persisted to prevent key reuse)
///
/// The on-chain public key is a 16-byte commitment: H(full_pk).
/// The full pk (64 bytes) is included in signatures for verification.
#[cfg(feature = "shrincs-dev")]
pub fn shrincs_keypair() -> Result<
    (
        Vec<u8>,
        crate::shrincs::shrincs::ShrincsKeyMaterial,
        crate::shrincs::state::SigningState,
    ),
    ConsensusError,
> {
    use crate::shrincs::shrincs::{ShrincsFullParams, keygen};

    let params = ShrincsFullParams::LEVEL1_2_30;
    let (key_material, state) = keygen(params).map_err(|_| ConsensusError::InvalidSignature)?;

    // Serialize 16-byte pk commitment with algorithm prefix
    let commitment = key_material.pk.to_commitment();
    let mut pk_ser = Vec::with_capacity(1 + SHRINCS_PUBKEY_LEN);
    pk_ser.push(SHRINCS_ALG_ID);
    pk_ser.extend_from_slice(&commitment);

    Ok((pk_ser, key_material, state))
}

/// SHRINCS signing (prepends type byte, includes full pk, appends sighash type byte).
///
/// # Arguments
/// - `key_material`: Key material from `shrincs_keypair()`
/// - `state`: Mutable signing state (updated on each signature)
/// - `msg32`: 32-byte message to sign
/// - `sighash_type`: Sighash type byte to append
///
/// # Returns
/// Serialized signature: `[type(1) || full_pk(64) || sig_data || sighash(1)]`
/// - type = 0x00 for stateful signatures
/// - full_pk = `[pk_seed(32) || pors_root(16) || hypertree_root(16)]`
#[cfg(feature = "shrincs-dev")]
pub fn shrincs_sign(
    key_material: &crate::shrincs::shrincs::ShrincsKeyMaterial,
    state: &mut crate::shrincs::state::SigningState,
    msg32: &[u8],
    sighash_type: u8,
) -> Result<Vec<u8>, ConsensusError> {
    use crate::shrincs::shrincs::sign;

    let msg: [u8; 32] = msg32
        .try_into()
        .map_err(|_| ConsensusError::InvalidSignature)?;

    let sig = sign(&msg, key_material, state).map_err(|_| ConsensusError::InvalidSignature)?;

    let sig_bytes = sig.to_bytes();
    let pk_bytes = key_material.pk.to_bytes();

    // Format: type_prefix(1) || full_pk(64) || sig_data || sighash(1)
    let mut sig_ser = Vec::with_capacity(1 + pk_bytes.len() + sig_bytes.len() + 1);
    sig_ser.push(0x00); // Stateful signature type prefix
    sig_ser.extend_from_slice(&pk_bytes); // Full pk for verification
    sig_ser.extend_from_slice(&sig_bytes);
    sig_ser.push(sighash_type);

    Ok(sig_ser)
}

/// SHRINCS keypair generation with SPHINCS+ fallback keys.
///
/// Returns:
/// - `pk_ser`: Algorithm-prefixed 16-byte commitment (1 + 16 bytes)
/// - `sphincs_pk`: Full SPHINCS+ public key (32 bytes) for witness extension
/// - `ext_key`: Extended key material (stateful + SPHINCS+ fallback)
/// - `state`: Signing state (must be persisted to prevent key reuse)
///
/// For fallback signatures, the witness pk must be 48 bytes: `[commitment(16) || sphincs_pk(32)]`
#[cfg(feature = "shrincs-dev")]
pub fn shrincs_keypair_with_fallback() -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        crate::shrincs::shrincs::ShrincsExtendedKeyMaterial,
        crate::shrincs::state::SigningState,
    ),
    ConsensusError,
> {
    use crate::shrincs::shrincs::{ShrincsFullParams, keygen_with_fallback};

    let params = ShrincsFullParams::LEVEL1_2_30;
    let (ext_key, state, _ext_pk) =
        keygen_with_fallback(params).map_err(|_| ConsensusError::InvalidSignature)?;

    // Serialize 16-byte pk commitment with algorithm prefix
    let commitment = ext_key.base.pk.to_commitment();
    let mut pk_ser = Vec::with_capacity(1 + SHRINCS_PUBKEY_LEN);
    pk_ser.push(SHRINCS_ALG_ID);
    pk_ser.extend_from_slice(&commitment);

    // Return the full SPHINCS+ pk separately (needed for extended witness)
    let sphincs_pk = ext_key.sphincs_pk.clone();

    Ok((pk_ser, sphincs_pk, ext_key, state))
}

/// SHRINCS fallback signing (uses SPHINCS+ stateless mode).
///
/// # Arguments
/// - `ext_key`: Extended key material from `shrincs_keypair_with_fallback()`
/// - `msg32`: 32-byte message to sign
/// - `sighash_type`: Sighash type byte to append
///
/// # Returns
/// Serialized signature: [type_prefix(1) || reserved(4) || sphincs_sig || sighash(1)]
/// where type_prefix is 0x01 for fallback signatures
#[cfg(feature = "shrincs-dev")]
pub fn shrincs_sign_fallback(
    ext_key: &crate::shrincs::shrincs::ShrincsExtendedKeyMaterial,
    msg32: &[u8],
    sighash_type: u8,
) -> Result<Vec<u8>, ConsensusError> {
    use crate::shrincs::sphincs_fallback::sphincs_sign;

    let msg: [u8; 32] = msg32
        .try_into()
        .map_err(|_| ConsensusError::InvalidSignature)?;

    let sphincs_sig =
        sphincs_sign(&msg, &ext_key.sphincs_sk).map_err(|_| ConsensusError::InvalidSignature)?;

    // Format: type_prefix(1) || reserved(4) || sphincs_sig || sighash(1)
    let mut sig_ser = Vec::with_capacity(1 + 4 + sphincs_sig.len() + 1);
    sig_ser.push(0x01); // Fallback signature type prefix
    sig_ser.extend_from_slice(&[0u8; 4]); // Reserved bytes
    sig_ser.extend_from_slice(&sphincs_sig);
    sig_ser.push(sighash_type);

    Ok(sig_ser)
}
