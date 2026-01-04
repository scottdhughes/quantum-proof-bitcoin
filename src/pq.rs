use crate::constants::{MLDSA65_ALG_ID, MLDSA65_PUBKEY_LEN, MLDSA65_SIG_LEN};
#[cfg(feature = "shrincs-dev")]
use crate::constants::{SHRINCS_ALG_ID, SHRINCS_PUBKEY_LEN};
use crate::errors::ConsensusError;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

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
    MLDSA65,
    #[cfg(feature = "shrincs-dev")]
    SHRINCS,
}

impl AlgorithmId {
    pub fn from_byte(b: u8) -> Result<Self, ConsensusError> {
        match b {
            MLDSA65_ALG_ID => Ok(AlgorithmId::MLDSA65),
            #[cfg(feature = "shrincs-dev")]
            SHRINCS_ALG_ID => Ok(AlgorithmId::SHRINCS),
            _ => Err(ConsensusError::InactiveAlgorithm),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            AlgorithmId::MLDSA65 => MLDSA65_ALG_ID,
            #[cfg(feature = "shrincs-dev")]
            AlgorithmId::SHRINCS => SHRINCS_ALG_ID,
        }
    }
}

/// PQSigCheck cost units per algorithm (genesis).
/// Hash-based signatures are more expensive to verify than lattice-based.
pub fn pqsig_cost(alg: AlgorithmId) -> u32 {
    match alg {
        AlgorithmId::MLDSA65 => 1,
        #[cfg(feature = "shrincs-dev")]
        AlgorithmId::SHRINCS => 2, // ~2x slower than ML-DSA-65
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
static SHRINCS_FFI: OnceCell<Option<ShrincsFfi>> = OnceCell::new();

#[cfg(feature = "shrincs-ffi")]
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

pub fn verify_pq(
    alg: AlgorithmId,
    pk: &[u8],
    msg32: &[u8],
    sig: &[u8],
) -> Result<(), ConsensusError> {
    match alg {
        AlgorithmId::MLDSA65 => {
            if msg32.len() != 32 {
                return Err(ConsensusError::InvalidSignature);
            }
            if pk.len() != MLDSA65_PUBKEY_LEN || sig.len() != MLDSA65_SIG_LEN {
                return Err(ConsensusError::InvalidSignature);
            }
            let pk_obj = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(pk)
                .map_err(|_| ConsensusError::InvalidPublicKey)?;
            let sig_obj = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(sig)
                .map_err(|_| ConsensusError::InvalidSignature)?;
            pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig_obj, msg32, &pk_obj)
                .map_err(|_| ConsensusError::PQSignatureInvalid)
        }
        #[cfg(feature = "shrincs-dev")]
        AlgorithmId::SHRINCS => verify_shrincs(pk, msg32, sig),
    }?;

    #[allow(unreachable_code)]
    Ok(())
}

/// Verify a SHRINCS signature (stateful or fallback).
#[cfg(feature = "shrincs-dev")]
fn verify_shrincs(pk: &[u8], msg32: &[u8], sig: &[u8]) -> Result<(), ConsensusError> {
    use crate::shrincs::shrincs::{verify, ShrincsFullParams, ShrincsFullPublicKey};
    use crate::shrincs::shrincs::ShrincsUnifiedSignature;

    if msg32.len() != 32 {
        return Err(ConsensusError::InvalidSignature);
    }
    if pk.len() != SHRINCS_PUBKEY_LEN {
        return Err(ConsensusError::InvalidPublicKey);
    }
    if sig.is_empty() {
        return Err(ConsensusError::InvalidSignature);
    }

    let msg: [u8; 32] = msg32.try_into().map_err(|_| ConsensusError::InvalidSignature)?;
    let params = ShrincsFullParams::LEVEL1_2_30;

    // Parse public key
    let full_pk = ShrincsFullPublicKey::from_bytes(pk, params)
        .ok_or(ConsensusError::InvalidPublicKey)?;

    // Parse and verify based on signature type prefix
    match sig[0] {
        0x00 => {
            // Stateful signature - parse from bytes after type prefix
            let sig_data = &sig[1..]; // Skip type prefix byte
            let full_sig = crate::shrincs::shrincs::ShrincsFullSignature::from_bytes(sig_data, params)
                .ok_or(ConsensusError::InvalidSignature)?;
            verify(&msg, &full_sig, &full_pk)
                .map_err(|_| ConsensusError::PQSignatureInvalid)
        }
        0x01 => {
            // Fallback signature - need extended pk with SPHINCS+ key
            // For consensus, we need the SPHINCS+ pk provided separately
            // Currently: verify against pk hash stored in ShrincsFullPublicKey
            let _unified_sig = ShrincsUnifiedSignature::from_bytes(sig, params)
                .ok_or(ConsensusError::InvalidSignature)?;

            // Extract SPHINCS+ pk hash from unified pk (bytes 32-64)
            if pk.len() < 64 {
                return Err(ConsensusError::InvalidPublicKey);
            }

            // For fallback, caller must provide full SPHINCS+ pk in witness
            // This is a simplified path - full implementation would parse witness
            Err(ConsensusError::InvalidSignature) // TBD: fallback witness format
        }
        _ => Err(ConsensusError::InvalidSignature),
    }
}

/// Dev-only SHRINCS verifier (wraps verify_shrincs for backward compatibility).
#[cfg(feature = "shrincs-dev")]
#[deprecated(note = "Use verify_pq(AlgorithmId::SHRINCS, ...) instead")]
pub fn verify_shrincs_dev(pk: &[u8], msg32: &[u8], sig: &[u8]) -> Result<(), ConsensusError> {
    verify_shrincs(pk, msg32, sig)
}

/// ML-DSA keypair helper for dev/CLI.
pub fn mldsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// ML-DSA sign helper (deterministic).
pub fn mldsa_sign(sk: &[u8], msg32: &[u8]) -> Result<Vec<u8>, ConsensusError> {
    if msg32.len() != 32 {
        return Err(ConsensusError::InvalidSignature);
    }
    if sk.len() != pqcrypto_dilithium::dilithium3::secret_key_bytes() {
        return Err(ConsensusError::InvalidSignature);
    }
    let sk_obj = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(sk)
        .map_err(|_| ConsensusError::InvalidSignature)?;
    let sig = pqcrypto_dilithium::dilithium3::detached_sign(msg32, &sk_obj);
    Ok(sig.as_bytes().to_vec())
}

/// SHRINCS keypair generation (returns serialized pk with algorithm prefix).
///
/// Returns:
/// - `pk_ser`: Algorithm-prefixed public key (1 + 64 bytes)
/// - `key_material`: Stateful key material for signing
/// - `state`: Signing state (must be persisted to prevent key reuse)
#[cfg(feature = "shrincs-dev")]
pub fn shrincs_keypair() -> Result<
    (Vec<u8>, crate::shrincs::shrincs::ShrincsKeyMaterial, crate::shrincs::state::SigningState),
    ConsensusError,
> {
    use crate::shrincs::shrincs::{keygen, ShrincsFullParams};

    let params = ShrincsFullParams::LEVEL1_2_30;
    let (key_material, state) = keygen(params).map_err(|_| ConsensusError::InvalidSignature)?;

    // Serialize pk with algorithm prefix
    let mut pk_ser = Vec::with_capacity(1 + SHRINCS_PUBKEY_LEN);
    pk_ser.push(SHRINCS_ALG_ID);
    pk_ser.extend_from_slice(&key_material.pk.to_bytes());

    Ok((pk_ser, key_material, state))
}

/// SHRINCS signing (prepends type byte, appends sighash type byte).
///
/// # Arguments
/// - `key_material`: Key material from `shrincs_keypair()`
/// - `state`: Mutable signing state (updated on each signature)
/// - `msg32`: 32-byte message to sign
/// - `sighash_type`: Sighash type byte to append
///
/// # Returns
/// Serialized signature: [type_prefix(1) || sig_data || sighash(1)]
/// where type_prefix is 0x00 for stateful signatures
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

    // Format: type_prefix(1) || sig_data || sighash(1)
    let mut sig_ser = Vec::with_capacity(1 + sig_bytes.len() + 1);
    sig_ser.push(0x00); // Stateful signature type prefix
    sig_ser.extend_from_slice(&sig_bytes);
    sig_ser.push(sighash_type);

    Ok(sig_ser)
}
