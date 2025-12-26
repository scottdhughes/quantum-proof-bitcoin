use crate::constants::{MLDSA65_ALG_ID, MLDSA65_PUBKEY_LEN, MLDSA65_SIG_LEN};
#[cfg(feature = "shrincs-dev")]
use crate::constants::{SHRINCS_MAX_INDEX, SHRINCS_PUBKEY_LEN, SHRINCS_SIG_LEN};
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
}

impl AlgorithmId {
    pub fn from_byte(b: u8) -> Result<Self, ConsensusError> {
        match b {
            MLDSA65_ALG_ID => Ok(AlgorithmId::MLDSA65),
            _ => Err(ConsensusError::InactiveAlgorithm),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            AlgorithmId::MLDSA65 => MLDSA65_ALG_ID,
        }
    }
}

/// PQSigCheck cost units per algorithm (genesis).
pub fn pqsig_cost(alg: AlgorithmId) -> u32 {
    match alg {
        AlgorithmId::MLDSA65 => 1,
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
    }?;

    #[allow(unreachable_code)]
    Ok(())
}

/// Dev-only SHRINCS stub verifier (never active in consensus).
#[cfg(feature = "shrincs-dev")]
pub fn verify_shrincs_dev(pk: &[u8], msg32: &[u8], sig: &[u8]) -> Result<(), ConsensusError> {
    if msg32.len() != 32 {
        return Err(ConsensusError::InvalidSignature);
    }
    if pk.len() != SHRINCS_PUBKEY_LEN || sig.len() != SHRINCS_SIG_LEN {
        return Err(ConsensusError::InvalidSignature);
    }

    // Enforce message binding: sig[4..] repeats msg32.
    for (i, b) in sig.iter().enumerate().skip(4) {
        if *b != msg32[(i - 4) % 32] {
            return Err(ConsensusError::InvalidSignature);
        }
    }

    let idx = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);

    // If an FFI library is available, attempt to verify there too (but still
    // require the message-binding pattern above for determinism).
    #[cfg(feature = "shrincs-ffi")]
    if let Some(ffi) = load_shrincs() {
        unsafe {
            let rc = (ffi.verify)(
                msg32.as_ptr(),
                msg32.len(),
                pk.as_ptr(),
                pk.len(),
                sig.as_ptr(),
                sig.len(),
            );
            if rc == 1 {
                return Ok(());
            }
        }
    }

    if idx >= SHRINCS_MAX_INDEX {
        // Simulate SLH fallback acceptance in the stub.
        return Ok(());
    }

    Ok(())
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

/// Dev-only SHRINCS helpers retained behind `shrincs-dev`.
#[cfg(feature = "shrincs-dev")]
pub fn shrincs_keygen() -> [u8; SHRINCS_PUBKEY_LEN] {
    // Fallback deterministic pattern
    let mut pk = [0u8; SHRINCS_PUBKEY_LEN];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x5a;
    }
    pk
}

#[cfg(feature = "shrincs-dev")]
pub fn shrincs_sign(_pk: &[u8], msg32: &[u8]) -> [u8; SHRINCS_SIG_LEN] {
    let mut sig = [0u8; SHRINCS_SIG_LEN];
    sig[0..4].copy_from_slice(&0u32.to_be_bytes());
    for i in 4..SHRINCS_SIG_LEN {
        sig[i] = msg32[(i - 4) % msg32.len()];
    }
    sig
}
