use crate::constants::{SHRINCS_ALG_ID, SHRINCS_PUBKEY_LEN, SHRINCS_SIG_LEN};
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
    Shrincs,
}

impl AlgorithmId {
    pub fn from_byte(b: u8) -> Result<Self, ConsensusError> {
        match b {
            SHRINCS_ALG_ID => Ok(AlgorithmId::Shrincs),
            _ => Err(ConsensusError::InactiveAlgorithm),
        }
    }

    pub fn as_byte(self) -> u8 {
        match self {
            AlgorithmId::Shrincs => SHRINCS_ALG_ID,
        }
    }
}

/// PQSigCheck cost units per algorithm (genesis).
pub fn pqsig_cost(alg: AlgorithmId) -> u32 {
    match alg {
        AlgorithmId::Shrincs => 1,
    }
}

/// Stub verifier: length checks only; accepts valid-length SHRINCS signatures.
fn verify_stub(
    alg: AlgorithmId,
    pk: &[u8],
    msg32: &[u8],
    sig: &[u8],
) -> Result<(), ConsensusError> {
    if msg32.len() != 32 {
        return Err(ConsensusError::InvalidSignature);
    }
    match alg {
        AlgorithmId::Shrincs => {
            if pk.len() != SHRINCS_PUBKEY_LEN {
                return Err(ConsensusError::InvalidPublicKey);
            }
            if sig.len() != SHRINCS_SIG_LEN {
                return Err(ConsensusError::InvalidSignature);
            }
            Ok(())
        }
    }
}

#[cfg(feature = "shrincs-ffi")]
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
    // Always enforce length checks
    verify_stub(alg, pk, msg32, sig)?;

    #[cfg(feature = "shrincs-ffi")]
    {
        if let Some(ffi) = load_shrincs() {
            let ok = unsafe {
                (ffi.verify)(
                    msg32.as_ptr(),
                    msg32.len(),
                    pk.as_ptr(),
                    pk.len(),
                    sig.as_ptr(),
                    sig.len(),
                )
            };
            if ok == 1 {
                return Ok(());
            }
            return Err(ConsensusError::PQSignatureInvalid);
        }
    }

    // Fallback stub accept
    Ok(())
}

/// Deterministic keygen helper (uses shrincs-ffi if available; otherwise fixed pattern).
pub fn shrincs_keygen() -> [u8; SHRINCS_PUBKEY_LEN] {
    #[cfg(feature = "shrincs-ffi")]
    {
        if let Some(ffi) = load_shrincs() && let Some(keygen) = &ffi.keygen {
            let mut pk = [0u8; SHRINCS_PUBKEY_LEN];
            let ok = unsafe { (keygen)(pk.as_mut_ptr(), pk.len()) };
            if ok == 1 {
                return pk;
            }
        }
    }
    // Fallback deterministic pattern
    let mut pk = [0u8; SHRINCS_PUBKEY_LEN];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x5a;
    }
    pk
}

/// Deterministic sign helper (uses shrincs-ffi if available; otherwise repeats msg bytes and zeros state byte).
pub fn shrincs_sign(pk: &[u8], msg32: &[u8]) -> [u8; SHRINCS_SIG_LEN] {
    let mut sig = [0u8; SHRINCS_SIG_LEN];

    #[cfg(feature = "shrincs-ffi")]
    {
        if let Some(ffi) = load_shrincs() && let Some(sign) = &ffi.sign {
            let ok = unsafe {
                (sign)(
                    msg32.as_ptr(),
                    msg32.len(),
                    pk.as_ptr(),
                    pk.len(),
                    sig.as_mut_ptr(),
                    sig.len(),
                )
            };
            if ok == 1 {
                return sig;
            }
        }
    }

    // Fallback deterministic pattern
    for i in 0..SHRINCS_SIG_LEN {
        sig[i] = msg32[i % msg32.len()];
    }
    sig[0] = 0; // LMS state valid
    sig
}
