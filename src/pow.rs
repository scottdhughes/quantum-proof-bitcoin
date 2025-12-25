use argon2::{Algorithm, Argon2, Params, Version};

use crate::constants::{POW_LANES, POW_MEMORY_KIB, POW_OUT_LEN, POW_TIME_COST};
use crate::errors::ConsensusError;
use crate::types::BlockHeader;

/// Convert compact bits encoding (Bitcoin-style) to a 32-byte big-endian target.
pub fn bits_to_target(bits: u32) -> Option<[u8; 32]> {
    let exp = (bits >> 24) as u8;
    let mant = bits & 0x007f_ffff; // top bit is sign, reject if set
    if bits & 0x0080_0000 != 0 || mant == 0 {
        return None;
    }
    if exp == 0 {
        return None;
    }
    let mut target = [0u8; 32];
    let mant_bytes = [(mant >> 16) as u8, (mant >> 8) as u8, mant as u8];
    if exp <= 3 {
        // Right shift mantissa
        let shift = 3 - exp;
        let value = mant >> (8 * shift as u32);
        let bytes = value.to_be_bytes(); // 4 bytes
        target[32 - 4..].copy_from_slice(&bytes);
    } else {
        let start = 32usize.saturating_sub(exp as usize);
        if start + 3 > 32 {
            return None;
        }
        target[start..start + 3].copy_from_slice(&mant_bytes);
    }
    Some(target)
}

/// Compute Argon2id hash of the block header.
///
/// Password: serialized block header (80 bytes)
/// Salt: prev_blockhash (32 bytes) to keep block-specific salt.
pub fn pow_hash(header: &BlockHeader) -> Result<[u8; 32], ConsensusError> {
    let params = Params::new(
        POW_MEMORY_KIB,
        POW_TIME_COST,
        POW_LANES,
        Some(POW_OUT_LEN as usize),
    )
    .map_err(|_| ConsensusError::Unimplemented("argon2 params"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password = header.serialize();
    let salt = header.prev_blockhash;
    let mut out = [0u8; POW_OUT_LEN as usize];
    argon
        .hash_password_into(&password, &salt, &mut out)
        .map_err(|_| ConsensusError::ScriptFailed)?;
    Ok(out)
}

/// Check PoW: argon2id hash interpreted as big-endian integer <= target(bits).
pub fn validate_pow(header: &BlockHeader) -> Result<(), ConsensusError> {
    let target = bits_to_target(header.bits).ok_or(ConsensusError::ScriptFailed)?;
    let hash = pow_hash(header)?;
    if hash <= target {
        Ok(())
    } else {
        Err(ConsensusError::ScriptFailed)
    }
}
