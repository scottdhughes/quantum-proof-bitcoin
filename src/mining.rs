use std::ops::Range;

#[cfg(feature = "parallel-mine")]
use rayon::prelude::*;

use crate::errors::ConsensusError;
use crate::pow::{bits_to_target, pow_hash, validate_pow};
use crate::types::BlockHeader;

/// Compute merkle root from a list of 32-byte txids (HASH256), duplicating the last when odd.
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = txids.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for i in (0..layer.len()).step_by(2) {
            let a = layer[i];
            let b = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                layer[i]
            };
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&a);
            buf.extend_from_slice(&b);
            next.push(crate::hashing::hash256(&buf));
        }
        layer = next;
    }
    layer[0]
}

/// Serial mining helper: iterate nonces starting at `start_nonce`, up to `max_attempts`,
/// returning the first header that satisfies PoW. Designed for dev/regtest with easy bits.
pub fn mine_header_serial(
    mut header: BlockHeader,
    start_nonce: u32,
    max_attempts: u64,
) -> Option<BlockHeader> {
    let target = bits_to_target(header.bits)?;
    let mut nonce = start_nonce;
    for _ in 0..max_attempts {
        header.nonce = nonce;
        if let Ok(hash) = pow_hash(&header) && hash <= target {
            return Some(header);
        }
        nonce = nonce.wrapping_add(1);
    }
    None
}

/// Parallel mining helper (requires `parallel-mine` feature).
/// Splits the provided nonce range across rayon threads.
#[cfg(feature = "parallel-mine")]
pub fn mine_header_parallel(header: &BlockHeader, nonces: Range<u64>) -> Option<BlockHeader> {
    let target = bits_to_target(header.bits)?;
    nonces.into_par_iter().find_map_any(|n| {
        let mut h = header.clone();
        h.nonce = n as u32;
        pow_hash(&h).ok().filter(|hash| *hash <= target).map(|_| h)
    })
}

/// Stub when parallel mining feature is disabled.
#[cfg(not(feature = "parallel-mine"))]
pub fn mine_header_parallel(_header: &BlockHeader, _nonces: Range<u64>) -> Option<BlockHeader> {
    None
}

/// Convenience: validate PoW for a header (re-exports validate_pow).
pub fn check_pow(header: &BlockHeader) -> Result<(), ConsensusError> {
    validate_pow(header)
}
