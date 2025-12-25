//! FORS (Forest of Random Subsets) placeholder per Sec. 9.1 of the paper.
//! Stub-only: deterministic, hash-based reveals; NOT a real FORS.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

pub const FORS_K: u32 = 4;
pub const FORS_A: u32 = 4;
pub const FORS_REVEAL_LEN: usize = 32;

pub fn sign(msg: &[u8; 32], k: u32, a: u32) -> Vec<u8> {
    let k = if k == 0 { FORS_K } else { k };
    let a = if a == 0 { FORS_A } else { a };
    let mut out = Vec::with_capacity(k as usize * FORS_REVEAL_LEN);
    for i in 0..k {
        let mut h = Sha256::new();
        h.update(msg);
        h.update(i.to_be_bytes());
        h.update(a.to_be_bytes());
        out.extend_from_slice(&h.finalize());
    }
    out
}

pub fn verify(msg: &[u8; 32], sig: &[u8], k: u32, a: u32) -> bool {
    let k = if k == 0 { FORS_K } else { k };
    let a = if a == 0 { FORS_A } else { a };
    if sig.len() < k as usize * FORS_REVEAL_LEN {
        return false;
    }
    for i in 0..k {
        let start = i as usize * FORS_REVEAL_LEN;
        let end = start + FORS_REVEAL_LEN;
        let mut h = Sha256::new();
        h.update(msg);
        h.update(i.to_be_bytes());
        h.update(a.to_be_bytes());
        let expect = h.finalize();
        if sig[start..end] != expect[..] {
            return false;
        }
    }
    true
}
