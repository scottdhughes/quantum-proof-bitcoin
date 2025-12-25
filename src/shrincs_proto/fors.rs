//! FORS (Forest of Random Subsets) placeholder per Sec. 9.1 of the paper.
//! Stub-only: deterministic, hash-based reveals; NOT a real FORS.

#![allow(dead_code)]

use sha2::{Digest, Sha256};

pub const FORS_K: u32 = 4;
pub const FORS_A: u32 = 4;
pub const FORS_REVEAL_LEN: usize = 32;
pub const FORS_NONCE_LEN: usize = 32; // r value
pub const FORS_COMPRESS_LAST: bool = true;

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn last_a_bits_zero(d: &[u8], a: u32) -> bool {
    if a == 0 {
        return true;
    }
    let bits = a as usize;
    let byte = d.last().cloned().unwrap_or(0);
    let mask = (1u16 << bits) - 1;
    (byte as u16 & mask) == 0
}

pub fn sign(msg: &[u8; 32], k: u32, a: u32) -> Vec<u8> {
    let k = if k == 0 { FORS_K } else { k };
    let a = if a == 0 { FORS_A } else { a };
    let mut count: u32 = 0;
    loop {
        let mut nonce_input = Vec::with_capacity(FORS_NONCE_LEN + 8);
        nonce_input.extend_from_slice(msg);
        nonce_input.extend_from_slice(&count.to_be_bytes());
        let r = hash_bytes(&nonce_input);
        let mut digest_input = Vec::with_capacity(msg.len() + r.len());
        digest_input.extend_from_slice(msg);
        digest_input.extend_from_slice(&r);
        let digest = hash_bytes(&digest_input);
        if last_a_bits_zero(&digest, a) {
            let mut out = Vec::with_capacity(FORS_NONCE_LEN + 4 + (k as usize) * FORS_REVEAL_LEN);
            out.extend_from_slice(&r);
            out.extend_from_slice(&count.to_le_bytes());
            let limit = if FORS_COMPRESS_LAST && k > 0 {
                k - 1
            } else {
                k
            };
            for i in 0..limit {
                let mut h = Sha256::new();
                h.update(digest);
                h.update(i.to_be_bytes());
                out.extend_from_slice(&h.finalize());
            }
            return out;
        }
        count = count.wrapping_add(1);
        if count == 0 {
            // extremely unlikely overflow guard
            break;
        }
    }
    Vec::new()
}

pub fn verify(msg: &[u8; 32], sig: &[u8], k: u32, a: u32) -> bool {
    let k = if k == 0 { FORS_K } else { k };
    let a = if a == 0 { FORS_A } else { a };
    let limit = if FORS_COMPRESS_LAST && k > 0 {
        k - 1
    } else {
        k
    };
    let min_len = FORS_NONCE_LEN + 4 + limit as usize * FORS_REVEAL_LEN;
    if sig.len() < min_len {
        return false;
    }
    let r = &sig[..FORS_NONCE_LEN];
    let _count_bytes = &sig[FORS_NONCE_LEN..FORS_NONCE_LEN + 4];
    let mut digest_input = Vec::with_capacity(msg.len() + r.len());
    digest_input.extend_from_slice(msg);
    digest_input.extend_from_slice(r);
    let digest = hash_bytes(&digest_input);
    if !last_a_bits_zero(&digest, a) {
        return false;
    }
    let reveals = &sig[FORS_NONCE_LEN + 4..];
    if reveals.len() < limit as usize * FORS_REVEAL_LEN {
        return false;
    }
    for i in 0..limit {
        let start = i as usize * FORS_REVEAL_LEN;
        let end = start + FORS_REVEAL_LEN;
        let mut h = Sha256::new();
        h.update(digest);
        h.update(i.to_be_bytes());
        let expect = h.finalize();
        if reveals[start..end] != expect[..] {
            return false;
        }
    }
    true
}
