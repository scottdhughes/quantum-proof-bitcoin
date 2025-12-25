//! WOTS+C (tweaked Winternitz) skeleton based on SHRINCS proposal (Sec. 5).
//! This is a placeholder to keep the Rust prototype structure compiling;
//! it is NOT a production implementation.

#![allow(dead_code)]

use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct WotsCParams {
    /// Hash output size in bytes (n).
    pub n: usize,
    /// Winternitz parameter (power of two in this sketch).
    pub w: u32,
    /// Number of chains (l). In a full WOTS this is derived from n and w;
    /// here we keep it explicit to keep the prototype simple.
    pub l: usize,
}

impl Default for WotsCParams {
    fn default() -> Self {
        Self {
            n: 32,
            w: 16,
            l: 16, // small for prototype
        }
    }
}

fn base_w(input: &[u8], w: u32, out_len: usize) -> Vec<u32> {
    // Convert byte string to base-w digits (little-endian).
    let mut acc = 0u32;
    let mut bits = 0u32;
    let log_w = (w as f64).log2() as u32;
    let mut res = Vec::with_capacity(out_len);
    for b in input {
        acc = (acc << 8) | (*b as u32);
        bits += 8;
        while bits >= log_w && res.len() < out_len {
            bits -= log_w;
            res.push((acc >> bits) & (w - 1));
        }
    }
    while res.len() < out_len {
        res.push(0);
    }
    res
}

/// Simple chain function: hash(input || counter) `steps` times starting at `start`.
pub fn gen_chain(input: &[u8], start: u32, steps: u32) -> Vec<u8> {
    let mut value = input.to_vec();
    for i in start..start + steps {
        let mut h = Sha256::new();
        h.update(&value);
        h.update(&i.to_le_bytes());
        value = h.finalize().to_vec();
    }
    value
}

#[derive(Debug, Clone)]
pub struct WotsCSecret {
    pub sk: Vec<Vec<u8>>, // l seeds of length n
    pub params: WotsCParams,
}

#[derive(Debug, Clone)]
pub struct WotsCPublic {
    pub pk: Vec<Vec<u8>>, // l chain tips
    pub params: WotsCParams,
}

/// Key generation: sample l seeds, derive chain tips of length n.
pub fn keygen(params: &WotsCParams) -> (WotsCSecret, WotsCPublic) {
    let mut rng = rand::thread_rng();
    let mut sk = Vec::with_capacity(params.l);
    let mut pk = Vec::with_capacity(params.l);
    for _ in 0..params.l {
        let mut seed = vec![0u8; params.n];
        rng.fill_bytes(&mut seed);
        let tip = gen_chain(&seed, 0, params.w - 1);
        sk.push(seed);
        pk.push(tip);
    }
    (
        WotsCSecret {
            sk: sk.clone(),
            params: params.clone(),
        },
        WotsCPublic {
            pk,
            params: params.clone(),
        },
    )
}

/// Sign: map msg to base-w digits (truncated/expanded to l), then run each chain for a_i steps.
pub fn sign(msg: &[u8; 32], sk: &WotsCSecret) -> Vec<Vec<u8>> {
    let params = &sk.params;
    let a = base_w(msg, params.w, params.l);
    let mut sig = Vec::with_capacity(params.l);
    for (i, ai) in a.iter().enumerate() {
        let seed = &sk.sk[i];
        sig.push(gen_chain(seed, 0, *ai));
    }
    sig
}

/// Verify: advance each signature element to the chain tip and compare to pk.
pub fn verify(msg: &[u8; 32], sig: &[Vec<u8>], pk: &WotsCPublic) -> bool {
    let params = &pk.params;
    if sig.len() != params.l || pk.pk.len() != params.l {
        return false;
    }
    let a = base_w(msg, params.w, params.l);
    for i in 0..params.l {
        let end = gen_chain(&sig[i], a[i], params.w - 1 - a[i]);
        if end != pk.pk[i] {
            return false;
        }
    }
    true
}
