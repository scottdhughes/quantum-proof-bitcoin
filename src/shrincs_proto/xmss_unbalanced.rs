//! Unbalanced XMSS scaffold (Appendix B.3 of the SHRINCS proposal).
//! Placeholder only; no real XMSS security properties.

#![allow(dead_code)]

use crate::shrincs_proto::wots_c;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct UnbalancedXmss {
    pub height: u32,
    pub root: [u8; 32],
    pub wots_params: wots_c::WotsCParams,
    pub wots_pk: wots_c::WotsCPublic,
    pub wots_sk: wots_c::WotsCSecret,
}

#[derive(Debug, Clone)]
pub struct XmssSignature {
    pub auth: Vec<[u8; 32]>,
    pub ots_sig: Vec<Vec<u8>>,
    pub leaf_q: u32,
}

impl UnbalancedXmss {
    /// Height=1 by default keeps auth minimal (matches low-sign wallets).
    pub fn new(height: u32) -> Self {
        let params = wots_c::WotsCParams::default();
        let (wots_sk, wots_pk) = wots_c::keygen(&params);
        let mut h = Sha256::new();
        h.update(flatten_pk(&wots_pk));
        h.update(height.to_le_bytes());
        let mut root = [0u8; 32];
        root.copy_from_slice(&h.finalize());
        Self {
            height,
            root,
            wots_params: params,
            wots_pk,
            wots_sk,
        }
    }

    /// Octopus-style auth path (App C): true sibling minimization.
    /// Works on integer indices, pairing siblings and only adding missing ones.
    pub fn octopus_auth(&self, leaves: &[u32]) -> Vec<[u8; 32]> {
        if leaves.is_empty() {
            return Vec::new();
        }
        let mut layer: Vec<u32> = leaves.to_vec();
        let mut auth: Vec<[u8; 32]> = Vec::new();
        let mut depth: u32 = 0;

        while layer.len() > 1 && depth < self.height {
            let set: HashSet<u32> = layer.iter().cloned().collect();
            let mut processed: HashSet<u32> = HashSet::new();
            let mut next: Vec<u32> = Vec::new();
            for &v in layer.iter() {
                if processed.contains(&v) {
                    continue;
                }
                let sib = v ^ 1; // flip last bit
                if set.contains(&sib) {
                    processed.insert(sib);
                    processed.insert(v);
                    // sibling present: skip adding to auth, just push parent
                } else {
                    auth.push(hash_sib_int(v, sib, depth));
                    processed.insert(v);
                }
                next.push(v >> 1);
            }
            layer = next;
            depth += 1;
        }

        // Pad up to tree height for deterministic length (helps sequential verify placeholder).
        while auth.len() < self.height as usize {
            auth.push(hash_pad(depth, leaves));
            depth += 1;
        }
        auth
    }

    pub fn sign(&self, msg: &[u8; 32], q: u32) -> XmssSignature {
        let ots_sig = wots_c::sign(msg, &self.wots_sk);
        XmssSignature {
            auth: self.octopus_auth(&[q]),
            ots_sig,
            leaf_q: q,
        }
    }

    pub fn verify(&self, msg: &[u8; 32], sig: &XmssSignature) -> bool {
        if !wots_c::verify(msg, &sig.ots_sig, &self.wots_pk) {
            return false;
        }
        let mut h = Sha256::new();
        h.update(flatten_sig(&sig.ots_sig));
        let mut node = [0u8; 32];
        node.copy_from_slice(&h.finalize());
        for sibling in sig.auth.iter() {
            let mut hh = Sha256::new();
            hh.update(node);
            hh.update(*sibling);
            node.copy_from_slice(&hh.finalize());
        }
        node == self.root
    }
}

fn flatten_pk(pk: &wots_c::WotsCPublic) -> Vec<u8> {
    pk.pk.iter().flat_map(|v| v.clone()).collect()
}

fn flatten_sig(sig: &[Vec<u8>]) -> Vec<u8> {
    sig.iter().flat_map(|v| v.clone()).collect()
}

fn flip_last_bit(bits: &str) -> String {
    if bits.is_empty() {
        return String::new();
    }
    let mut chars: Vec<char> = bits.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == '0' { '1' } else { '0' };
    }
    chars.into_iter().collect()
}

fn parent_encode(bits: &str) -> String {
    if bits.is_empty() {
        String::new()
    } else {
        bits[..bits.len().saturating_sub(1)].to_string()
    }
}

fn hash_sib(v: &str, sib: &str, depth: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(v.as_bytes());
    h.update(sib.as_bytes());
    h.update(depth.to_le_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash_pad(depth: u32, leaves: &[u32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pad");
    h.update(depth.to_le_bytes());
    for l in leaves {
        h.update(l.to_be_bytes());
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash_sib_int(v: u32, sib: u32, depth: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    let min = v.min(sib).to_be_bytes();
    let max = v.max(sib).to_be_bytes();
    h.update(min);
    h.update(max);
    h.update(depth.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}
