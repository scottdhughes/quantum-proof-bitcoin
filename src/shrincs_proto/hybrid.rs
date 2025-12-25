//! Hybrid SHRINCS prototype: tiny XMSS-style stateful path with a stateless
//! fallback (now using FORS stub). Non-consensus, stub-quality only.

#![allow(dead_code)]

use crate::shrincs_proto::fors;
use crate::shrincs_proto::xmss_unbalanced::{UnbalancedXmss, XmssSignature};
use sha2::{Digest, Sha256};

pub const PROTO_PK_LEN: usize = 64;
pub const PROTO_SIG_LEN: usize = 324;

#[derive(Debug, Clone)]
pub struct ShrincsProtoKeypair {
    pub pk: [u8; PROTO_PK_LEN],
    pub sk_stateful: UnbalancedXmss,
}

pub fn keygen() -> ShrincsProtoKeypair {
    let xmss = UnbalancedXmss::new(1);
    let mut pk = [0u8; PROTO_PK_LEN];
    // stateful half = XMSS root (32B)
    pk[..32].copy_from_slice(&xmss.root);
    // stateless/fallback half = hash(root || tag)
    let mut h = Sha256::new();
    h.update(xmss.root);
    h.update(b"fallback");
    let digest = h.finalize();
    pk[32..].copy_from_slice(&digest[..32]);
    ShrincsProtoKeypair {
        pk,
        sk_stateful: xmss,
    }
}

fn serialize_stateful(sig: &XmssSignature, out: &mut [u8]) {
    out[0] = 0; // fallback flag
    out[1..5].copy_from_slice(&sig.leaf_q.to_be_bytes());
    let mut cursor = 5;
    for node in sig.auth.iter() {
        if cursor + 32 > out.len() {
            break;
        }
        out[cursor..cursor + 32].copy_from_slice(node);
        cursor += 32;
    }
    for chunk in sig.ots_sig.iter() {
        if cursor >= out.len() {
            break;
        }
        let take = chunk.len().min(out.len() - cursor);
        out[cursor..cursor + take].copy_from_slice(&chunk[..take]);
        cursor += take;
    }
    // Remaining bytes stay zero.
}

fn serialize_fallback(msg: &[u8; 32], _pk: &[u8], out: &mut [u8]) {
    out[0] = 1; // fallback flag
    out[1..5].copy_from_slice(&0u32.to_be_bytes());
    let fors_sig = fors::sign(msg, fors::FORS_K, fors::FORS_A);
    let cursor = 5;
    let take = fors_sig.len().min(out.len().saturating_sub(cursor));
    out[cursor..cursor + take].copy_from_slice(&fors_sig[..take]);
}

pub fn sign(msg: &[u8; 32], kp: &ShrincsProtoKeypair, q: u32, force_fallback: bool) -> Vec<u8> {
    let mut out = vec![0u8; PROTO_SIG_LEN];
    if force_fallback {
        serialize_fallback(msg, &kp.pk, &mut out);
        return out;
    }
    let sig = kp.sk_stateful.sign(msg, q);
    serialize_stateful(&sig, &mut out);
    out
}

pub fn verify(msg: &[u8; 32], pk: &[u8], sig: &[u8], q: u32) -> bool {
    if pk.len() != PROTO_PK_LEN || sig.len() != PROTO_SIG_LEN {
        return false;
    }
    let fallback_flag = sig[0] == 1;
    if fallback_flag {
        let fors_slice = &sig[5..];
        return fors::verify(msg, fors_slice, fors::FORS_K, fors::FORS_A);
    }
    // Recreate XMSS view from pk
    let mut root = [0u8; 32];
    root.copy_from_slice(&pk[..32]);
    let xmss = UnbalancedXmss::new(1);
    if xmss.root != root {
        return false;
    }
    // Parse auth path and OTS chunks
    let mut auth = Vec::new();
    let mut cursor = 5usize;
    for _ in 0..xmss.height {
        if cursor + 32 > sig.len() {
            return false;
        }
        let mut node = [0u8; 32];
        node.copy_from_slice(&sig[cursor..cursor + 32]);
        auth.push(node);
        cursor += 32;
    }
    let mut ots_chunks: Vec<Vec<u8>> = Vec::new();
    while cursor < sig.len() {
        let take = (sig.len() - cursor).min(32);
        ots_chunks.push(sig[cursor..cursor + take].to_vec());
        cursor += take;
    }
    let xmss_sig = XmssSignature {
        auth,
        ots_sig: ots_chunks,
        leaf_q: q,
    };
    xmss.verify(msg, &xmss_sig)
}
