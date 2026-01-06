//! XMSS^MT: Multi-Tree Extended Merkle Signature Scheme
//!
//! Implementation based on "Hash-based Signature Schemes for Bitcoin"
//! (Kudinov & Nick, 2025) and RFC 8391 (XMSS).
//!
//! # Structure
//!
//! A hypertree consists of d layers of XMSS subtrees:
//! - Each subtree has height h' = h/d
//! - Layer 0 signs the PORS root (few-time signature output)
//! - Each subsequent layer signs the root of the layer below
//! - The final layer's root is the public key
//!
//! # Parameters (2^30 signatures)
//!
//! - h = 32 (total height)
//! - d = 4 (number of layers)
//! - h' = 8 (height per subtree)
//! - 2^8 = 256 leaves per subtree

use crate::shrincs::wots::{
    self, Address, WotsCParams, WotsCPublicKey, WotsCSecretKey, WotsCSignature,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Hypertree parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HypertreeParams {
    /// Total tree height
    pub h: u32,
    /// Number of layers (subtrees)
    pub d: u32,
    /// Height per subtree = h / d
    pub h_prime: u32,
    /// WOTS+C parameters
    pub wots_params: WotsCParams,
}

impl HypertreeParams {
    /// Parameters for 2^30 signatures
    pub const LEVEL1_2_30: Self = Self {
        h: 32,
        d: 4,
        h_prime: 8, // 32 / 4 = 8
        wots_params: WotsCParams::LEVEL1,
    };

    /// Number of leaves per subtree
    pub const fn leaves_per_subtree(&self) -> u32 {
        1 << self.h_prime
    }

    /// Total signature capacity
    pub const fn max_signatures(&self) -> u64 {
        1u64 << self.h
    }
}

/// A single XMSS subtree layer
#[derive(Clone)]
pub struct XmssLayer {
    /// Layer index (0 = bottom, d-1 = top)
    pub layer_idx: u32,
    /// Subtree root
    pub root: Vec<u8>,
    /// All nodes in the subtree (for auth path generation)
    /// Indexed as nodes[level][index]
    pub nodes: Vec<Vec<Vec<u8>>>,
    /// WOTS keypairs for each leaf
    pub wots_keypairs: Vec<(WotsCSecretKey, WotsCPublicKey)>,
    /// Parameters
    pub params: HypertreeParams,
}

/// Signature for a single XMSS layer
#[derive(Clone)]
pub struct XmssLayerSignature {
    /// WOTS+C signature
    pub wots_sig: WotsCSignature,
    /// Authentication path (h' sibling hashes)
    pub auth_path: Vec<Vec<u8>>,
    /// Leaf index within this subtree
    pub leaf_index: u32,
}

impl XmssLayerSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let wots_bytes = self.wots_sig.to_bytes();
        let _n = self.wots_sig.params.n;

        let mut out = Vec::new();
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&(wots_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&wots_bytes);
        out.extend_from_slice(&(self.auth_path.len() as u16).to_le_bytes());
        for node in &self.auth_path {
            out.extend_from_slice(node);
        }
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], wots_params: WotsCParams) -> Option<Self> {
        if bytes.len() < 10 {
            return None;
        }

        let leaf_index = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let wots_len = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;

        if bytes.len() < 8 + wots_len + 2 {
            return None;
        }

        let wots_sig = WotsCSignature::from_bytes(&bytes[8..8 + wots_len], wots_params)?;

        let offset = 8 + wots_len;
        let auth_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
        let n = wots_params.n;

        if bytes.len() < offset + 2 + auth_len * n {
            return None;
        }

        let mut auth_path = Vec::with_capacity(auth_len);
        let mut pos = offset + 2;
        for _ in 0..auth_len {
            auth_path.push(bytes[pos..pos + n].to_vec());
            pos += n;
        }

        Some(Self {
            wots_sig,
            auth_path,
            leaf_index,
        })
    }
}

/// Complete hypertree signature (d layer signatures)
#[derive(Clone)]
pub struct HypertreeSignature {
    /// Signatures for each layer (0 = bottom)
    pub layer_sigs: Vec<XmssLayerSignature>,
    /// Parameters
    pub params: HypertreeParams,
}

impl HypertreeSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.layer_sigs.len() as u8).to_le_bytes());

        for sig in &self.layer_sigs {
            let sig_bytes = sig.to_bytes();
            out.extend_from_slice(&(sig_bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&sig_bytes);
        }
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: HypertreeParams) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        let num_layers = bytes[0] as usize;
        let mut offset = 1;
        let mut layer_sigs = Vec::with_capacity(num_layers);

        for _ in 0..num_layers {
            if offset + 4 > bytes.len() {
                return None;
            }
            let sig_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
            offset += 4;

            if offset + sig_len > bytes.len() {
                return None;
            }

            let layer_sig = XmssLayerSignature::from_bytes(
                &bytes[offset..offset + sig_len],
                params.wots_params,
            )?;
            layer_sigs.push(layer_sig);
            offset += sig_len;
        }

        Some(Self { layer_sigs, params })
    }
}

/// Hash function for XMSS nodes
fn hash_node(
    pk_seed: &[u8; 32],
    left: &[u8],
    right: &[u8],
    layer: u32,
    tree_idx: u64,
    node_idx: u32,
    n: usize,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"XMSS_NODE");
    hasher.update(pk_seed);
    hasher.update(layer.to_le_bytes());
    hasher.update(tree_idx.to_le_bytes());
    hasher.update(node_idx.to_le_bytes());
    hasher.update(left);
    hasher.update(right);
    let hash = hasher.finalize();
    hash[..n].to_vec()
}

/// Compress WOTS+ public key to leaf hash
fn hash_wots_pk(
    pk_seed: &[u8; 32],
    pk: &WotsCPublicKey,
    layer: u32,
    leaf_idx: u32,
    n: usize,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"XMSS_WOTS_PK");
    hasher.update(pk_seed);
    hasher.update(layer.to_le_bytes());
    hasher.update(leaf_idx.to_le_bytes());
    for tip in &pk.chain_tips {
        hasher.update(tip);
    }
    let hash = hasher.finalize();
    hash[..n].to_vec()
}

/// Build a single XMSS subtree layer
pub fn build_xmss_layer(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    layer_idx: u32,
    tree_idx: u64,
    params: &HypertreeParams,
) -> XmssLayer {
    let h_prime = params.h_prime;
    let num_leaves = 1u32 << h_prime;
    let n = params.wots_params.n;

    // Generate WOTS keypairs for each leaf
    let mut wots_keypairs = Vec::with_capacity(num_leaves as usize);
    let mut leaf_nodes = Vec::with_capacity(num_leaves as usize);

    for leaf_idx in 0..num_leaves {
        // Create address for this WOTS keypair
        let addr = Address::new(layer_idx, tree_idx, leaf_idx, 0, 0);

        // Derive layer-specific sk_seed
        let mut hasher = Sha256::new();
        hasher.update(b"XMSS_SK_DERIVE");
        hasher.update(sk_seed);
        hasher.update(layer_idx.to_le_bytes());
        hasher.update(tree_idx.to_le_bytes());
        hasher.update(leaf_idx.to_le_bytes());
        let derived_seed: [u8; 32] = hasher.finalize().into();

        let (sk, pk) = wots::keygen(&derived_seed, pk_seed, addr, &params.wots_params);

        // Compute leaf hash from WOTS public key
        let leaf_hash = hash_wots_pk(pk_seed, &pk, layer_idx, leaf_idx, n);
        leaf_nodes.push(leaf_hash);
        wots_keypairs.push((sk, pk));
    }

    // Build Merkle tree
    let mut nodes: Vec<Vec<Vec<u8>>> = Vec::with_capacity((h_prime + 1) as usize);
    nodes.push(leaf_nodes);

    for level in 1..=h_prime {
        let prev = &nodes[(level - 1) as usize];
        let mut current = Vec::with_capacity(prev.len() / 2);

        for i in 0..prev.len() / 2 {
            let parent = hash_node(
                pk_seed,
                &prev[2 * i],
                &prev[2 * i + 1],
                layer_idx,
                tree_idx,
                i as u32,
                n,
            );
            current.push(parent);
        }
        nodes.push(current);
    }

    let root = nodes[h_prime as usize][0].clone();

    XmssLayer {
        layer_idx,
        root,
        nodes,
        wots_keypairs,
        params: *params,
    }
}

/// Get authentication path for a leaf
pub fn get_auth_path(layer: &XmssLayer, leaf_idx: u32) -> Vec<Vec<u8>> {
    let h_prime = layer.params.h_prime;
    let mut auth_path = Vec::with_capacity(h_prime as usize);
    let mut idx = leaf_idx;

    for level in 0..h_prime {
        let sibling_idx = idx ^ 1;
        if (sibling_idx as usize) < layer.nodes[level as usize].len() {
            auth_path.push(layer.nodes[level as usize][sibling_idx as usize].clone());
        }
        idx >>= 1;
    }

    auth_path
}

/// Sign with a single XMSS layer
pub fn sign_layer(
    msg: &[u8],
    layer: &XmssLayer,
    leaf_idx: u32,
    pk_seed: &[u8; 32],
    randomness: &[u8; 32],
    hypertree_root: &[u8], // Use top-level root for all layers (enables verification)
) -> Option<XmssLayerSignature> {
    if leaf_idx >= (1 << layer.params.h_prime) {
        return None;
    }

    let (sk, _pk) = &layer.wots_keypairs[leaf_idx as usize];

    // Create message hash (truncate to 32 bytes)
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let msg_hash: [u8; 32] = hasher.finalize().into();

    // Create WOTS address
    let addr = Address::new(layer.layer_idx, 0, leaf_idx, 0, 0);

    // Sign with WOTS+C using hypertree_root as pk_root (not layer.root)
    // This enables verification without knowing intermediate layer roots
    let wots_sig = wots::sign(&msg_hash, sk, pk_seed, hypertree_root, addr, randomness)?;

    // Get auth path
    let auth_path = get_auth_path(layer, leaf_idx);

    Some(XmssLayerSignature {
        wots_sig,
        auth_path,
        leaf_index: leaf_idx,
    })
}

/// Reconstruct the layer root from an XMSS layer signature.
/// Returns the reconstructed root, or None if WOTS counter verification fails.
/// Uses pk_root (hypertree root) for message digest - same for all layers.
#[allow(clippy::too_many_arguments)]
pub fn reconstruct_layer_root_v2(
    msg: &[u8],
    sig: &XmssLayerSignature,
    pk_root: &[u8], // hypertree_root, same for all layers
    pk_seed: &[u8; 32],
    layer_idx: u32,
    tree_idx: u64,
    randomness: &[u8; 32],
    params: &HypertreeParams,
) -> Option<Vec<u8>> {
    let n = params.wots_params.n;

    // Create message hash
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let msg_hash: [u8; 32] = hasher.finalize().into();

    // Create WOTS address
    let addr = Address::new(layer_idx, tree_idx, sig.leaf_index, 0, 0);

    // Recompute the message digest with counter using pk_root (hypertree root)
    let (digits, sum) = wots::message_digest_with_counter_raw(
        randomness,
        pk_root,
        &msg_hash,
        sig.wots_sig.counter,
        &params.wots_params,
    );

    // Verify counter achieved target sum
    if sum != params.wots_params.target_sum {
        return None;
    }

    // Compute WOTS public key elements by completing chains
    let mut pk_elements = Vec::with_capacity(params.wots_params.l);
    let mut chain_addr = addr;

    #[allow(clippy::needless_range_loop)]
    for i in 0..params.wots_params.l {
        chain_addr.chain = i as u32;
        let remaining = params.wots_params.w - 1 - digits[i];
        let tip = wots::gen_chain_public(
            pk_seed,
            &sig.wots_sig.sig_elements[i],
            digits[i],
            remaining,
            &mut chain_addr,
            n,
        );
        pk_elements.push(tip);
    }

    // Hash WOTS public key to get leaf node
    let recovered_pk = WotsCPublicKey {
        chain_tips: pk_elements,
        params: params.wots_params,
    };
    let mut leaf_hash = hash_wots_pk(pk_seed, &recovered_pk, layer_idx, sig.leaf_index, n);

    // Walk auth path to reconstruct layer root
    let mut idx = sig.leaf_index;
    for sibling in sig.auth_path.iter() {
        let (left, right) = if idx.is_multiple_of(2) {
            (&leaf_hash, sibling)
        } else {
            (sibling, &leaf_hash)
        };

        leaf_hash = hash_node(pk_seed, left, right, layer_idx, tree_idx, idx >> 1, n);
        idx >>= 1;
    }

    Some(leaf_hash)
}

/// Verify a single XMSS layer signature.
/// Uses pk_root (hypertree root) for message digest.
/// Checks that reconstructed root matches expected_root.
#[allow(clippy::too_many_arguments)]
pub fn verify_layer(
    msg: &[u8],
    sig: &XmssLayerSignature,
    expected_root: &[u8],
    pk_root: &[u8], // hypertree_root for message digest
    pk_seed: &[u8; 32],
    layer_idx: u32,
    tree_idx: u64,
    randomness: &[u8; 32],
    params: &HypertreeParams,
) -> bool {
    match reconstruct_layer_root_v2(
        msg, sig, pk_root, pk_seed, layer_idx, tree_idx, randomness, params,
    ) {
        Some(root) => root == expected_root,
        None => false,
    }
}

/// Full hypertree structure
pub struct Hypertree {
    /// All d layers
    pub layers: Vec<XmssLayer>,
    /// Parameters
    pub params: HypertreeParams,
    /// Secret seed
    pub sk_seed: [u8; 32],
    /// Public seed
    pub pk_seed: [u8; 32],
}

impl Hypertree {
    /// Build a new hypertree
    /// Note: This is expensive - builds d subtrees with 2^h' leaves each
    pub fn new(sk_seed: [u8; 32], pk_seed: [u8; 32], params: HypertreeParams) -> Self {
        let mut layers = Vec::with_capacity(params.d as usize);

        // Build each layer (in practice, only layer 0 is fully materialized)
        for layer_idx in 0..params.d {
            let layer = build_xmss_layer(&sk_seed, &pk_seed, layer_idx, 0, &params);
            layers.push(layer);
        }

        Self {
            layers,
            params,
            sk_seed,
            pk_seed,
        }
    }

    /// Get the root (public key)
    pub fn root(&self) -> &[u8] {
        &self.layers[self.params.d as usize - 1].root
    }

    /// Sign with the hypertree
    pub fn sign(
        &self,
        msg: &[u8],
        leaf_indices: &[u32],
        randomness: &[u8; 32],
    ) -> Option<HypertreeSignature> {
        if leaf_indices.len() != self.params.d as usize {
            return None;
        }

        // Use top layer's root as pk_root for all layers (enables verification)
        let hypertree_root = &self.layers.last()?.root;

        let mut layer_sigs = Vec::with_capacity(self.params.d as usize);
        let mut current_msg = msg.to_vec();

        for (i, layer) in self.layers.iter().enumerate() {
            let leaf_idx = leaf_indices[i];
            let layer_sig = sign_layer(
                &current_msg,
                layer,
                leaf_idx,
                &self.pk_seed,
                randomness,
                hypertree_root,
            )?;

            // Message for next layer is this layer's root
            current_msg = layer.root.clone();
            layer_sigs.push(layer_sig);
        }

        Some(HypertreeSignature {
            layer_sigs,
            params: self.params,
        })
    }
}

/// Verify a hypertree signature.
/// Uses pk_root (hypertree root) as the pk_root for message digest in ALL layers.
/// Verification is bottom-up: reconstruct each layer's root and use it as the
/// message for the next layer. The final layer must reconstruct to pk_root.
///
/// Uses constant-time comparison for the final root check.
pub fn verify_hypertree(
    msg: &[u8],
    sig: &HypertreeSignature,
    pk_root: &[u8],
    pk_seed: &[u8; 32],
    randomness: &[u8; 32],
) -> bool {
    let d = sig.params.d as usize;
    if sig.layer_sigs.len() != d {
        return false;
    }

    // Layer 0 signs the original message (PORS hash passed in)
    let mut current_msg = msg.to_vec();

    // Track validity using constant-time accumulator
    let mut valid = subtle::Choice::from(1u8);

    // Verify each layer bottom-up
    for i in 0..d {
        let layer_sig = &sig.layer_sigs[i];

        // Reconstruct this layer's root
        let reconstructed_root = match reconstruct_layer_root_v2(
            &current_msg,
            layer_sig,
            pk_root, // Use hypertree root for all layers
            pk_seed,
            i as u32,
            0,
            randomness,
            &sig.params,
        ) {
            Some(root) => root,
            None => return false, // WOTS counter verification failed (early exit acceptable)
        };

        if i == d - 1 {
            // Last layer: constant-time comparison with public key root
            valid &= reconstructed_root.ct_eq(pk_root);
        } else {
            // Intermediate layer: reconstructed root becomes message for next layer
            current_msg = reconstructed_root;
        }
    }

    bool::from(valid)
}

// Re-export helper for WOTS verification
pub mod wots_helpers {
    use super::*;

    impl wots::WotsCParams {
        /// Expose for tree layer
        pub fn message_digest_with_counter(
            &self,
            randomness: &[u8; 32],
            pk_root: &[u8],
            msg: &[u8; 32],
            counter: u32,
        ) -> (Vec<u32>, u32) {
            wots::message_digest_with_counter_raw(randomness, pk_root, msg, counter, self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_hypertree_params() {
        let params = HypertreeParams::LEVEL1_2_30;
        assert_eq!(params.h, 32);
        assert_eq!(params.d, 4);
        assert_eq!(params.h_prime, 8);
        assert_eq!(params.leaves_per_subtree(), 256);
        assert_eq!(params.max_signatures(), 1 << 32);
    }

    #[test]
    fn test_build_xmss_layer_small() {
        // Use smaller parameters for testing
        let params = HypertreeParams {
            h: 8,
            d: 2,
            h_prime: 4, // 16 leaves per subtree
            wots_params: WotsCParams::LEVEL1,
        };

        let sk_seed = [1u8; 32];
        let pk_seed = [2u8; 32];

        let layer = build_xmss_layer(&sk_seed, &pk_seed, 0, 0, &params);

        assert_eq!(layer.wots_keypairs.len(), 16);
        assert_eq!(layer.nodes.len(), 5); // 5 levels (0-4)
        assert_eq!(layer.root.len(), params.wots_params.n);
    }

    #[test]
    fn test_auth_path() {
        let params = HypertreeParams {
            h: 8,
            d: 2,
            h_prime: 4,
            wots_params: WotsCParams::LEVEL1,
        };

        let sk_seed = [1u8; 32];
        let pk_seed = [2u8; 32];

        let layer = build_xmss_layer(&sk_seed, &pk_seed, 0, 0, &params);
        let auth_path = get_auth_path(&layer, 5);

        assert_eq!(auth_path.len(), params.h_prime as usize);
    }

    #[test]
    fn test_sign_layer_small() {
        let params = HypertreeParams {
            h: 8,
            d: 2,
            h_prime: 4,
            wots_params: WotsCParams::LEVEL1,
        };

        let mut rng = rand::thread_rng();
        let mut sk_seed = [0u8; 32];
        let mut pk_seed = [0u8; 32];
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut pk_seed);
        rng.fill_bytes(&mut randomness);

        let layer = build_xmss_layer(&sk_seed, &pk_seed, 0, 0, &params);

        let msg = b"test message for signing";
        // Use layer.root as hypertree_root for single-layer test
        let sig = sign_layer(msg, &layer, 3, &pk_seed, &randomness, &layer.root);

        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.leaf_index, 3);
        assert_eq!(sig.auth_path.len(), params.h_prime as usize);
    }

    #[test]
    fn test_layer_signature_serialization() {
        let params = WotsCParams::LEVEL1;
        let wots_sig = WotsCSignature {
            sig_elements: vec![vec![0xAB; params.n]; params.l],
            counter: 42,
            params,
        };

        let layer_sig = XmssLayerSignature {
            wots_sig,
            auth_path: vec![vec![0xCD; params.n]; 4],
            leaf_index: 7,
        };

        let bytes = layer_sig.to_bytes();
        let parsed = XmssLayerSignature::from_bytes(&bytes, params).unwrap();

        assert_eq!(parsed.leaf_index, 7);
        assert_eq!(parsed.wots_sig.counter, 42);
        assert_eq!(parsed.auth_path.len(), 4);
    }

    #[test]
    fn test_hypertree_signature_serialization() {
        let params = HypertreeParams {
            h: 8,
            d: 2,
            h_prime: 4,
            wots_params: WotsCParams::LEVEL1,
        };

        let wots_params = params.wots_params;
        let layer_sigs: Vec<XmssLayerSignature> = (0..2)
            .map(|i| XmssLayerSignature {
                wots_sig: WotsCSignature {
                    sig_elements: vec![vec![0xAB; wots_params.n]; wots_params.l],
                    counter: i,
                    params: wots_params,
                },
                auth_path: vec![vec![0xCD; wots_params.n]; 4],
                leaf_index: i,
            })
            .collect();

        let sig = HypertreeSignature { layer_sigs, params };

        let bytes = sig.to_bytes();
        let parsed = HypertreeSignature::from_bytes(&bytes, params).unwrap();

        assert_eq!(parsed.layer_sigs.len(), 2);
    }
}
