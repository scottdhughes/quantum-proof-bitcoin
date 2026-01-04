//! PORS+FP: Probabilistic One-time Signature with Fixed Positions
//!
//! Implementation based on "Hash-based Signature Schemes for Bitcoin"
//! (Kudinov & Nick, 2025) Section 4.4.
//!
//! # Key Innovation
//!
//! PORS+FP uses a single Merkle tree with t = k * 2^a leaves.
//! The "Octopus" authentication algorithm minimizes the auth set size
//! by merging sibling paths when multiple selected leaves share ancestors.
//!
//! Counter grinding finds a message digest where the auth set size <= mmax.
//!
//! # Parameters (2^30 signatures target)
//!
//! - k = 10 (selected leaves per signature)
//! - a = 14 (log2 of conceptual leaves per tree)
//! - t = 163,840 (total leaves = k * 2^a)
//! - mmax = ~120 (max auth set nodes, computed dynamically)

use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// PORS+FP parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PorsParams {
    /// Hash output size in bytes (n)
    pub n: usize,
    /// Number of selected leaves per signature (k)
    pub k: usize,
    /// log2 of leaves per conceptual FORS tree (a)
    pub a: usize,
    /// Total leaves = k * 2^a
    pub t: usize,
    /// Max authentication set size
    pub mmax: usize,
}

impl PorsParams {
    /// Parameters for 2^30 signatures (from paper Table 1)
    pub const LEVEL1_2_30: Self = Self {
        n: 16,
        k: 10,
        a: 14,
        t: 10 * (1 << 14), // 163,840
        mmax: 120,         // Tuned for ~same signing time as FORS+C
    };

    /// Compute tree height: ceil(log2(t))
    pub fn tree_height(&self) -> u32 {
        let mut h = 0u32;
        let mut size = 1usize;
        while size < self.t {
            size *= 2;
            h += 1;
        }
        h
    }

    /// Number of bits needed to represent a leaf index
    pub fn index_bits(&self) -> usize {
        (self.t as f64).log2().ceil() as usize
    }
}

/// PORS secret key
#[derive(Clone)]
pub struct PorsSecretKey {
    /// Seed for deriving leaf secrets
    pub sk_seed: [u8; 32],
    /// Public seed for domain separation
    pub pk_seed: [u8; 32],
    /// Parameters
    pub params: PorsParams,
}

impl Drop for PorsSecretKey {
    fn drop(&mut self) {
        self.sk_seed.fill(0);
        self.pk_seed.fill(0);
    }
}

/// PORS public key (tree root)
#[derive(Clone, PartialEq, Eq)]
pub struct PorsPublicKey {
    /// Root hash of the PORS tree
    pub root: Vec<u8>,
    /// Parameters
    pub params: PorsParams,
}

/// PORS+FP signature
#[derive(Clone)]
pub struct PorsSignature {
    /// k revealed leaf values
    pub revealed_leaves: Vec<Vec<u8>>,
    /// Octopus authentication set (variable size, <= mmax)
    pub auth_set: Vec<Vec<u8>>,
    /// Counter used to achieve auth_set.len() <= mmax
    pub counter: u32,
    /// k selected leaf indices
    pub indices: Vec<u32>,
    /// Parameters
    pub params: PorsParams,
}

impl PorsSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.params.n;
        let k = self.params.k;

        // Format: [counter:4] [indices:k*4] [leaves:k*n] [auth_len:2] [auth:auth_len*n]
        let auth_len = self.auth_set.len();
        let mut out = Vec::with_capacity(4 + k * 4 + k * n + 2 + auth_len * n);

        out.extend_from_slice(&self.counter.to_le_bytes());
        for idx in &self.indices {
            out.extend_from_slice(&idx.to_le_bytes());
        }
        for leaf in &self.revealed_leaves {
            out.extend_from_slice(leaf);
        }
        out.extend_from_slice(&(auth_len as u16).to_le_bytes());
        for node in &self.auth_set {
            out.extend_from_slice(node);
        }
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: PorsParams) -> Option<Self> {
        let n = params.n;
        let k = params.k;

        if bytes.len() < 4 + k * 4 + k * n + 2 {
            return None;
        }

        let counter = u32::from_le_bytes(bytes[0..4].try_into().ok()?);

        let mut offset = 4;
        let mut indices = Vec::with_capacity(k);
        for _ in 0..k {
            indices.push(u32::from_le_bytes(
                bytes[offset..offset + 4].try_into().ok()?,
            ));
            offset += 4;
        }

        let mut revealed_leaves = Vec::with_capacity(k);
        for _ in 0..k {
            revealed_leaves.push(bytes[offset..offset + n].to_vec());
            offset += n;
        }

        let auth_len = u16::from_le_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
        offset += 2;

        if bytes.len() < offset + auth_len * n {
            return None;
        }

        let mut auth_set = Vec::with_capacity(auth_len);
        for _ in 0..auth_len {
            auth_set.push(bytes[offset..offset + n].to_vec());
            offset += n;
        }

        Some(Self {
            revealed_leaves,
            auth_set,
            counter,
            indices,
            params,
        })
    }

    /// Serialized size in bytes
    pub fn size(&self) -> usize {
        let n = self.params.n;
        let k = self.params.k;
        4 + k * 4 + k * n + 2 + self.auth_set.len() * n
    }
}

/// Derive a leaf secret from the secret seed
fn derive_leaf_secret(sk_seed: &[u8; 32], pk_seed: &[u8; 32], idx: u32, n: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"PORS_LEAF");
    hasher.update(sk_seed);
    hasher.update(pk_seed);
    hasher.update(&idx.to_le_bytes());
    let hash = hasher.finalize();
    hash[..n].to_vec()
}

/// Hash a leaf value to get leaf node
fn hash_leaf(pk_seed: &[u8; 32], leaf_value: &[u8], idx: u32, n: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"PORS_LEAF_HASH");
    hasher.update(pk_seed);
    hasher.update(&idx.to_le_bytes());
    hasher.update(leaf_value);
    let hash = hasher.finalize();
    hash[..n].to_vec()
}

/// Hash two child nodes to get parent
fn hash_node(
    pk_seed: &[u8; 32],
    left: &[u8],
    right: &[u8],
    level: u32,
    idx: u32,
    n: usize,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"PORS_NODE");
    hasher.update(pk_seed);
    hasher.update(&level.to_le_bytes());
    hasher.update(&idx.to_le_bytes());
    hasher.update(left);
    hasher.update(right);
    let hash = hasher.finalize();
    hash[..n].to_vec()
}

/// Build the full PORS Merkle tree
/// Returns: (root, all_nodes) where all_nodes[level][idx] = hash
pub fn build_tree(sk: &PorsSecretKey) -> (Vec<u8>, Vec<Vec<Vec<u8>>>) {
    let params = &sk.params;
    let height = params.tree_height();
    let t = params.t;
    let n = params.n;

    // Allocate tree levels
    let mut levels: Vec<Vec<Vec<u8>>> = Vec::with_capacity(height as usize + 1);

    // Level 0: leaf nodes
    let mut leaves = Vec::with_capacity(t);
    for i in 0..t {
        let secret = derive_leaf_secret(&sk.sk_seed, &sk.pk_seed, i as u32, n);
        let leaf_hash = hash_leaf(&sk.pk_seed, &secret, i as u32, n);
        leaves.push(leaf_hash);
    }

    // Pad to power of 2 if needed
    let padded_size = 1usize << height;
    while leaves.len() < padded_size {
        let pad_hash = hash_leaf(&sk.pk_seed, &[0u8; 32], leaves.len() as u32, n);
        leaves.push(pad_hash);
    }
    levels.push(leaves);

    // Build internal levels
    for level in 1..=height {
        let prev = &levels[(level - 1) as usize];
        let mut current = Vec::with_capacity(prev.len() / 2);

        for i in 0..prev.len() / 2 {
            let left = &prev[2 * i];
            let right = &prev[2 * i + 1];
            let parent = hash_node(&sk.pk_seed, left, right, level, i as u32, n);
            current.push(parent);
        }
        levels.push(current);
    }

    let root = levels[height as usize][0].clone();
    (root, levels)
}

/// Derive k unique leaf indices from message digest
pub fn derive_indices(digest: &[u8], k: usize, t: usize) -> Vec<u32> {
    let mut indices = Vec::with_capacity(k);
    let mut seen = HashSet::with_capacity(k);

    // Use expanding hash for more randomness if needed
    let mut extended_digest = digest.to_vec();
    let mut round = 0u32;

    while indices.len() < k {
        // Extract index from digest
        let offset = (indices.len() * 4) % extended_digest.len().saturating_sub(3).max(1);

        // Ensure we have enough bytes
        if offset + 4 > extended_digest.len() {
            // Extend digest
            let mut hasher = Sha256::new();
            hasher.update(&extended_digest);
            hasher.update(&round.to_le_bytes());
            extended_digest = hasher.finalize().to_vec();
            round += 1;
            continue;
        }

        let raw = u32::from_le_bytes(extended_digest[offset..offset + 4].try_into().unwrap());
        let idx = raw % (t as u32);

        if !seen.contains(&idx) {
            seen.insert(idx);
            indices.push(idx);
        } else {
            // Hash again for next attempt
            let mut hasher = Sha256::new();
            hasher.update(&extended_digest);
            hasher.update(&round.to_le_bytes());
            extended_digest = hasher.finalize().to_vec();
            round += 1;
        }
    }

    indices
}

/// Compute octopus authentication set for k selected indices
/// Returns the minimal set of sibling hashes needed to verify all paths to root
pub fn octopus_auth(indices: &[u32], tree_levels: &[Vec<Vec<u8>>], height: u32) -> Vec<Vec<u8>> {
    if indices.is_empty() {
        return Vec::new();
    }

    // Sort indices for deterministic traversal order (critical for verify to match)
    let mut layer: Vec<u32> = indices.to_vec();
    layer.sort();
    let mut auth_set: Vec<Vec<u8>> = Vec::new();

    for depth in 0..height {
        let index_set: HashSet<u32> = layer.iter().cloned().collect();
        let mut processed: HashSet<u32> = HashSet::new();
        let mut next_layer: Vec<u32> = Vec::new();

        for &idx in &layer {
            if processed.contains(&idx) {
                continue;
            }

            let sibling = idx ^ 1; // Flip last bit to get sibling

            if index_set.contains(&sibling) {
                // Both siblings are selected - no auth node needed at this level
                processed.insert(sibling);
            } else {
                // Need sibling as auth node
                if (sibling as usize) < tree_levels[depth as usize].len() {
                    auth_set.push(tree_levels[depth as usize][sibling as usize].clone());
                }
            }

            processed.insert(idx);
            next_layer.push(idx >> 1); // Parent index
        }

        // Deduplicate and sort parent indices for consistent traversal
        let mut unique_parents: Vec<u32> = next_layer
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        unique_parents.sort();
        layer = unique_parents;
    }

    auth_set
}

/// Estimate auth set size without building the full set
/// Used for counter grinding to avoid expensive operations
pub fn estimate_auth_size(indices: &[u32], height: u32) -> usize {
    if indices.is_empty() {
        return 0;
    }

    let mut layer: Vec<u32> = indices.to_vec();
    let mut auth_count = 0usize;

    for _depth in 0..height {
        let index_set: HashSet<u32> = layer.iter().cloned().collect();
        let mut processed: HashSet<u32> = HashSet::new();
        let mut next_layer: Vec<u32> = Vec::new();

        for &idx in &layer {
            if processed.contains(&idx) {
                continue;
            }

            let sibling = idx ^ 1;

            if index_set.contains(&sibling) {
                processed.insert(sibling);
            } else {
                auth_count += 1;
            }

            processed.insert(idx);
            next_layer.push(idx >> 1);
        }

        layer = next_layer
            .into_iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
    }

    auth_count
}

/// Compute message digest with counter
fn message_digest(randomness: &[u8; 32], pk_root: &[u8], msg: &[u8; 32], counter: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"PORS_MSG");
    hasher.update(randomness);
    hasher.update(pk_root);
    hasher.update(msg);
    hasher.update(&counter.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Grind counter until auth set size <= mmax
pub fn grind_counter(
    randomness: &[u8; 32],
    pk_root: &[u8],
    msg: &[u8; 32],
    params: &PorsParams,
    max_attempts: u32,
) -> Option<(u32, Vec<u32>)> {
    let height = params.tree_height();

    for counter in 0..max_attempts {
        let digest = message_digest(randomness, pk_root, msg, counter);
        let indices = derive_indices(&digest, params.k, params.t);
        let auth_size = estimate_auth_size(&indices, height);

        if auth_size <= params.mmax {
            return Some((counter, indices));
        }
    }
    None
}

/// Generate PORS keypair
pub fn keygen(
    sk_seed: [u8; 32],
    pk_seed: [u8; 32],
    params: PorsParams,
) -> (PorsSecretKey, PorsPublicKey, Vec<Vec<Vec<u8>>>) {
    let sk = PorsSecretKey {
        sk_seed,
        pk_seed,
        params,
    };

    let (root, tree_levels) = build_tree(&sk);

    let pk = PorsPublicKey { root, params };

    (sk, pk, tree_levels)
}

/// Sign a message using PORS+FP
pub fn sign(
    msg: &[u8; 32],
    sk: &PorsSecretKey,
    tree_levels: &[Vec<Vec<u8>>],
    pk_root: &[u8],
    randomness: &[u8; 32],
) -> Option<PorsSignature> {
    let params = &sk.params;
    let height = params.tree_height();

    // Grind for counter that achieves auth_size <= mmax
    let (counter, indices) = grind_counter(
        randomness,
        pk_root,
        msg,
        params,
        1 << 24, // Max 16M attempts
    )?;

    // Reveal k leaf values
    let mut revealed_leaves = Vec::with_capacity(params.k);
    for &idx in &indices {
        let leaf_secret = derive_leaf_secret(&sk.sk_seed, &sk.pk_seed, idx, params.n);
        revealed_leaves.push(leaf_secret);
    }

    // Build octopus auth set
    let auth_set = octopus_auth(&indices, tree_levels, height);

    Some(PorsSignature {
        revealed_leaves,
        auth_set,
        counter,
        indices,
        params: *params,
    })
}

/// Verify a PORS+FP signature
pub fn verify(
    msg: &[u8; 32],
    sig: &PorsSignature,
    pk: &PorsPublicKey,
    pk_seed: &[u8; 32],
    randomness: &[u8; 32],
) -> bool {
    let params = &sig.params;
    let height = params.tree_height();

    // Recompute message digest and indices
    let digest = message_digest(randomness, &pk.root, msg, sig.counter);
    let expected_indices = derive_indices(&digest, params.k, params.t);

    // Check indices match
    if sig.indices != expected_indices {
        return false;
    }

    // Check auth set size is within bounds
    if sig.auth_set.len() > params.mmax {
        return false;
    }

    // Verify by reconstructing path to root using octopus verification
    octopus_verify(
        &sig.revealed_leaves,
        &sig.indices,
        &sig.auth_set,
        &pk.root,
        pk_seed,
        params,
        height,
    )
}

/// Verify octopus auth path leads to expected root
fn octopus_verify(
    leaves: &[Vec<u8>],
    indices: &[u32],
    auth_set: &[Vec<u8>],
    expected_root: &[u8],
    pk_seed: &[u8; 32],
    params: &PorsParams,
    height: u32,
) -> bool {
    if leaves.len() != indices.len() {
        return false;
    }

    let n = params.n;

    // Compute leaf hashes and sort by index for deterministic traversal
    let mut current_nodes: Vec<(u32, Vec<u8>)> = indices
        .iter()
        .zip(leaves.iter())
        .map(|(&idx, leaf)| (idx, hash_leaf(pk_seed, leaf, idx, n)))
        .collect();
    current_nodes.sort_by_key(|(idx, _)| *idx);

    let mut auth_idx = 0usize;

    for level in 0..height {
        let index_set: HashSet<u32> = current_nodes.iter().map(|(idx, _)| *idx).collect();
        let mut next_nodes: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut processed: HashSet<u32> = HashSet::new();

        for (idx, node) in &current_nodes {
            if processed.contains(idx) {
                continue;
            }

            let sibling_idx = idx ^ 1;
            let parent_idx = idx >> 1;

            let (left, right) = if idx % 2 == 0 {
                // Current node is left child
                let right_node = if index_set.contains(&sibling_idx) {
                    // Find sibling in current nodes
                    current_nodes
                        .iter()
                        .find(|(i, _)| *i == sibling_idx)
                        .map(|(_, n)| n.clone())
                } else {
                    // Use auth set
                    if auth_idx >= auth_set.len() {
                        return false;
                    }
                    let auth_node = auth_set[auth_idx].clone();
                    auth_idx += 1;
                    Some(auth_node)
                };

                match right_node {
                    Some(r) => (node.clone(), r),
                    None => return false,
                }
            } else {
                // Current node is right child
                let left_node = if index_set.contains(&sibling_idx) {
                    current_nodes
                        .iter()
                        .find(|(i, _)| *i == sibling_idx)
                        .map(|(_, n)| n.clone())
                } else {
                    if auth_idx >= auth_set.len() {
                        return false;
                    }
                    let auth_node = auth_set[auth_idx].clone();
                    auth_idx += 1;
                    Some(auth_node)
                };

                match left_node {
                    Some(l) => (l, node.clone()),
                    None => return false,
                }
            };

            if index_set.contains(&sibling_idx) {
                processed.insert(sibling_idx);
            }
            processed.insert(*idx);

            let parent = hash_node(pk_seed, &left, &right, level + 1, parent_idx, n);

            // Only add parent if not already present
            if !next_nodes.iter().any(|(i, _)| *i == parent_idx) {
                next_nodes.push((parent_idx, parent));
            }
        }

        // Sort for consistent traversal order matching octopus_auth
        next_nodes.sort_by_key(|(idx, _)| *idx);
        current_nodes = next_nodes;
    }

    // Should have exactly one node at root
    if current_nodes.len() != 1 {
        return false;
    }

    current_nodes[0].1 == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_tree_height() {
        let params = PorsParams::LEVEL1_2_30;
        let height = params.tree_height();
        // t = 163,840, so height should be 18 (2^18 = 262,144 >= 163,840)
        assert!(height >= 17 && height <= 18);
    }

    #[test]
    fn test_derive_indices() {
        let digest = [0xABu8; 32];
        let indices = derive_indices(&digest, 10, 163840);
        assert_eq!(indices.len(), 10);

        // All indices should be unique
        let unique: HashSet<_> = indices.iter().collect();
        assert_eq!(unique.len(), 10);

        // All indices should be < t
        for idx in &indices {
            assert!(*idx < 163840);
        }
    }

    #[test]
    fn test_estimate_auth_size() {
        // Adjacent indices should share sibling, reducing auth size
        let indices_adjacent = vec![0, 1, 2, 3];
        let indices_spread = vec![0, 100, 200, 300];

        let size_adjacent = estimate_auth_size(&indices_adjacent, 10);
        let size_spread = estimate_auth_size(&indices_spread, 10);

        // Adjacent indices should have smaller auth set
        assert!(size_adjacent <= size_spread);
    }

    #[test]
    fn test_keygen() {
        let params = PorsParams {
            n: 16,
            k: 4,
            a: 4, // Smaller tree for testing: t = 4 * 16 = 64
            t: 64,
            mmax: 20,
        };

        let sk_seed = [1u8; 32];
        let pk_seed = [2u8; 32];

        let (sk, pk, tree_levels) = keygen(sk_seed, pk_seed, params);

        assert_eq!(pk.root.len(), params.n);
        assert!(!tree_levels.is_empty());
    }

    #[test]
    fn test_sign_verify_small() {
        let params = PorsParams {
            n: 16,
            k: 4,
            a: 4, // t = 64
            t: 64,
            mmax: 30,
        };

        let mut rng = rand::thread_rng();
        let mut sk_seed = [0u8; 32];
        let mut pk_seed = [0u8; 32];
        let mut msg = [0u8; 32];
        let mut randomness = [0u8; 32];

        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut pk_seed);
        rng.fill_bytes(&mut msg);
        rng.fill_bytes(&mut randomness);

        let (sk, pk, tree_levels) = keygen(sk_seed, pk_seed, params);

        let sig = sign(&msg, &sk, &tree_levels, &pk.root, &randomness);
        assert!(sig.is_some(), "Signing should succeed");

        let sig = sig.unwrap();
        assert_eq!(sig.revealed_leaves.len(), params.k);
        assert!(sig.auth_set.len() <= params.mmax);

        // Verify the signature
        let valid = verify(&msg, &sig, &pk, &pk_seed, &randomness);
        assert!(valid, "PORS signature should verify");

        // Wrong message should fail
        let mut wrong_msg = msg;
        wrong_msg[0] ^= 1;
        let invalid = verify(&wrong_msg, &sig, &pk, &pk_seed, &randomness);
        assert!(!invalid, "Wrong message should fail verification");
    }

    #[test]
    fn test_signature_serialization() {
        let params = PorsParams {
            n: 16,
            k: 4,
            a: 4,
            t: 64,
            mmax: 30,
        };

        let sig = PorsSignature {
            revealed_leaves: vec![vec![0xAB; 16]; 4],
            auth_set: vec![vec![0xCD; 16]; 10],
            counter: 12345,
            indices: vec![1, 5, 10, 20],
            params,
        };

        let bytes = sig.to_bytes();
        let parsed = PorsSignature::from_bytes(&bytes, params).unwrap();

        assert_eq!(parsed.counter, 12345);
        assert_eq!(parsed.indices, vec![1, 5, 10, 20]);
        assert_eq!(parsed.revealed_leaves.len(), 4);
        assert_eq!(parsed.auth_set.len(), 10);
    }

    #[test]
    fn test_counter_grinding() {
        let params = PorsParams {
            n: 16,
            k: 4,
            a: 4,
            t: 64,
            mmax: 30, // Generous mmax for easy grinding
        };

        let randomness = [0u8; 32];
        let pk_root = [1u8; 16];
        let msg = [2u8; 32];

        let result = grind_counter(&randomness, &pk_root, &msg, &params, 1 << 16);
        assert!(result.is_some(), "Should find valid counter");

        let (counter, indices) = result.unwrap();
        let height = params.tree_height();
        let auth_size = estimate_auth_size(&indices, height);

        assert!(auth_size <= params.mmax);
        println!("Found counter {} with auth_size {}", counter, auth_size);
    }
}
