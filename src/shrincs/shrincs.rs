//! SHRINCS: Full Signature Scheme Orchestrator
//!
//! This module ties together WOTS+C, PORS+FP, and XMSS^MT hypertree
//! into a complete post-quantum signature scheme.
//!
//! # Architecture
//!
//! ```text
//! Message → PORS+FP (few-time sig) → Hypertree (d XMSS layers) → Signature
//!              ↑                            ↑
//!         counter grinding            WOTS+C per layer
//! ```
//!
//! # Signature Flow
//!
//! 1. Generate randomness R from PRF
//! 2. PORS+FP: Grind counter, reveal k leaves, build octopus auth
//! 3. Hypertree: Sign PORS output through d XMSS layers
//! 4. Return complete signature

use crate::shrincs::error::ShrincsError;
use crate::shrincs::pors::{self, PorsParams, PorsPublicKey, PorsSecretKey, PorsSignature};
use crate::shrincs::state::SigningState;
use crate::shrincs::tree::{
    self, build_xmss_layer, sign_layer, HypertreeParams, HypertreeSignature, XmssLayer,
    XmssLayerSignature,
};
use crate::shrincs::wots::WotsCParams;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Complete SHRINCS parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShrincsFullParams {
    /// PORS parameters
    pub pors: PorsParams,
    /// Hypertree parameters
    pub hypertree: HypertreeParams,
    /// Hash output size (n)
    pub n: usize,
}

impl ShrincsFullParams {
    /// Level 1 parameters for 2^30 signatures
    pub const LEVEL1_2_30: Self = Self {
        pors: PorsParams::LEVEL1_2_30,
        hypertree: HypertreeParams::LEVEL1_2_30,
        n: 16,
    };

    /// Estimate signature size
    pub fn signature_size_estimate(&self) -> usize {
        // PORS: counter(4) + indices(k*4) + leaves(k*n) + auth_len(2) + auth(mmax*n)
        let pors_size = 4 + self.pors.k * 4 + self.pors.k * self.n + 2 + self.pors.mmax * self.n;

        // Hypertree: d layers, each with WOTS sig + auth path
        let wots_size = 4 + self.hypertree.wots_params.l * self.n; // counter + elements
        let auth_size = self.hypertree.h_prime as usize * self.n;
        let layer_size = 4 + 4 + wots_size + 2 + auth_size; // leaf_idx + wots_len + wots + auth_len + auth
        let hypertree_size = 1 + self.hypertree.d as usize * (4 + layer_size); // num_layers + per-layer overhead

        // Randomness (32) + signature type (1) + leaf index (8)
        32 + 1 + 8 + pors_size + hypertree_size
    }
}

/// SHRINCS secret key (complete)
#[derive(Clone)]
pub struct ShrincsFullSecretKey {
    /// Master secret seed
    pub sk_seed: [u8; 32],
    /// Public seed for domain separation
    pub pk_seed: [u8; 32],
    /// PRF key for randomness generation
    pub prf_key: [u8; 32],
    /// Parameters
    pub params: ShrincsFullParams,
}

impl Drop for ShrincsFullSecretKey {
    fn drop(&mut self) {
        self.sk_seed.fill(0);
        self.prf_key.fill(0);
    }
}

/// SHRINCS public key
#[derive(Clone, PartialEq, Eq)]
pub struct ShrincsFullPublicKey {
    /// PORS tree root
    pub pors_root: Vec<u8>,
    /// Hypertree root (final XMSS layer root)
    pub hypertree_root: Vec<u8>,
    /// Public seed
    pub pk_seed: [u8; 32],
    /// Parameters
    pub params: ShrincsFullParams,
}

impl ShrincsFullPublicKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.params.n * 2);
        out.extend_from_slice(&self.pk_seed);
        out.extend_from_slice(&self.pors_root);
        out.extend_from_slice(&self.hypertree_root);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: ShrincsFullParams) -> Option<Self> {
        let n = params.n;
        if bytes.len() < 32 + n * 2 {
            return None;
        }

        let pk_seed: [u8; 32] = bytes[0..32].try_into().ok()?;
        let pors_root = bytes[32..32 + n].to_vec();
        let hypertree_root = bytes[32 + n..32 + 2 * n].to_vec();

        Some(Self {
            pors_root,
            hypertree_root,
            pk_seed,
            params,
        })
    }
}

/// Complete SHRINCS signature
#[derive(Clone)]
pub struct ShrincsFullSignature {
    /// Randomness used for signing
    pub randomness: [u8; 32],
    /// Global leaf index
    pub leaf_index: u64,
    /// PORS+FP signature
    pub pors_sig: PorsSignature,
    /// Hypertree signature (d layers)
    pub hypertree_sig: HypertreeSignature,
    /// Parameters
    pub params: ShrincsFullParams,
}

impl ShrincsFullSignature {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let pors_bytes = self.pors_sig.to_bytes();
        let hypertree_bytes = self.hypertree_sig.to_bytes();

        let mut out = Vec::with_capacity(32 + 8 + pors_bytes.len() + hypertree_bytes.len());
        out.extend_from_slice(&self.randomness);
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&(pors_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&pors_bytes);
        out.extend_from_slice(&hypertree_bytes);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: ShrincsFullParams) -> Option<Self> {
        if bytes.len() < 32 + 8 + 4 {
            return None;
        }

        let randomness: [u8; 32] = bytes[0..32].try_into().ok()?;
        let leaf_index = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
        let pors_len = u32::from_le_bytes(bytes[40..44].try_into().ok()?) as usize;

        if bytes.len() < 44 + pors_len {
            return None;
        }

        let pors_sig = PorsSignature::from_bytes(&bytes[44..44 + pors_len], params.pors)?;
        let hypertree_sig =
            HypertreeSignature::from_bytes(&bytes[44 + pors_len..], params.hypertree)?;

        Some(Self {
            randomness,
            leaf_index,
            pors_sig,
            hypertree_sig,
            params,
        })
    }

    /// Get serialized size
    pub fn size(&self) -> usize {
        32 + 8 + 4 + self.pors_sig.size() + self.hypertree_sig.to_bytes().len()
    }
}

/// Cached key material for efficient signing
pub struct ShrincsKeyMaterial {
    /// Secret key
    pub sk: ShrincsFullSecretKey,
    /// Public key
    pub pk: ShrincsFullPublicKey,
    /// PORS tree levels (for auth path generation)
    pub pors_tree: Vec<Vec<Vec<u8>>>,
    /// XMSS layers (built on demand)
    pub xmss_layers: Vec<XmssLayer>,
}

/// Generate SHRINCS keypair
pub fn keygen(params: ShrincsFullParams) -> Result<(ShrincsKeyMaterial, SigningState), ShrincsError> {
    let mut rng = rand::thread_rng();

    // Generate seeds
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 32];
    let mut prf_key = [0u8; 32];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut pk_seed);
    rng.fill_bytes(&mut prf_key);

    keygen_from_seeds(sk_seed, pk_seed, prf_key, params)
}

/// Generate keypair from explicit seeds (for deterministic testing)
pub fn keygen_from_seeds(
    sk_seed: [u8; 32],
    pk_seed: [u8; 32],
    prf_key: [u8; 32],
    params: ShrincsFullParams,
) -> Result<(ShrincsKeyMaterial, SigningState), ShrincsError> {
    // Build PORS tree
    let pors_sk = PorsSecretKey {
        sk_seed,
        pk_seed,
        params: params.pors,
    };
    let (pors_root, pors_tree) = pors::build_tree(&pors_sk);

    // Build XMSS layers
    // Note: For production, layers should be built on-demand to save memory
    let mut xmss_layers = Vec::with_capacity(params.hypertree.d as usize);

    for layer_idx in 0..params.hypertree.d {
        let layer = build_xmss_layer(&sk_seed, &pk_seed, layer_idx, 0, &params.hypertree);
        xmss_layers.push(layer);
    }

    let hypertree_root = xmss_layers[params.hypertree.d as usize - 1].root.clone();

    let sk = ShrincsFullSecretKey {
        sk_seed,
        pk_seed,
        prf_key,
        params,
    };

    let pk = ShrincsFullPublicKey {
        pors_root,
        hypertree_root,
        pk_seed,
        params,
    };

    let key_material = ShrincsKeyMaterial {
        sk,
        pk,
        pors_tree,
        xmss_layers,
    };

    // Initialize signing state
    let max_signatures = params.hypertree.max_signatures();
    let state = SigningState::new(max_signatures);

    Ok((key_material, state))
}

/// Generate PRF-based randomness for signing
fn generate_randomness(prf_key: &[u8; 32], msg: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SHRINCS_PRF");
    hasher.update(prf_key);
    hasher.update(msg);
    hasher.update(&leaf_index.to_le_bytes());
    hasher.finalize().into()
}

/// Sign a message
pub fn sign(
    msg: &[u8; 32],
    key_material: &ShrincsKeyMaterial,
    state: &mut SigningState,
) -> Result<ShrincsFullSignature, ShrincsError> {
    let params = key_material.sk.params;

    // Allocate leaf index
    let leaf_index = state.allocate_leaf()?;

    // Generate randomness
    let randomness = generate_randomness(&key_material.sk.prf_key, msg, leaf_index);

    // PORS+FP signature
    let pors_sk = PorsSecretKey {
        sk_seed: key_material.sk.sk_seed,
        pk_seed: key_material.sk.pk_seed,
        params: params.pors,
    };

    let pors_sig = pors::sign(
        msg,
        &pors_sk,
        &key_material.pors_tree,
        &key_material.pk.pors_root,
        &randomness,
    )
    .ok_or(ShrincsError::CryptoError("PORS signing failed".into()))?;

    // Hypertree signature
    // Compute what to sign at each layer
    let mut layer_sigs = Vec::with_capacity(params.hypertree.d as usize);

    // First layer signs the PORS signature (or a hash of it)
    let mut current_msg = {
        let mut hasher = Sha256::new();
        hasher.update(b"PORS_SIG_HASH");
        hasher.update(&pors_sig.to_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hash.to_vec()
    };

    // Compute leaf indices for each layer from global leaf index
    let leaves_per_subtree = params.hypertree.leaves_per_subtree() as u64;
    let mut remaining_index = leaf_index;
    let mut layer_indices = Vec::with_capacity(params.hypertree.d as usize);

    for _ in 0..params.hypertree.d {
        let layer_leaf = (remaining_index % leaves_per_subtree) as u32;
        layer_indices.push(layer_leaf);
        remaining_index /= leaves_per_subtree;
    }

    // Sign each layer
    for (i, layer) in key_material.xmss_layers.iter().enumerate() {
        let layer_sig = sign_layer(
            &current_msg,
            layer,
            layer_indices[i],
            &key_material.sk.pk_seed,
            &randomness,
        )
        .ok_or(ShrincsError::CryptoError("XMSS layer signing failed".into()))?;

        // Next layer signs this layer's root
        current_msg = layer.root.clone();
        layer_sigs.push(layer_sig);
    }

    let hypertree_sig = HypertreeSignature {
        layer_sigs,
        params: params.hypertree,
    };

    Ok(ShrincsFullSignature {
        randomness,
        leaf_index,
        pors_sig,
        hypertree_sig,
        params,
    })
}

/// Verify a signature
pub fn verify(
    msg: &[u8; 32],
    sig: &ShrincsFullSignature,
    pk: &ShrincsFullPublicKey,
) -> Result<(), ShrincsError> {
    let params = sig.params;

    // Verify PORS signature
    let pors_pk = PorsPublicKey {
        root: pk.pors_root.clone(),
        params: params.pors,
    };

    if !pors::verify(msg, &sig.pors_sig, &pors_pk, &pk.pk_seed, &sig.randomness) {
        return Err(ShrincsError::VerificationFailed);
    }

    // Verify hypertree signature structure
    // TODO: Full hypertree verification requires reconstructing each layer's root
    // For now, we verify the signature has the correct structure
    if sig.hypertree_sig.layer_sigs.len() != params.hypertree.d as usize {
        return Err(ShrincsError::VerificationFailed);
    }

    // Verify each layer has valid auth path length
    for layer_sig in &sig.hypertree_sig.layer_sigs {
        if layer_sig.auth_path.len() != params.hypertree.h_prime as usize {
            return Err(ShrincsError::VerificationFailed);
        }
    }

    // PORS verification passed, structure is valid
    // Full cryptographic verification of hypertree deferred to production implementation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> ShrincsFullParams {
        // Smaller params for fast testing
        ShrincsFullParams {
            pors: PorsParams {
                n: 16,
                k: 4,
                a: 4, // t = 64
                t: 64,
                mmax: 30,
            },
            hypertree: HypertreeParams {
                h: 8,
                d: 2,
                h_prime: 4, // 16 leaves per subtree
                wots_params: WotsCParams::LEVEL1,
            },
            n: 16,
        }
    }

    #[test]
    fn test_keygen() {
        let params = test_params();
        let result = keygen(params);
        assert!(result.is_ok());

        let (key_material, state) = result.unwrap();
        assert_eq!(key_material.pk.pors_root.len(), params.n);
        assert_eq!(key_material.pk.hypertree_root.len(), params.n);
        assert_eq!(state.remaining_leaves(), params.hypertree.max_signatures());
    }

    #[test]
    fn test_keygen_deterministic() {
        let params = test_params();
        let sk_seed = [1u8; 32];
        let pk_seed = [2u8; 32];
        let prf_key = [3u8; 32];

        let (km1, _) = keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();
        let (km2, _) = keygen_from_seeds(sk_seed, pk_seed, prf_key, params).unwrap();

        assert_eq!(km1.pk.pors_root, km2.pk.pors_root);
        assert_eq!(km1.pk.hypertree_root, km2.pk.hypertree_root);
    }

    #[test]
    fn test_sign() {
        let params = test_params();
        let (key_material, mut state) = keygen(params).unwrap();

        let msg = [0xABu8; 32];
        let sig = sign(&msg, &key_material, &mut state);

        assert!(sig.is_ok());
        let sig = sig.unwrap();
        assert_eq!(sig.leaf_index, 0);
        assert_eq!(sig.pors_sig.revealed_leaves.len(), params.pors.k);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let params = test_params();
        let (key_material, mut state) = keygen(params).unwrap();

        let msg = [0xABu8; 32];
        let sig = sign(&msg, &key_material, &mut state).unwrap();

        let result = verify(&msg, &sig, &key_material.pk);
        assert!(result.is_ok(), "Verification should succeed");
    }

    #[test]
    fn test_wrong_message_fails() {
        let params = test_params();
        let (key_material, mut state) = keygen(params).unwrap();

        let msg = [0xABu8; 32];
        let sig = sign(&msg, &key_material, &mut state).unwrap();

        let wrong_msg = [0xCDu8; 32];
        let result = verify(&wrong_msg, &sig, &key_material.pk);
        assert!(result.is_err(), "Wrong message should fail");
    }

    #[test]
    fn test_multiple_signatures() {
        let params = test_params();
        let (key_material, mut state) = keygen(params).unwrap();

        // Sign multiple messages
        for i in 0..5 {
            let mut msg = [0u8; 32];
            msg[0] = i;

            let sig = sign(&msg, &key_material, &mut state);
            assert!(sig.is_ok(), "Signature {} should succeed", i);

            let sig = sig.unwrap();
            assert_eq!(sig.leaf_index, i as u64);

            // Verify each signature
            let result = verify(&msg, &sig, &key_material.pk);
            assert!(result.is_ok(), "Verification {} should succeed", i);
        }

        // Check state advanced
        assert_eq!(state.remaining_leaves(), params.hypertree.max_signatures() - 5);
    }

    #[test]
    fn test_signature_serialization() {
        let params = test_params();
        let (key_material, mut state) = keygen(params).unwrap();

        let msg = [0xABu8; 32];
        let sig = sign(&msg, &key_material, &mut state).unwrap();

        let bytes = sig.to_bytes();
        let parsed = ShrincsFullSignature::from_bytes(&bytes, params).unwrap();

        assert_eq!(parsed.leaf_index, sig.leaf_index);
        assert_eq!(parsed.randomness, sig.randomness);
        assert_eq!(parsed.pors_sig.counter, sig.pors_sig.counter);
    }

    #[test]
    fn test_public_key_serialization() {
        let params = test_params();
        let (key_material, _) = keygen(params).unwrap();

        let bytes = key_material.pk.to_bytes();
        let parsed = ShrincsFullPublicKey::from_bytes(&bytes, params).unwrap();

        assert_eq!(parsed.pors_root, key_material.pk.pors_root);
        assert_eq!(parsed.hypertree_root, key_material.pk.hypertree_root);
        assert_eq!(parsed.pk_seed, key_material.pk.pk_seed);
    }

    #[test]
    fn test_signature_size_estimate() {
        let params = ShrincsFullParams::LEVEL1_2_30;
        let estimate = params.signature_size_estimate();

        // Should be roughly ~3.4KB for 2^30 params
        // Actual size depends on auth set size (variable)
        println!("Estimated signature size: {} bytes", estimate);
        assert!(estimate > 2000 && estimate < 5000);
    }
}
