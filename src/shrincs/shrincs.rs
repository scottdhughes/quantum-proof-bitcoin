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
#[allow(unused_imports)]
use crate::shrincs::sphincs_fallback::{
    self, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES, SPHINCS_SK_BYTES, sphincs_pk_hash,
};
use crate::shrincs::state::SigningState;
use crate::shrincs::tree::{
    HypertreeParams, HypertreeSignature, XmssLayer, build_xmss_layer, sign_layer, verify_hypertree,
};
#[allow(unused_imports)]
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

// ============================================================================
// Extended Key Material with SPHINCS+ Fallback
// ============================================================================

/// Extended key material including SPHINCS+ fallback keys
///
/// When the stateful XMSS tree is exhausted or state is corrupted,
/// the SPHINCS+ fallback provides stateless signing capability.
pub struct ShrincsExtendedKeyMaterial {
    /// Base stateful key material (PORS + XMSS hypertree)
    pub base: ShrincsKeyMaterial,
    /// SPHINCS+ fallback secret key (64 bytes)
    pub sphincs_sk: Vec<u8>,
    /// SPHINCS+ fallback public key (32 bytes)
    pub sphincs_pk: Vec<u8>,
}

/// Extended public key with SPHINCS+ fallback info
#[derive(Clone, PartialEq, Eq)]
pub struct ShrincsExtendedPublicKey {
    /// Base public key
    pub base: ShrincsFullPublicKey,
    /// Hash of SPHINCS+ public key (32 bytes)
    /// Full pk must be provided separately for fallback verification
    pub sphincs_pk_hash: [u8; 32],
}

impl ShrincsExtendedPublicKey {
    /// Serialize to bytes (fixed 96 bytes: base + sphincs_pk_hash)
    pub fn to_bytes(&self) -> Vec<u8> {
        let base_bytes = self.base.to_bytes();
        let mut out = Vec::with_capacity(base_bytes.len() + 32);
        out.extend_from_slice(&base_bytes);
        out.extend_from_slice(&self.sphincs_pk_hash);
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: ShrincsFullParams) -> Option<Self> {
        let n = params.n;
        let base_len = 32 + n * 2;
        if bytes.len() < base_len + 32 {
            return None;
        }

        let base = ShrincsFullPublicKey::from_bytes(&bytes[..base_len], params)?;
        let sphincs_pk_hash: [u8; 32] = bytes[base_len..base_len + 32].try_into().ok()?;

        Some(Self {
            base,
            sphincs_pk_hash,
        })
    }

    /// Verify that a provided SPHINCS+ public key matches the stored hash
    pub fn verify_sphincs_pk(&self, pk: &[u8]) -> bool {
        sphincs_pk_hash(pk) == self.sphincs_pk_hash
    }
}

// ============================================================================
// Unified Signature (Stateful or Fallback)
// ============================================================================

/// Signature type byte for wire format
const SIG_TYPE_STATEFUL: u8 = 0x00;
const SIG_TYPE_FALLBACK: u8 = 0x01;

/// Unified signature that can be either stateful or fallback
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ShrincsUnifiedSignature {
    /// Stateful PORS+XMSS signature (~3.4KB)
    Stateful(ShrincsFullSignature),
    /// SPHINCS+ fallback signature (~7.8KB)
    Fallback {
        /// The SPHINCS+ signature bytes
        signature: Vec<u8>,
        /// Reserved for future use (e.g., rotation counter)
        reserved: u32,
    },
}

impl ShrincsUnifiedSignature {
    /// Check if this is a fallback signature
    pub fn is_fallback(&self) -> bool {
        matches!(self, ShrincsUnifiedSignature::Fallback { .. })
    }

    /// Get serialized size
    pub fn size(&self) -> usize {
        match self {
            ShrincsUnifiedSignature::Stateful(sig) => 1 + sig.size(),
            ShrincsUnifiedSignature::Fallback { signature, .. } => 1 + 4 + signature.len(),
        }
    }

    /// Serialize to bytes with type prefix
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            ShrincsUnifiedSignature::Stateful(sig) => {
                let inner = sig.to_bytes();
                let mut out = Vec::with_capacity(1 + inner.len());
                out.push(SIG_TYPE_STATEFUL);
                out.extend_from_slice(&inner);
                out
            }
            ShrincsUnifiedSignature::Fallback {
                signature,
                reserved,
            } => {
                let mut out = Vec::with_capacity(1 + 4 + signature.len());
                out.push(SIG_TYPE_FALLBACK);
                out.extend_from_slice(&reserved.to_le_bytes());
                out.extend_from_slice(signature);
                out
            }
        }
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: ShrincsFullParams) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }

        match bytes[0] {
            SIG_TYPE_STATEFUL => {
                let sig = ShrincsFullSignature::from_bytes(&bytes[1..], params)?;
                Some(ShrincsUnifiedSignature::Stateful(sig))
            }
            SIG_TYPE_FALLBACK => {
                if bytes.len() < 5 {
                    return None;
                }
                let reserved = u32::from_le_bytes(bytes[1..5].try_into().ok()?);
                let signature = bytes[5..].to_vec();
                Some(ShrincsUnifiedSignature::Fallback {
                    signature,
                    reserved,
                })
            }
            _ => None,
        }
    }
}

/// Generate SHRINCS keypair
pub fn keygen(
    params: ShrincsFullParams,
) -> Result<(ShrincsKeyMaterial, SigningState), ShrincsError> {
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

// ============================================================================
// Extended Keygen with SPHINCS+ Fallback
// ============================================================================

/// Generate SHRINCS keypair with SPHINCS+ fallback keys
///
/// This is the recommended keygen for production use. It generates both:
/// - Stateful PORS+XMSS keys (efficient, ~3.4KB signatures)
/// - SPHINCS+ fallback keys (stateless, ~7.8KB signatures)
///
/// # Returns
/// * Extended key material with both key types
/// * Initial signing state
/// * Extended public key (with SPHINCS+ pk hash)
#[cfg(feature = "shrincs-dev")]
pub fn keygen_with_fallback(
    params: ShrincsFullParams,
) -> Result<
    (
        ShrincsExtendedKeyMaterial,
        SigningState,
        ShrincsExtendedPublicKey,
    ),
    ShrincsError,
> {
    let mut rng = rand::thread_rng();

    // Generate seeds
    let mut sk_seed = [0u8; 32];
    let mut pk_seed = [0u8; 32];
    let mut prf_key = [0u8; 32];
    rng.fill_bytes(&mut sk_seed);
    rng.fill_bytes(&mut pk_seed);
    rng.fill_bytes(&mut prf_key);

    keygen_with_fallback_from_seeds(sk_seed, pk_seed, prf_key, params)
}

/// Generate extended keypair from explicit seeds (for deterministic testing)
#[cfg(feature = "shrincs-dev")]
pub fn keygen_with_fallback_from_seeds(
    sk_seed: [u8; 32],
    pk_seed: [u8; 32],
    prf_key: [u8; 32],
    params: ShrincsFullParams,
) -> Result<
    (
        ShrincsExtendedKeyMaterial,
        SigningState,
        ShrincsExtendedPublicKey,
    ),
    ShrincsError,
> {
    // Generate base SHRINCS keys
    let (base, state) = keygen_from_seeds(sk_seed, pk_seed, prf_key, params)?;

    // Generate SPHINCS+ fallback keys
    let (sphincs_pk, sphincs_sk) = sphincs_fallback::sphincs_keygen()?;

    // Compute SPHINCS+ pk hash for embedding in extended public key
    let pk_hash = sphincs_pk_hash(&sphincs_pk);

    let extended_pk = ShrincsExtendedPublicKey {
        base: base.pk.clone(),
        sphincs_pk_hash: pk_hash,
    };

    let extended_material = ShrincsExtendedKeyMaterial {
        base,
        sphincs_sk,
        sphincs_pk,
    };

    Ok((extended_material, state, extended_pk))
}

/// Stub when feature is disabled
#[cfg(not(feature = "shrincs-dev"))]
pub fn keygen_with_fallback(
    _params: ShrincsFullParams,
) -> Result<
    (
        ShrincsExtendedKeyMaterial,
        SigningState,
        ShrincsExtendedPublicKey,
    ),
    ShrincsError,
> {
    Err(ShrincsError::NotImplemented(
        "keygen_with_fallback requires shrincs-dev feature",
    ))
}

/// Stub when feature is disabled
#[cfg(not(feature = "shrincs-dev"))]
pub fn keygen_with_fallback_from_seeds(
    _sk_seed: [u8; 32],
    _pk_seed: [u8; 32],
    _prf_key: [u8; 32],
    _params: ShrincsFullParams,
) -> Result<
    (
        ShrincsExtendedKeyMaterial,
        SigningState,
        ShrincsExtendedPublicKey,
    ),
    ShrincsError,
> {
    Err(ShrincsError::NotImplemented(
        "keygen_with_fallback_from_seeds requires shrincs-dev feature",
    ))
}

// ============================================================================
// Auto-Fallback Signing
// ============================================================================

/// Sign with automatic fallback to SPHINCS+
///
/// Tries stateful signing first. On state exhaustion or `force_fallback`,
/// uses SPHINCS+ for stateless signing.
///
/// # Arguments
/// * `msg` - 32-byte message (typically transaction hash)
/// * `key_material` - Extended key material with fallback keys
/// * `state` - Mutable signing state (not consumed on fallback)
/// * `force_fallback` - If true, skip stateful signing and use SPHINCS+
///
/// # Returns
/// * `ShrincsUnifiedSignature::Stateful` - Normal stateful signature
/// * `ShrincsUnifiedSignature::Fallback` - SPHINCS+ signature (on exhaustion or forced)
#[cfg(feature = "shrincs-dev")]
pub fn sign_auto(
    msg: &[u8; 32],
    key_material: &ShrincsExtendedKeyMaterial,
    state: &mut SigningState,
    force_fallback: bool,
) -> Result<ShrincsUnifiedSignature, ShrincsError> {
    // Check for forced fallback mode
    if force_fallback {
        return sign_fallback(msg, key_material);
    }

    // Try stateful signing
    match sign(msg, &key_material.base, state) {
        Ok(sig) => Ok(ShrincsUnifiedSignature::Stateful(sig)),
        Err(ShrincsError::StateExhausted) | Err(ShrincsError::StateCorrupted(_)) => {
            // Fall back to SPHINCS+
            sign_fallback(msg, key_material)
        }
        Err(e) => Err(e),
    }
}

/// Sign using SPHINCS+ fallback directly
#[cfg(feature = "shrincs-dev")]
fn sign_fallback(
    msg: &[u8; 32],
    key_material: &ShrincsExtendedKeyMaterial,
) -> Result<ShrincsUnifiedSignature, ShrincsError> {
    let signature = sphincs_fallback::sphincs_sign(msg, &key_material.sphincs_sk)?;
    Ok(ShrincsUnifiedSignature::Fallback {
        signature,
        reserved: 0,
    })
}

/// Stub when feature is disabled
#[cfg(not(feature = "shrincs-dev"))]
pub fn sign_auto(
    _msg: &[u8; 32],
    _key_material: &ShrincsExtendedKeyMaterial,
    _state: &mut SigningState,
    _force_fallback: bool,
) -> Result<ShrincsUnifiedSignature, ShrincsError> {
    Err(ShrincsError::NotImplemented(
        "sign_auto requires shrincs-dev feature",
    ))
}

// ============================================================================
// Unified Verification
// ============================================================================

/// Verify a unified signature (stateful or fallback)
///
/// # Arguments
/// * `msg` - Original 32-byte message
/// * `sig` - Unified signature
/// * `pk` - Extended public key (contains SPHINCS+ pk hash)
/// * `sphincs_pk` - Full SPHINCS+ public key (required for fallback verification)
///
/// # Returns
/// * `Ok(())` on valid signature
/// * `Err` on invalid signature or missing data
#[cfg(feature = "shrincs-dev")]
pub fn verify_unified(
    msg: &[u8; 32],
    sig: &ShrincsUnifiedSignature,
    pk: &ShrincsExtendedPublicKey,
    sphincs_pk: Option<&[u8]>,
) -> Result<(), ShrincsError> {
    match sig {
        ShrincsUnifiedSignature::Stateful(stateful_sig) => {
            // Verify using base SHRINCS verification
            verify(msg, stateful_sig, &pk.base)
        }
        ShrincsUnifiedSignature::Fallback { signature, .. } => {
            // SPHINCS+ verification requires the full public key
            let sphincs_pk = sphincs_pk.ok_or_else(|| {
                ShrincsError::InvalidPublicKey(
                    "SPHINCS+ public key required for fallback verification".into(),
                )
            })?;

            // Verify the provided pk matches the stored hash
            if !pk.verify_sphincs_pk(sphincs_pk) {
                return Err(ShrincsError::InvalidPublicKey(
                    "SPHINCS+ public key does not match stored hash".into(),
                ));
            }

            // Verify SPHINCS+ signature
            sphincs_fallback::sphincs_verify(msg, signature, sphincs_pk)
        }
    }
}

/// Stub when feature is disabled
#[cfg(not(feature = "shrincs-dev"))]
pub fn verify_unified(
    _msg: &[u8; 32],
    _sig: &ShrincsUnifiedSignature,
    _pk: &ShrincsExtendedPublicKey,
    _sphincs_pk: Option<&[u8]>,
) -> Result<(), ShrincsError> {
    Err(ShrincsError::NotImplemented(
        "verify_unified requires shrincs-dev feature",
    ))
}

/// Generate PRF-based randomness for signing
fn generate_randomness(prf_key: &[u8; 32], msg: &[u8; 32], leaf_index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SHRINCS_PRF");
    hasher.update(prf_key);
    hasher.update(msg);
    hasher.update(leaf_index.to_le_bytes());
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
        hasher.update(pors_sig.to_bytes());
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

    // Sign each layer (use hypertree_root as pk_root for all layers)
    let hypertree_root = &key_material.pk.hypertree_root;
    for (i, layer) in key_material.xmss_layers.iter().enumerate() {
        let layer_sig = sign_layer(
            &current_msg,
            layer,
            layer_indices[i],
            &key_material.sk.pk_seed,
            &randomness,
            hypertree_root,
        )
        .ok_or(ShrincsError::CryptoError(
            "XMSS layer signing failed".into(),
        ))?;

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

    // Compute PORS signature hash (same as signing)
    let pors_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"PORS_SIG_HASH");
        hasher.update(sig.pors_sig.to_bytes());
        hasher.finalize().to_vec()
    };

    // Verify hypertree cryptographically
    if !verify_hypertree(
        &pors_hash,
        &sig.hypertree_sig,
        &pk.hypertree_root,
        &pk.pk_seed,
        &sig.randomness,
    ) {
        return Err(ShrincsError::VerificationFailed);
    }

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
        assert_eq!(
            state.remaining_leaves(),
            params.hypertree.max_signatures() - 5
        );
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

    // ========================================================================
    // SPHINCS+ Fallback Tests (require shrincs-dev feature)
    // ========================================================================

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_keygen_with_fallback() {
        let params = test_params();
        let result = keygen_with_fallback(params);
        assert!(result.is_ok(), "keygen_with_fallback should succeed");

        let (key_material, state, ext_pk) = result.unwrap();

        // Base keys should be valid
        assert_eq!(key_material.base.pk.pors_root.len(), params.n);
        assert_eq!(key_material.base.pk.hypertree_root.len(), params.n);

        // SPHINCS+ keys should have correct sizes
        assert_eq!(key_material.sphincs_pk.len(), SPHINCS_PK_BYTES);
        assert_eq!(key_material.sphincs_sk.len(), SPHINCS_SK_BYTES);

        // Extended pk should match
        assert_eq!(ext_pk.base.pors_root, key_material.base.pk.pors_root);

        // SPHINCS+ pk hash should be correct
        assert!(ext_pk.verify_sphincs_pk(&key_material.sphincs_pk));

        assert_eq!(state.remaining_leaves(), params.hypertree.max_signatures());
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sign_auto_stateful() {
        let params = test_params();
        let (key_material, mut state, ext_pk) = keygen_with_fallback(params).unwrap();

        let msg = [0xABu8; 32];

        // Normal signing should use stateful path
        let sig = sign_auto(&msg, &key_material, &mut state, false).unwrap();

        assert!(
            !sig.is_fallback(),
            "Normal signing should produce stateful signature"
        );

        // Verify the signature
        let result = verify_unified(&msg, &sig, &ext_pk, Some(&key_material.sphincs_pk));
        assert!(result.is_ok(), "Stateful signature should verify");

        // Check state advanced
        assert_eq!(
            state.remaining_leaves(),
            params.hypertree.max_signatures() - 1
        );
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_sign_auto_forced_fallback() {
        let params = test_params();
        let (key_material, mut state, ext_pk) = keygen_with_fallback(params).unwrap();

        let msg = [0xCDu8; 32];

        // Forced fallback should use SPHINCS+
        let sig = sign_auto(&msg, &key_material, &mut state, true).unwrap();

        assert!(
            sig.is_fallback(),
            "Forced fallback should produce SPHINCS+ signature"
        );

        // Verify the signature (requires SPHINCS+ pk)
        let result = verify_unified(&msg, &sig, &ext_pk, Some(&key_material.sphincs_pk));
        assert!(result.is_ok(), "Fallback signature should verify");

        // State should NOT advance (fallback doesn't consume leaves)
        assert_eq!(
            state.remaining_leaves(),
            params.hypertree.max_signatures(),
            "Fallback signing should not consume state"
        );
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_fallback_wrong_message_fails() {
        let params = test_params();
        let (key_material, mut state, ext_pk) = keygen_with_fallback(params).unwrap();

        let msg = [0xEFu8; 32];
        let wrong_msg = [0x12u8; 32];

        let sig = sign_auto(&msg, &key_material, &mut state, true).unwrap();
        assert!(sig.is_fallback());

        // Verification with wrong message should fail
        let result = verify_unified(&wrong_msg, &sig, &ext_pk, Some(&key_material.sphincs_pk));
        assert!(
            result.is_err(),
            "Wrong message should fail fallback verification"
        );
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_fallback_wrong_key_fails() {
        let params = test_params();
        let (key_material1, mut state1, ext_pk1) = keygen_with_fallback(params).unwrap();
        let (key_material2, _, _) = keygen_with_fallback(params).unwrap();

        let msg = [0x34u8; 32];
        let sig = sign_auto(&msg, &key_material1, &mut state1, true).unwrap();

        // Verification with different SPHINCS+ pk should fail (hash mismatch)
        let result = verify_unified(&msg, &sig, &ext_pk1, Some(&key_material2.sphincs_pk));
        assert!(
            result.is_err(),
            "Wrong SPHINCS+ key should fail verification"
        );
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_fallback_missing_sphincs_pk() {
        let params = test_params();
        let (key_material, mut state, ext_pk) = keygen_with_fallback(params).unwrap();

        let msg = [0x56u8; 32];
        let sig = sign_auto(&msg, &key_material, &mut state, true).unwrap();

        // Fallback verification without SPHINCS+ pk should fail
        let result = verify_unified(&msg, &sig, &ext_pk, None);
        assert!(result.is_err(), "Missing SPHINCS+ pk should fail");
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_unified_signature_serialization() {
        let params = test_params();
        let (key_material, mut state, ext_pk) = keygen_with_fallback(params).unwrap();

        let msg = [0x78u8; 32];

        // Test stateful signature serialization
        let stateful_sig = sign_auto(&msg, &key_material, &mut state, false).unwrap();
        let stateful_bytes = stateful_sig.to_bytes();
        let parsed_stateful = ShrincsUnifiedSignature::from_bytes(&stateful_bytes, params).unwrap();
        assert!(!parsed_stateful.is_fallback());
        assert!(
            verify_unified(
                &msg,
                &parsed_stateful,
                &ext_pk,
                Some(&key_material.sphincs_pk)
            )
            .is_ok()
        );

        // Test fallback signature serialization
        let fallback_sig = sign_auto(&msg, &key_material, &mut state, true).unwrap();
        let fallback_bytes = fallback_sig.to_bytes();
        let parsed_fallback = ShrincsUnifiedSignature::from_bytes(&fallback_bytes, params).unwrap();
        assert!(parsed_fallback.is_fallback());
        assert!(
            verify_unified(
                &msg,
                &parsed_fallback,
                &ext_pk,
                Some(&key_material.sphincs_pk)
            )
            .is_ok()
        );
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_signature_size_comparison() {
        let params = test_params();
        let (key_material, mut state, _) = keygen_with_fallback(params).unwrap();

        let msg = [0x9Au8; 32];

        // Get stateful signature
        let stateful_sig = sign_auto(&msg, &key_material, &mut state, false).unwrap();
        let stateful_size = stateful_sig.size();

        // Get fallback signature
        let fallback_sig = sign_auto(&msg, &key_material, &mut state, true).unwrap();
        let fallback_size = fallback_sig.size();

        println!("Stateful signature size: {} bytes", stateful_size);
        println!("Fallback signature size: {} bytes", fallback_size);

        // Fallback should be larger (~7.8KB vs ~3.4KB)
        assert!(
            fallback_size > stateful_size,
            "Fallback sig ({}) should be larger than stateful sig ({})",
            fallback_size,
            stateful_size
        );

        // Fallback should be approximately SPHINCS signature size
        assert!(
            fallback_size > 7000 && fallback_size < 8500,
            "Fallback size {} should be ~7.8KB",
            fallback_size
        );
    }

    #[test]
    #[cfg(feature = "shrincs-dev")]
    fn test_extended_public_key_serialization() {
        let params = test_params();
        let (key_material, _, ext_pk) = keygen_with_fallback(params).unwrap();

        let bytes = ext_pk.to_bytes();
        let parsed = ShrincsExtendedPublicKey::from_bytes(&bytes, params).unwrap();

        assert_eq!(parsed.base.pors_root, ext_pk.base.pors_root);
        assert_eq!(parsed.base.hypertree_root, ext_pk.base.hypertree_root);
        assert_eq!(parsed.sphincs_pk_hash, ext_pk.sphincs_pk_hash);

        // Verify SPHINCS+ pk still works
        assert!(parsed.verify_sphincs_pk(&key_material.sphincs_pk));
    }
}
