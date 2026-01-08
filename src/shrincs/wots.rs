//! WOTS+C: Winternitz One-Time Signature with Counter Grinding
//!
//! Implementation based on "Hash-based Signature Schemes for Bitcoin"
//! (Kudinov & Nick, 2025) Section 3.4.
//!
//! # Key Innovation
//!
//! WOTS+C eliminates checksum chains by grinding a counter until the
//! message digest's base-w digits sum to exactly S_{w,n} (target sum).
//! This reduces signature size by removing l2 checksum chains.
//!
//! # Parameters (Level 1, 128-bit security)
//!
//! - n = 16 bytes (hash output)
//! - w = 256 (Winternitz parameter)
//! - l = 16 chains (no checksum chains!)
//! - S_{w,n} = 2040 (target chain sum)
//! - Signature: 16 * 16 = 256 bytes + 4 byte counter = 260 bytes

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// WOTS+C parameters
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WotsCParams {
    /// Hash output size in bytes (n)
    pub n: usize,
    /// Winternitz parameter (must be power of 2)
    pub w: u32,
    /// Number of chains: l = 8*n / log2(w)
    pub l: usize,
    /// Target chain sum S_{w,n}
    /// Verification cost = (w-1)*l - S_{w,n} hash calls
    pub target_sum: u32,
}

impl WotsCParams {
    /// Level 1 (128-bit) parameters from the paper
    pub const LEVEL1: Self = Self {
        n: 16,
        w: 256,
        l: 16,            // 128 / 8 = 16
        target_sum: 2040, // From paper Table 1
    };

    /// Level 3 (192-bit) parameters
    pub const LEVEL3: Self = Self {
        n: 24,
        w: 256,
        l: 24,            // 192 / 8 = 24
        target_sum: 3060, // Scaled from Level 1: 2040 * 24/16 = 3060
    };

    /// Calculate log2(w)
    #[inline]
    pub const fn log_w(&self) -> u32 {
        match self.w {
            16 => 4,
            256 => 8,
            _ => 8, // Default to 8 for w=256
        }
    }

    /// Expected verification cost in hash calls
    /// = (w-1)*l - S_{w,n}
    pub const fn verify_cost(&self) -> u32 {
        (self.w - 1) * (self.l as u32) - self.target_sum
    }
}

/// WOTS+C secret key: l seeds of n bytes each
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WotsCSecretKey {
    /// Secret seeds for each chain
    pub seeds: Vec<[u8; 32]>, // Using 32 bytes internally, truncate to n
    /// Parameters used
    #[zeroize(skip)]
    pub params: WotsCParams,
}

/// WOTS+C public key: l chain tips of n bytes each
#[derive(Clone, PartialEq, Eq)]
pub struct WotsCPublicKey {
    /// Chain tips (public key elements)
    pub chain_tips: Vec<Vec<u8>>,
    /// Parameters used
    pub params: WotsCParams,
}

/// WOTS+C signature: l chain values + counter
#[derive(Clone)]
pub struct WotsCSignature {
    /// Signature elements (l values of n bytes each)
    pub sig_elements: Vec<Vec<u8>>,
    /// Counter used to achieve target sum
    pub counter: u32,
    /// Parameters used
    pub params: WotsCParams,
}

impl WotsCSignature {
    /// Serialize to bytes: [counter:4] [sig_elements:l*n]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.params.l * self.params.n);
        out.extend_from_slice(&self.counter.to_le_bytes());
        for elem in &self.sig_elements {
            out.extend_from_slice(elem);
        }
        out
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8], params: WotsCParams) -> Option<Self> {
        if bytes.len() < 4 + params.l * params.n {
            return None;
        }
        let counter = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let mut sig_elements = Vec::with_capacity(params.l);
        let mut offset = 4;
        for _ in 0..params.l {
            sig_elements.push(bytes[offset..offset + params.n].to_vec());
            offset += params.n;
        }
        Some(Self {
            sig_elements,
            counter,
            params,
        })
    }

    /// Serialized size in bytes
    pub const fn size(params: &WotsCParams) -> usize {
        4 + params.l * params.n
    }
}

/// Tweakable hash function T_k(addr, input)
/// Using SHA-256 with domain separation
fn tweakable_hash(pk_seed: &[u8], addr: &Address, input: &[u8], n: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pk_seed);
    hasher.update(addr.to_bytes());
    hasher.update(input);
    let hash = hasher.finalize();
    hash[..n].to_vec()
}

/// Chain address for domain separation
#[derive(Clone, Copy)]
pub struct Address {
    /// Layer in the tree (0 for WOTS)
    pub layer: u32,
    /// Tree index
    pub tree: u64,
    /// Key pair index within tree
    pub keypair: u32,
    /// Chain index within keypair
    pub chain: u32,
    /// Position within chain
    pub hash_idx: u32,
}

impl Address {
    pub fn new(layer: u32, tree: u64, keypair: u32, chain: u32, hash_idx: u32) -> Self {
        Self {
            layer,
            tree,
            keypair,
            chain,
            hash_idx,
        }
    }

    pub fn to_bytes(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0..4].copy_from_slice(&self.layer.to_be_bytes());
        out[4..12].copy_from_slice(&self.tree.to_be_bytes());
        out[12..16].copy_from_slice(&self.keypair.to_be_bytes());
        out[16..18].copy_from_slice(&(self.chain as u16).to_be_bytes());
        out[18..22].copy_from_slice(&self.hash_idx.to_be_bytes());
        out
    }
}

/// Generate a single hash chain from seed
/// chain[i] = T(addr_i, chain[i-1])
fn gen_chain(
    pk_seed: &[u8],
    input: &[u8],
    start: u32,
    steps: u32,
    addr: &mut Address,
    n: usize,
) -> Vec<u8> {
    let mut value = input.to_vec();
    for i in start..start + steps {
        addr.hash_idx = i;
        value = tweakable_hash(pk_seed, addr, &value, n);
    }
    value
}

/// Convert bytes to base-w representation
fn base_w(input: &[u8], w: u32, out_len: usize) -> Vec<u32> {
    let log_w = match w {
        16 => 4,
        256 => 8,
        _ => panic!("Unsupported w"),
    };

    let mut result = Vec::with_capacity(out_len);
    let mut bits_in_buffer = 0u32;
    let mut buffer = 0u64;
    let mut byte_idx = 0;

    while result.len() < out_len {
        // Load more bits if needed
        while bits_in_buffer < log_w && byte_idx < input.len() {
            buffer = (buffer << 8) | (input[byte_idx] as u64);
            bits_in_buffer += 8;
            byte_idx += 1;
        }

        if bits_in_buffer >= log_w {
            bits_in_buffer -= log_w;
            result.push(((buffer >> bits_in_buffer) & (w as u64 - 1)) as u32);
        } else {
            // Pad with zeros if we run out of input
            result.push(0);
        }
    }

    result
}

/// Compute message digest with counter for WOTS+C
/// Returns (digest_as_base_w, sum_of_digits)
fn message_digest_with_counter(
    randomness: &[u8; 32],
    pk_root: &[u8],
    msg: &[u8; 32],
    counter: u32,
    params: &WotsCParams,
) -> (Vec<u32>, u32) {
    // H_msg = Hash(R || pk_root || msg || counter)
    let mut hasher = Sha256::new();
    hasher.update(randomness);
    hasher.update(pk_root);
    hasher.update(msg);
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();

    // Convert to base-w
    let digits = base_w(&digest, params.w, params.l);
    let sum: u32 = digits.iter().sum();

    (digits, sum)
}

/// Public version of message_digest_with_counter for tree verification
pub fn message_digest_with_counter_raw(
    randomness: &[u8; 32],
    pk_root: &[u8],
    msg: &[u8; 32],
    counter: u32,
    params: &WotsCParams,
) -> (Vec<u32>, u32) {
    message_digest_with_counter(randomness, pk_root, msg, counter, params)
}

/// Public chain function for verification (uses pk_seed for tweaking)
pub fn gen_chain_public(
    pk_seed: &[u8],
    input: &[u8],
    start: u32,
    steps: u32,
    addr: &mut Address,
    n: usize,
) -> Vec<u8> {
    gen_chain(pk_seed, input, start, steps, addr, n)
}

/// Find counter that achieves target sum (counter grinding)
/// Returns (counter, message_digits)
pub fn grind_counter(
    randomness: &[u8; 32],
    pk_root: &[u8],
    msg: &[u8; 32],
    params: &WotsCParams,
    max_attempts: u32,
) -> Option<(u32, Vec<u32>)> {
    for counter in 0..max_attempts {
        let (digits, sum) = message_digest_with_counter(randomness, pk_root, msg, counter, params);
        if sum == params.target_sum {
            return Some((counter, digits));
        }
    }
    None
}

/// Generate WOTS+C keypair
pub fn keygen(
    sk_seed: &[u8; 32],
    pk_seed: &[u8; 32],
    addr: Address,
    params: &WotsCParams,
) -> (WotsCSecretKey, WotsCPublicKey) {
    let mut seeds = Vec::with_capacity(params.l);
    let mut chain_tips = Vec::with_capacity(params.l);
    let mut chain_addr = addr;

    for i in 0..params.l {
        // Derive chain secret from sk_seed using PRF
        let mut hasher = Sha256::new();
        hasher.update(sk_seed);
        hasher.update((i as u32).to_le_bytes());
        hasher.update(addr.to_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        seeds.push(seed);

        // Generate chain tip (public key element)
        chain_addr.chain = i as u32;
        let tip = gen_chain(
            pk_seed,
            &seed[..params.n],
            0,
            params.w - 1,
            &mut chain_addr,
            params.n,
        );
        chain_tips.push(tip);
    }

    (
        WotsCSecretKey {
            seeds,
            params: *params,
        },
        WotsCPublicKey {
            chain_tips,
            params: *params,
        },
    )
}

/// Sign a message using WOTS+C
pub fn sign(
    msg: &[u8; 32],
    sk: &WotsCSecretKey,
    pk_seed: &[u8; 32],
    pk_root: &[u8],
    addr: Address,
    randomness: &[u8; 32],
) -> Option<WotsCSignature> {
    let params = &sk.params;

    // Grind for counter that achieves target sum
    let (counter, digits) = grind_counter(
        randomness,
        pk_root,
        msg,
        params,
        1 << 24, // Max 16M attempts (should be enough for ~2040 target)
    )?;

    // Generate signature elements
    let mut sig_elements = Vec::with_capacity(params.l);
    let mut chain_addr = addr;

    #[allow(clippy::needless_range_loop)]
    for i in 0..params.l {
        chain_addr.chain = i as u32;
        // Sign element = chain value at position digits[i]
        let elem = gen_chain(
            pk_seed,
            &sk.seeds[i][..params.n],
            0,
            digits[i],
            &mut chain_addr,
            params.n,
        );
        sig_elements.push(elem);
    }

    Some(WotsCSignature {
        sig_elements,
        counter,
        params: *params,
    })
}

/// Verify a WOTS+C signature
pub fn verify(
    msg: &[u8; 32],
    sig: &WotsCSignature,
    pk: &WotsCPublicKey,
    pk_seed: &[u8; 32],
    pk_root: &[u8],
    addr: Address,
    randomness: &[u8; 32],
) -> bool {
    let params = &sig.params;

    // Length checks can be non-constant-time (public information)
    if sig.sig_elements.len() != params.l || pk.chain_tips.len() != params.l {
        return false;
    }

    // Recompute message digest with the counter
    let (digits, sum) = message_digest_with_counter(randomness, pk_root, msg, sig.counter, params);

    // Accumulate validity using constant-time operations
    // Start with target sum check
    let mut valid = subtle::Choice::from(u8::from(sum == params.target_sum));

    // Verify each chain with constant-time comparison
    let mut chain_addr = addr;
    #[allow(clippy::needless_range_loop)]
    for i in 0..params.l {
        chain_addr.chain = i as u32;
        // Advance signature element to chain tip
        let remaining = params.w - 1 - digits[i];
        let tip = gen_chain(
            pk_seed,
            &sig.sig_elements[i],
            digits[i],
            remaining,
            &mut chain_addr,
            params.n,
        );

        // Constant-time comparison of chain tips
        valid &= tip.ct_eq(&pk.chain_tips[i]);
    }

    bool::from(valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_base_w_256() {
        // For w=256, each byte is one digit
        let input = [0x12, 0x34, 0x56, 0x78];
        let digits = base_w(&input, 256, 4);
        assert_eq!(digits, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_base_w_16() {
        // For w=16, each nibble is one digit
        let input = [0x12, 0x34];
        let digits = base_w(&input, 16, 4);
        assert_eq!(digits, vec![1, 2, 3, 4]);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // WOTS keygen involves many SHA-256 chains - too slow for Miri
    fn test_keygen_sign_verify() {
        let params = WotsCParams::LEVEL1;
        let mut rng = rand::thread_rng();

        // Generate seeds
        let mut sk_seed = [0u8; 32];
        let mut pk_seed = [0u8; 32];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut pk_seed);

        let addr = Address::new(0, 0, 0, 0, 0);

        // Generate keypair
        let (sk, pk) = keygen(&sk_seed, &pk_seed, addr, &params);
        assert_eq!(sk.seeds.len(), params.l);
        assert_eq!(pk.chain_tips.len(), params.l);

        // Create message and randomness
        let mut msg = [0u8; 32];
        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut msg);
        rng.fill_bytes(&mut randomness);

        // Use chain tip hash as pk_root for testing
        let mut hasher = Sha256::new();
        for tip in &pk.chain_tips {
            hasher.update(tip);
        }
        let pk_root = hasher.finalize().to_vec();

        // Sign
        let sig = sign(&msg, &sk, &pk_seed, &pk_root, addr, &randomness);
        assert!(sig.is_some(), "Signing should succeed");
        let sig = sig.unwrap();

        // Verify
        let valid = verify(&msg, &sig, &pk, &pk_seed, &pk_root, addr, &randomness);
        assert!(valid, "Signature should verify");

        // Modify message - should fail
        let mut bad_msg = msg;
        bad_msg[0] ^= 1;
        let invalid = verify(&bad_msg, &sig, &pk, &pk_seed, &pk_root, addr, &randomness);
        assert!(!invalid, "Modified message should fail verification");
    }

    #[test]
    fn test_signature_serialization() {
        let params = WotsCParams::LEVEL1;
        let sig = WotsCSignature {
            sig_elements: vec![vec![0xAB; params.n]; params.l],
            counter: 12345,
            params,
        };

        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), WotsCSignature::size(&params));

        let parsed = WotsCSignature::from_bytes(&bytes, params).unwrap();
        assert_eq!(parsed.counter, 12345);
        assert_eq!(parsed.sig_elements.len(), params.l);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Counter grinding does up to 2^20 hashes - far too slow for Miri
    fn test_counter_grinding() {
        let params = WotsCParams::LEVEL1;
        let randomness = [0u8; 32];
        let pk_root = [1u8; 32];
        let msg = [2u8; 32];

        // This may take a few attempts but should find a valid counter
        let result = grind_counter(&randomness, &pk_root, &msg, &params, 1 << 20);
        assert!(
            result.is_some(),
            "Should find counter within reasonable attempts"
        );

        let (counter, digits) = result.unwrap();
        let sum: u32 = digits.iter().sum();
        assert_eq!(sum, params.target_sum, "Sum should equal target");
        println!("Found counter {} with sum {}", counter, sum);
    }
}
