//! SHRINCS parameter sets targeting NIST security levels.
//!
//! Based on the SHRINCS proposal (Delving Bitcoin, Dec 11 2025) and
//! "Hash-based Signature Schemes for Bitcoin" (ePrint 2025/2203).

/// Hash function selection for SHRINCS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashFunction {
    /// SHA-256 truncated to n bytes (more conservative)
    Sha256,
    /// BLAKE2s truncated to n bytes (faster)
    Blake2s,
}

/// SHRINCS parameter set configuration.
#[derive(Debug, Clone, Copy)]
pub struct ShrincsParams {
    /// Security level name (e.g., "Level3")
    pub name: &'static str,

    /// NIST security level (1, 3, or 5)
    pub security_level: u8,

    /// Hash output size in bytes (n)
    pub n: usize,

    /// Winternitz parameter (w)
    /// Higher w = shorter signatures but slower signing
    pub w: u32,

    /// Number of WOTS+ chains (l)
    /// Derived from n and w: l = ceil(8n / log2(w)) + checksum_chains
    pub wots_chains: usize,

    /// WOTS+C signature size in bytes (base, without auth path)
    /// = wots_chains × n
    pub wots_sig_bytes: usize,

    /// Overhead per signature: randomness (32B) + counter (4B)
    pub wots_overhead: usize,

    /// Authentication path size per depth level (= n bytes)
    pub auth_node_bytes: usize,

    /// Public key size in bytes
    /// = 32 (XMSS root) + 32 (SPHINCS+ pk hash) = 64
    pub pk_bytes: usize,

    /// Base signature size (first signature, q=1)
    /// = wots_sig_bytes + wots_overhead + auth_node_bytes
    pub sig_base_bytes: usize,

    /// Hash function to use
    pub hash: HashFunction,

    /// Algorithm ID for consensus (0x30 for SHRINCS)
    pub alg_id: u8,
}

impl ShrincsParams {
    /// Calculate signature size for a given signature index q.
    ///
    /// Signature size grows logarithmically with usage:
    /// `sig_size = base + (q × auth_node_bytes)`
    ///
    /// where q is the 1-indexed signature count (first sig = q=1).
    #[must_use]
    pub const fn signature_size(&self, q: u32) -> usize {
        // Base signature + auth path nodes
        // Auth path depth = ceil(log2(q+1)) ≈ q for unbalanced tree
        self.sig_base_bytes + (q as usize - 1) * self.auth_node_bytes
    }

    /// Maximum number of stateful signatures before fallback is required.
    /// For unbalanced XMSS, this depends on tree depth allocation.
    #[must_use]
    pub const fn max_stateful_signatures(&self) -> u64 {
        // Unbalanced tree can support many signatures, but auth path grows
        // Practical limit based on signature size budget
        1 << 20 // ~1 million signatures
    }
}

/// NIST Level 1 (128-bit security) parameter set.
///
/// This is the production parameter set per the Delving Bitcoin SHRINCS spec.
/// https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158
///
/// # Parameters
/// - n = 16 bytes (hash output)
/// - w = 256 (Winternitz parameter)
/// - l = 16 chains
/// - Signature: 292 + q×16 bytes (324 bytes @ q=2)
/// - Public key: 16 bytes (H(pk_stateful || pk_stateless) truncated)
pub const LEVEL1: ShrincsParams = ShrincsParams {
    name: "SHRINCS-Level1",
    security_level: 1,
    n: 16,
    w: 256,
    wots_chains: 16,     // 128/8 = 16
    wots_sig_bytes: 256, // 16 chains × 16 bytes
    wots_overhead: 36,   // 32-byte randomness + 4-byte counter
    auth_node_bytes: 16, // One hash per depth level
    pk_bytes: 16,        // H(pk_stateful || pk_stateless) truncated
    sig_base_bytes: 308, // 256 + 36 + 16 (first auth node)
    hash: HashFunction::Sha256,
    alg_id: 0x30,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level1_signature_sizes() {
        // First signature (q=1): 308 bytes
        assert_eq!(LEVEL1.signature_size(1), 308);
        // Second signature (q=2): 324 bytes (matches SHRINCS proposal title!)
        assert_eq!(LEVEL1.signature_size(2), 324);
        // Tenth signature (q=10): 308 + 9×16 = 452 bytes
        assert_eq!(LEVEL1.signature_size(10), 308 + 9 * 16);
        assert_eq!(LEVEL1.signature_size(10), 452);
    }

    #[test]
    fn pk_size_constant() {
        // Per SHRINCS spec: pk = H(pk_stateful || pk_stateless) truncated to 16 bytes
        assert_eq!(LEVEL1.pk_bytes, 16);
    }
}
