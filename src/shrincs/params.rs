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

/// NIST Level 3 (192-bit security) parameter set.
///
/// This is the recommended parameter set for production use.
///
/// # Parameters
/// - n = 24 bytes (hash output)
/// - w = 256 (Winternitz parameter)
/// - l = 24 chains
/// - Signature: 612 + q×24 bytes
/// - Public key: 64 bytes
pub const LEVEL3: ShrincsParams = ShrincsParams {
    name: "SHRINCS-Level3",
    security_level: 3,
    n: 24,
    w: 256,
    wots_chains: 24, // 192/8 = 24
    wots_sig_bytes: 576, // 24 chains × 24 bytes
    wots_overhead: 36, // 32-byte randomness + 4-byte counter
    auth_node_bytes: 24, // One hash per depth level
    pk_bytes: 64, // 32B XMSS root + 32B SPHINCS+ hash
    sig_base_bytes: 636, // 576 + 36 + 24 (first auth node)
    hash: HashFunction::Sha256,
    alg_id: 0x30,
};

/// NIST Level 1 (128-bit security) parameter set.
///
/// Smaller signatures but lower security margin.
/// Use only if signature size is critical.
///
/// # Parameters
/// - n = 16 bytes (hash output)
/// - w = 256 (Winternitz parameter)
/// - l = 16 chains
/// - Signature: 292 + q×16 bytes
/// - Public key: 64 bytes
pub const LEVEL1: ShrincsParams = ShrincsParams {
    name: "SHRINCS-Level1",
    security_level: 1,
    n: 16,
    w: 256,
    wots_chains: 16, // 128/8 = 16
    wots_sig_bytes: 256, // 16 chains × 16 bytes
    wots_overhead: 36, // 32-byte randomness + 4-byte counter
    auth_node_bytes: 16, // One hash per depth level
    pk_bytes: 64, // 32B XMSS root + 32B SPHINCS+ hash
    sig_base_bytes: 308, // 256 + 36 + 16 (first auth node)
    hash: HashFunction::Sha256,
    alg_id: 0x30,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level3_signature_sizes() {
        // First signature
        assert_eq!(LEVEL3.signature_size(1), 636);
        // Second signature (one more auth node)
        assert_eq!(LEVEL3.signature_size(2), 636 + 24);
        // Tenth signature
        assert_eq!(LEVEL3.signature_size(10), 636 + 9 * 24);
        assert_eq!(LEVEL3.signature_size(10), 852);
    }

    #[test]
    fn level1_signature_sizes() {
        // First signature
        assert_eq!(LEVEL1.signature_size(1), 308);
        // Tenth signature
        assert_eq!(LEVEL1.signature_size(10), 308 + 9 * 16);
    }

    #[test]
    fn pk_size_constant() {
        assert_eq!(LEVEL3.pk_bytes, 64);
        assert_eq!(LEVEL1.pk_bytes, 64);
    }
}
