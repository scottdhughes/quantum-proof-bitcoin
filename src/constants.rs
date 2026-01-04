use hex_literal::hex;

// ---- Chain identifiers ----

/// CHAIN_ID = HASH256(SerializeBlockHeader(genesis_header)).
///
/// Computed from the provided genesis header parameters:
/// version=1, prev=0, merkle_root=4a5e1e..., time=2025-12-25 00:00:00 UTC,
/// bits=0x1d00ffff, nonce=2083236893.
pub const CHAIN_ID: [u8; 32] =
    hex!("1566e6ed83e9b4ae20da6ba5627596200ce1d0c83936554c96b4091088f64fa9");

// ---- Global limits ----
pub const MAX_BLOCK_BYTES: u32 = 8_000_000;
pub const ABS_HARD_CAP_WU: u32 = 32_000_000;
pub const WEIGHT_FLOOR_WU: u32 = 4_000_000;
pub const MAX_MULTIPLIER: u32 = 2;
pub const W_ST: u32 = 100;
pub const W_LT: u32 = 100_000;
pub const LT_CLAMP_FACTOR: u32 = 10;
pub const LT_GROWTH_NUM: u32 = 14;
pub const LT_GROWTH_DEN: u32 = 10; // 1.4x growth limiter
pub const MAX_WITNESS_ITEM_BYTES: usize = 20_480;
pub const MAX_PQSIGCHECK_BUDGET: u32 = 500;
pub const MAX_PQSIGCHECK_PER_TX: u32 = 40;
pub const MAX_SCRIPT_SIZE: usize = 10_000;
pub const MAX_SCRIPT_OPS: usize = 201;
pub const MAX_STACK_ITEMS: usize = 1000;
pub const MAX_CONTROL_BLOCK_DEPTH: usize = 128;

// ---- PQ algorithms ----
// Active at genesis
pub const MLDSA65_ALG_ID: u8 = 0x11;
// ML-DSA-65 (Dilithium3) sizes
pub const MLDSA65_PUBKEY_LEN: usize = 1952;
pub const MLDSA65_SIG_LEN: usize = 3309;
// Reserved/inactive (require feature flags or hard fork)
pub const SLH_DSA_ALG_ID: u8 = 0x21;

// SHRINCS: Hybrid stateful/stateless hash-based signatures
// Variable signature sizes: stateful path is smaller, fallback is larger
pub const SHRINCS_ALG_ID: u8 = 0x30;
pub const SHRINCS_PUBKEY_LEN: usize = 64; // 32B XMSS root + 32B SPHINCS+ pk hash
pub const SHRINCS_SIG_MIN: usize = 3_400; // Minimum stateful signature (~3.4KB)
pub const SHRINCS_SIG_FALLBACK: usize = 7_856; // SPHINCS+-128s fallback signature
pub const SHRINCS_CAPACITY: u32 = 1 << 30; // 2^30 stateful signatures before fallback

// SHRINCS fallback witness: extended pk includes full SPHINCS+ public key
pub const SPHINCS_PK_LEN: usize = 32; // SPHINCS+-128s public key size
pub const SHRINCS_FALLBACK_PUBKEY_LEN: usize = 96; // 64B base + 32B SPHINCS+ pk

// ---- Witness versions & script ----
pub const P2QTSH_VERSION: u8 = 0x02; // OP_2 PUSH32
pub const P2QPKH_VERSION: u8 = 0x03; // OP_3 PUSH32
pub const SCRIPT_LEAF_VERSION_V0: u8 = 0x00;

// ---- Opcodes ----
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1; // BIP65
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2; // BIP112
pub const OP_CTV: u8 = 0xb5;
pub const OP_CHECKPQSIG: u8 = 0xba;

// ---- PoW params (dev defaults) ----
pub const POW_TIME_COST: u32 = 1;
pub const POW_MEMORY_KIB: u32 = 1024; // 1 MiB
pub const POW_LANES: u32 = 1;
pub const POW_OUT_LEN: u32 = 32;

// ---- Monetary constants ----
pub const COIN: u64 = 100_000_000;
pub const INITIAL_SUBSIDY: u64 = 50 * COIN;
pub const HALVING_INTERVAL: u32 = 210_000;
pub const TAIL_EMISSION: u64 = 10_000_000; // 0.1 QPB

// ---- Coinbase maturity ----
/// Coinbase outputs require this many confirmations before they can be spent.
/// This prevents spending coins from blocks that might be orphaned.
pub const COINBASE_MATURITY: u32 = 100;

// ---- Locktime constants ----
/// Threshold for interpreting nLockTime: below = block height, at or above = Unix timestamp.
/// This value (500,000,000) corresponds to November 1985 as a timestamp, safely past
/// any realistic block height but before any practical use of Bitcoin.
pub const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// When all inputs have this sequence number, the transaction is considered final
/// and nLockTime is ignored.
pub const SEQUENCE_FINAL: u32 = 0xffffffff;

/// Number of blocks to use for Median Time Past (BIP113).
/// MTP is the median timestamp of the last 11 blocks.
pub const MTP_BLOCKS: usize = 11;

// ---- BIP68 Relative locktime constants ----
/// Minimum transaction version that enforces BIP68 relative locktimes.
/// Transactions with version < 2 do not have relative locktime enforcement.
pub const BIP68_MIN_VERSION: i32 = 2;

/// If this bit is set in nSequence, relative locktime is disabled for that input.
/// The input can be spent regardless of how recently the prevout was confirmed.
pub const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31; // 0x80000000

/// If this bit is set, the relative locktime is time-based (512-second granularity).
/// If not set, the relative locktime is block-based.
pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22; // 0x00400000

/// Mask for extracting the relative locktime value (lower 16 bits).
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

/// Granularity of time-based relative locktimes in seconds.
/// Time-based relative locktimes are measured in 512-second intervals.
pub const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 512;

// ---- BIP125 Replace-by-Fee (RBF) constants ----

/// Maximum sequence number that signals RBF opt-in.
/// Any input with sequence <= this value signals RBF.
pub const MAX_BIP125_RBF_SEQUENCE: u32 = 0xfffffffd;

/// Recommended sequence for RBF-enabled transactions.
pub const SEQUENCE_RBF_ENABLED: u32 = 0xfffffffd;

/// Maximum number of transactions that can be evicted by a replacement.
/// BIP125 rule 5: replacement must not evict more than 100 descendants.
pub const MAX_REPLACEMENT_EVICTIONS: usize = 100;

/// Incremental relay fee in sat/vB for replacement transactions.
/// Replacement must pay at least this much more per vB than what it evicts.
pub const INCREMENTAL_RELAY_FEE: u64 = 1;

// ---- Orphan Pool constants ----

/// Maximum number of orphan transactions to buffer.
/// Prevents memory exhaustion from P2P spam.
pub const MAX_ORPHAN_TRANSACTIONS: usize = 100;

/// Maximum size of a single orphan transaction in bytes.
/// Oversized orphans are rejected immediately.
pub const MAX_ORPHAN_TX_SIZE: usize = 100_000;

/// Maximum total bytes of orphan transactions.
/// Provides an overall memory cap independent of count.
pub const MAX_ORPHAN_POOL_BYTES: usize = 10_000_000; // 10 MB

/// Maximum orphan transactions from a single peer.
/// Limits per-peer flooding attacks.
pub const MAX_ORPHANS_PER_PEER: usize = 10;

/// Maximum number of missing parents an orphan can have.
/// Rejects transactions with too many unknown inputs (likely spam).
pub const MAX_MISSING_PARENTS: usize = 10;
