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
// Reserved/inactive
pub const SLH_DSA_ALG_ID: u8 = 0x21;
pub const SHRINCS_ALG_ID: u8 = 0x30;
pub const SHRINCS_PUBKEY_LEN: usize = 64;
pub const SHRINCS_SIG_LEN: usize = 324;
pub const SHRINCS_MAX_INDEX: u32 = 1024;

// ---- Witness versions & script ----
pub const P2QTSH_VERSION: u8 = 0x02; // OP_2 PUSH32
pub const P2QPKH_VERSION: u8 = 0x03; // OP_3 PUSH32
pub const SCRIPT_LEAF_VERSION_V0: u8 = 0x00;

// ---- Opcodes ----
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
