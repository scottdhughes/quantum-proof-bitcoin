use crate::constants::{HALVING_INTERVAL, INITIAL_SUBSIDY, TAIL_EMISSION};

/// Block subsidy with Bitcoin-style halvings and tail emission floor.
pub fn block_subsidy(height: u32) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let mut subsidy = if halvings < 64 {
        INITIAL_SUBSIDY >> halvings
    } else {
        0
    };
    if subsidy < TAIL_EMISSION {
        subsidy = TAIL_EMISSION;
    }
    subsidy
}
