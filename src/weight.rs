use crate::constants::{
    ABS_HARD_CAP_WU, LT_CLAMP_FACTOR, LT_GROWTH_DEN, LT_GROWTH_NUM, MAX_MULTIPLIER, WEIGHT_FLOOR_WU,
};

/// Compute block weight in weight units (WU) from base/witness byte counts.
pub fn block_weight_wu(base_bytes: usize, witness_bytes: usize) -> u32 {
    // Spec: BlockWeightWU = 4*base + 4*witness
    let total = 4u64
        .saturating_mul(base_bytes as u64)
        .saturating_add(4u64.saturating_mul(witness_bytes as u64));
    total.min(u32::MAX as u64) as u32
}

/// Lower median (as per spec).
pub fn median_floor(values: &[u32]) -> u32 {
    if values.is_empty() {
        return WEIGHT_FLOOR_WU;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    v[(v.len() - 1) / 2]
}

/// Effective median = min(STM, LT_CLAMP_FACTOR * LTM)
pub fn effective_median(stm: u32, ltm: u32) -> u32 {
    let clamp = LT_CLAMP_FACTOR.saturating_mul(ltm);
    stm.min(clamp).max(WEIGHT_FLOOR_WU)
}

/// MaxAllowedWeight = min(ABS_HARD_CAP_WU, MAX_MULTIPLIER * EffectiveMedian)
pub fn max_allowed_weight(stm: u32, ltm: u32) -> u32 {
    let em = effective_median(stm, ltm);
    let candidate = MAX_MULTIPLIER.saturating_mul(em);
    candidate.min(ABS_HARD_CAP_WU)
}

/// Long-term growth clamp helper: floor((LT_GROWTH_NUM / LT_GROWTH_DEN) * prev_ltm)
pub fn ltm_growth_cap(prev_ltm: u32) -> u32 {
    ((LT_GROWTH_NUM as u64)
        .saturating_mul(prev_ltm as u64)
        .saturating_div(LT_GROWTH_DEN as u64)) as u32
}

/// Penalty = floor(subsidy * ((W - M)/M)^2) with 128-bit intermediates.
pub fn penalty(subsidy: u64, weight_wu: u64, median_wu: u64) -> u64 {
    if weight_wu <= median_wu || median_wu == 0 {
        return 0;
    }
    let w_minus_m = weight_wu.saturating_sub(median_wu);
    let num = (subsidy as u128)
        .saturating_mul(w_minus_m as u128)
        .saturating_mul(w_minus_m as u128);
    let den = (median_wu as u128).saturating_mul(median_wu as u128);
    (num / den) as u64
}
