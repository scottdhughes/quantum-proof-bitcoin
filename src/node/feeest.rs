//! Fee estimation for QPB.
//!
//! Provides fee rate estimates for transaction confirmation targets using a hybrid
//! approach: mempool depth analysis for short targets (1-6 blocks) and historical
//! block fee data for longer targets.

use std::collections::VecDeque;

use crate::node::mempool::Mempool;

/// Default minimum fee rate (sat/vB) when no data available.
pub const DEFAULT_MIN_FEE_RATE: f64 = 1.0;

/// Maximum confirmation target (blocks) - approximately 1 week.
pub const MAX_CONF_TARGET: u64 = 1008;

/// Number of historical blocks to track (~1 day).
pub const FEE_HISTORY_BLOCKS: usize = 144;

/// Threshold for switching from mempool-based to history-based estimation.
const MEMPOOL_TARGET_THRESHOLD: u64 = 6;

/// Fee estimation result.
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    /// Estimated fee rate in sat/vB.
    pub feerate_sat_vb: f64,
    /// Blocks expected for confirmation at this rate.
    pub blocks: u64,
    /// Estimation warnings if data was limited.
    pub errors: Vec<String>,
}

/// Historical fee statistics for a single block.
#[derive(Debug, Clone)]
pub struct BlockFeeStats {
    /// Block height.
    pub height: u64,
    /// Minimum fee rate that confirmed (sat/vB * 1000 for precision).
    pub min_fee_rate: u64,
    /// Median fee rate of transactions in block (sat/vB * 1000).
    pub median_fee_rate: u64,
    /// Block weight used.
    pub block_weight: u32,
}

/// Fee estimator with mempool analysis and historical tracking.
#[derive(Debug)]
pub struct FeeEstimator {
    /// Recent block fee statistics (most recent first).
    recent_blocks: VecDeque<BlockFeeStats>,
    /// Maximum blocks to keep in history.
    max_history: usize,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeEstimator {
    /// Create a new fee estimator.
    pub fn new() -> Self {
        Self {
            recent_blocks: VecDeque::new(),
            max_history: FEE_HISTORY_BLOCKS,
        }
    }

    /// Record fee statistics from a newly connected block.
    pub fn record_block(&mut self, stats: BlockFeeStats) {
        self.recent_blocks.push_front(stats);
        while self.recent_blocks.len() > self.max_history {
            self.recent_blocks.pop_back();
        }
    }

    /// Get number of blocks in history.
    pub fn history_len(&self) -> usize {
        self.recent_blocks.len()
    }

    /// Estimate fee rate for confirmation within target blocks.
    ///
    /// # Arguments
    /// * `mempool` - Current mempool state
    /// * `conf_target` - Desired confirmation target in blocks (1-1008)
    /// * `max_block_weight` - Maximum block weight for capacity calculation
    pub fn estimate(
        &self,
        mempool: &Mempool,
        conf_target: u64,
        max_block_weight: u32,
    ) -> FeeEstimate {
        let conf_target = conf_target.clamp(1, MAX_CONF_TARGET);
        let mut errors = Vec::new();

        // Try mempool-based estimation for short targets
        if conf_target <= MEMPOOL_TARGET_THRESHOLD {
            if let Some(rate) = self.estimate_from_mempool(mempool, conf_target, max_block_weight) {
                return FeeEstimate {
                    feerate_sat_vb: rate,
                    blocks: conf_target,
                    errors,
                };
            }
            errors.push("Insufficient mempool data".to_string());
        }

        // Try history-based estimation
        if let Some(rate) = self.estimate_from_history(conf_target) {
            return FeeEstimate {
                feerate_sat_vb: rate,
                blocks: conf_target,
                errors,
            };
        }
        errors.push("Insufficient historical data".to_string());

        // Fall back to mempool if available (even for long targets)
        if let Some(rate) = self.estimate_from_mempool(mempool, conf_target, max_block_weight) {
            // Apply conservative multiplier since we're using mempool for long target
            let conservative_rate = rate * 2.0;
            return FeeEstimate {
                feerate_sat_vb: conservative_rate.max(DEFAULT_MIN_FEE_RATE),
                blocks: conf_target,
                errors,
            };
        }

        // Last resort: default minimum
        FeeEstimate {
            feerate_sat_vb: DEFAULT_MIN_FEE_RATE,
            blocks: conf_target,
            errors,
        }
    }

    /// Estimate fee rate from mempool depth.
    ///
    /// Calculates the fee rate at the position where a transaction would land
    /// given the target number of blocks worth of capacity.
    fn estimate_from_mempool(
        &self,
        mempool: &Mempool,
        conf_target: u64,
        max_block_weight: u32,
    ) -> Option<f64> {
        if mempool.is_empty() {
            return None;
        }

        // Get fee rate distribution sorted by fee rate (descending)
        let distribution = mempool.fee_rate_distribution();
        if distribution.is_empty() {
            return None;
        }

        // Calculate target position in vbytes
        // Each block can hold max_block_weight / 4 vbytes
        let vbytes_per_block = max_block_weight / 4;
        let target_position_vbytes = (conf_target as u32).saturating_mul(vbytes_per_block);

        // Walk through mempool finding the fee rate at target position
        let mut cumulative_vsize: u32 = 0;
        let mut boundary_rate: Option<u64> = None;

        for (fee_rate_millionths, vsize) in &distribution {
            cumulative_vsize = cumulative_vsize.saturating_add(*vsize);
            if cumulative_vsize >= target_position_vbytes {
                boundary_rate = Some(*fee_rate_millionths);
                break;
            }
        }

        // If mempool smaller than target capacity, use lowest rate
        let rate_millionths = boundary_rate
            .unwrap_or_else(|| distribution.last().map(|(r, _)| *r).unwrap_or(1_000_000));

        // Convert from millionths and add 10% safety margin
        let rate_sat_vb = (rate_millionths as f64 / 1_000_000.0) * 1.1;
        Some(rate_sat_vb.max(DEFAULT_MIN_FEE_RATE))
    }

    /// Estimate fee rate from historical block data.
    ///
    /// Uses median of minimum confirming fee rates from recent blocks.
    fn estimate_from_history(&self, conf_target: u64) -> Option<f64> {
        if self.recent_blocks.is_empty() {
            return None;
        }

        // Look at last N blocks where N = min(conf_target, history_len)
        let look_back = (conf_target as usize).min(self.recent_blocks.len());
        if look_back == 0 {
            return None;
        }

        // Collect minimum fee rates from recent blocks
        let mut rates: Vec<u64> = self
            .recent_blocks
            .iter()
            .take(look_back)
            .map(|s| s.min_fee_rate)
            .collect();

        if rates.is_empty() {
            return None;
        }

        rates.sort_unstable();

        // Get median
        let median_rate = rates[rates.len() / 2];

        // Convert from rate * 1000 and add 20% safety margin for longer targets
        let rate_sat_vb = (median_rate as f64 / 1000.0) * 1.2;
        Some(rate_sat_vb.max(DEFAULT_MIN_FEE_RATE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_estimator_has_empty_history() {
        let est = FeeEstimator::new();
        assert_eq!(est.history_len(), 0);
    }

    #[test]
    fn record_block_adds_to_history() {
        let mut est = FeeEstimator::new();
        est.record_block(BlockFeeStats {
            height: 1,
            min_fee_rate: 1000,
            median_fee_rate: 2000,
            block_weight: 1_000_000,
        });
        assert_eq!(est.history_len(), 1);
    }

    #[test]
    fn history_respects_max_size() {
        let mut est = FeeEstimator::new();
        for i in 0..200 {
            est.record_block(BlockFeeStats {
                height: i,
                min_fee_rate: 1000,
                median_fee_rate: 2000,
                block_weight: 1_000_000,
            });
        }
        assert_eq!(est.history_len(), FEE_HISTORY_BLOCKS);
    }

    #[test]
    fn estimate_with_no_data_returns_default() {
        let est = FeeEstimator::new();
        let mempool = Mempool::new();
        let result = est.estimate(&mempool, 6, 4_000_000);
        assert_eq!(result.feerate_sat_vb, DEFAULT_MIN_FEE_RATE);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn estimate_clamps_target() {
        let est = FeeEstimator::new();
        let mempool = Mempool::new();

        let result = est.estimate(&mempool, 0, 4_000_000);
        assert_eq!(result.blocks, 1);

        let result = est.estimate(&mempool, 2000, 4_000_000);
        assert_eq!(result.blocks, MAX_CONF_TARGET);
    }

    #[test]
    fn history_median_calculation() {
        let mut est = FeeEstimator::new();

        // Add blocks with varying fee rates
        for rate in [1000u64, 2000, 3000, 4000, 5000] {
            est.record_block(BlockFeeStats {
                height: rate / 1000,
                min_fee_rate: rate,
                median_fee_rate: rate * 2,
                block_weight: 1_000_000,
            });
        }

        // For long target, should use historical median
        let mempool = Mempool::new();
        let result = est.estimate(&mempool, 10, 4_000_000);

        // Median of [1000, 2000, 3000, 4000, 5000] = 3000
        // Converted: 3000 / 1000 * 1.2 = 3.6 sat/vB
        assert!(result.feerate_sat_vb >= 3.0);
        assert!(result.feerate_sat_vb <= 4.0);
    }
}
