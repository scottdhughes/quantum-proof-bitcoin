//! Checkpoint verification for chain validation.
//!
//! Checkpoints are known-good block hashes at specific heights that are
//! hardcoded into the node. They provide:
//! - Protection against long-range attacks
//! - Faster initial sync (can skip some validation below checkpoints)
//! - Rejection of peers sending checkpoint-violating blocks

use anyhow::{Result, anyhow};

/// A known-good block at a specific height.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Block height.
    pub height: u64,
    /// Expected block hash (32 bytes).
    pub hash: [u8; 32],
}

/// Checkpoint verification for chain validation.
#[derive(Debug)]
pub struct CheckpointVerifier {
    /// Checkpoints sorted by height (ascending).
    checkpoints: Vec<Checkpoint>,
    /// Highest checkpoint height (cached for quick lookup).
    max_height: u64,
}

impl CheckpointVerifier {
    /// Create a checkpoint verifier for the given network.
    pub fn new(chain: &str) -> Self {
        let checkpoints = match chain {
            "devnet" => devnet_checkpoints(),
            "testnet" => testnet_checkpoints(),
            "mainnet" => mainnet_checkpoints(),
            _ => Vec::new(),
        };

        let max_height = checkpoints.last().map(|c| c.height).unwrap_or(0);

        Self {
            checkpoints,
            max_height,
        }
    }

    /// Create an empty verifier (no checkpoints).
    pub fn empty() -> Self {
        Self {
            checkpoints: Vec::new(),
            max_height: 0,
        }
    }

    /// Get the checkpoint at a specific height, if one exists.
    pub fn get_checkpoint(&self, height: u64) -> Option<&Checkpoint> {
        self.checkpoints.iter().find(|c| c.height == height)
    }

    /// Verify a block hash against checkpoints.
    ///
    /// Returns:
    /// - `Ok(true)` if the hash matches a checkpoint at this height
    /// - `Ok(false)` if there is no checkpoint at this height
    /// - `Err` if the hash violates a checkpoint
    pub fn verify(&self, height: u64, hash: &[u8; 32]) -> Result<bool> {
        if let Some(checkpoint) = self.get_checkpoint(height) {
            if hash == &checkpoint.hash {
                Ok(true)
            } else {
                Err(anyhow!(
                    "checkpoint violation at height {}: expected {}, got {}",
                    height,
                    hex::encode(checkpoint.hash),
                    hex::encode(hash)
                ))
            }
        } else {
            Ok(false)
        }
    }

    /// Check if a height is below all checkpoints.
    ///
    /// When syncing blocks below checkpoints, some validation can be skipped
    /// since we know the chain is valid up to the checkpoint.
    pub fn is_below_checkpoints(&self, height: u64) -> bool {
        height < self.max_height
    }

    /// Get the highest checkpoint height.
    pub fn max_checkpoint_height(&self) -> u64 {
        self.max_height
    }

    /// Verify a sequence of headers doesn't violate any checkpoints.
    ///
    /// Takes an iterator of (height, hash) pairs.
    pub fn verify_headers<'a, I>(&self, headers: I) -> Result<()>
    where
        I: IntoIterator<Item = (u64, &'a [u8; 32])>,
    {
        for (height, hash) in headers {
            self.verify(height, hash)?;
        }
        Ok(())
    }

    /// Get all checkpoints (for debugging/display).
    pub fn checkpoints(&self) -> &[Checkpoint] {
        &self.checkpoints
    }

    /// Check if there are any checkpoints configured.
    pub fn has_checkpoints(&self) -> bool {
        !self.checkpoints.is_empty()
    }
}

// ============================================================================
// Network-specific Checkpoints
// ============================================================================

/// Checkpoints for devnet (empty - development network).
fn devnet_checkpoints() -> Vec<Checkpoint> {
    // Devnet has no checkpoints (allows flexible testing)
    Vec::new()
}

/// Checkpoints for testnet.
fn testnet_checkpoints() -> Vec<Checkpoint> {
    // Testnet checkpoints will be added as the network matures
    // Example format:
    // vec![
    //     Checkpoint {
    //         height: 10000,
    //         hash: hex_literal::hex!("0000..."),
    //     },
    // ]
    Vec::new()
}

/// Checkpoints for mainnet.
fn mainnet_checkpoints() -> Vec<Checkpoint> {
    // Mainnet checkpoints will be added when mainnet launches
    Vec::new()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(val: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = val;
        hash
    }

    #[test]
    fn empty_verifier() {
        let verifier = CheckpointVerifier::empty();
        assert!(!verifier.has_checkpoints());
        assert_eq!(verifier.max_checkpoint_height(), 0);
    }

    #[test]
    fn verify_no_checkpoint() {
        let verifier = CheckpointVerifier::empty();
        let hash = make_hash(1);

        // No checkpoint at this height, should return Ok(false)
        assert_eq!(verifier.verify(100, &hash).unwrap(), false);
    }

    #[test]
    fn verify_matching_checkpoint() {
        let hash = make_hash(42);
        let mut verifier = CheckpointVerifier::empty();
        verifier.checkpoints.push(Checkpoint { height: 1000, hash });
        verifier.max_height = 1000;

        // Matching checkpoint
        assert_eq!(verifier.verify(1000, &hash).unwrap(), true);
    }

    #[test]
    fn verify_violating_checkpoint() {
        let expected_hash = make_hash(42);
        let wrong_hash = make_hash(99);

        let mut verifier = CheckpointVerifier::empty();
        verifier.checkpoints.push(Checkpoint {
            height: 1000,
            hash: expected_hash,
        });
        verifier.max_height = 1000;

        // Wrong hash at checkpoint height
        let result = verifier.verify(1000, &wrong_hash);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("checkpoint violation")
        );
    }

    #[test]
    fn is_below_checkpoints() {
        let mut verifier = CheckpointVerifier::empty();
        verifier.checkpoints.push(Checkpoint {
            height: 10000,
            hash: make_hash(1),
        });
        verifier.max_height = 10000;

        assert!(verifier.is_below_checkpoints(5000));
        assert!(verifier.is_below_checkpoints(9999));
        assert!(!verifier.is_below_checkpoints(10000));
        assert!(!verifier.is_below_checkpoints(10001));
    }

    #[test]
    fn verify_header_sequence() {
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);
        let hash_middle = make_hash(99);

        let mut verifier = CheckpointVerifier::empty();
        verifier.checkpoints.push(Checkpoint {
            height: 100,
            hash: hash1,
        });
        verifier.checkpoints.push(Checkpoint {
            height: 200,
            hash: hash2,
        });
        verifier.max_height = 200;

        // Valid sequence
        let headers = vec![(100, &hash1), (150, &hash_middle), (200, &hash2)];
        assert!(verifier.verify_headers(headers).is_ok());

        // Invalid sequence (wrong hash at checkpoint)
        let wrong = make_hash(99);
        let bad_headers = vec![(100, &wrong)];
        assert!(verifier.verify_headers(bad_headers).is_err());
    }

    #[test]
    fn devnet_has_no_checkpoints() {
        let verifier = CheckpointVerifier::new("devnet");
        assert!(!verifier.has_checkpoints());
    }
}
