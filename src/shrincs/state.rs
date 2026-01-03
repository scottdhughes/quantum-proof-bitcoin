//! SHRINCS state management for stateful signing.
//!
//! Stateful signature schemes require careful state management to prevent
//! one-time signature reuse, which would compromise security.

use crate::shrincs::error::ShrincsError;
use std::collections::HashSet;
use std::path::Path;

/// Signing state for SHRINCS stateful operations.
///
/// Tracks which leaf indices have been used to prevent reuse.
/// Must be persisted atomically after each signature.
#[derive(Debug, Clone)]
pub struct SigningState {
    /// Next leaf index to use for signing
    pub next_leaf: u64,

    /// Set of used leaf indices (for safety checking)
    pub used_leaves: HashSet<u64>,

    /// Whether fallback mode is forced (state corrupted/lost)
    pub force_fallback: bool,

    /// Maximum leaf index before exhaustion
    pub max_leaves: u64,
}

impl SigningState {
    /// Create a new signing state.
    pub fn new(max_leaves: u64) -> Self {
        Self {
            next_leaf: 0,
            used_leaves: HashSet::new(),
            force_fallback: false,
            max_leaves,
        }
    }

    /// Allocate the next available leaf index.
    ///
    /// # Returns
    /// * `Ok(index)` - The leaf index to use
    /// * `Err(StateExhausted)` - No more leaves available
    pub fn allocate_leaf(&mut self) -> Result<u64, ShrincsError> {
        if self.force_fallback {
            return Err(ShrincsError::StateCorrupted(
                "fallback mode forced".to_string(),
            ));
        }

        if self.next_leaf >= self.max_leaves {
            return Err(ShrincsError::StateExhausted);
        }

        let leaf = self.next_leaf;

        // Safety check: ensure we haven't somehow used this leaf before
        if self.used_leaves.contains(&leaf) {
            return Err(ShrincsError::LeafAlreadyUsed(leaf));
        }

        self.used_leaves.insert(leaf);
        self.next_leaf += 1;

        Ok(leaf)
    }

    /// Mark a specific leaf as used (for recovery scenarios).
    pub fn mark_used(&mut self, leaf: u64) -> Result<(), ShrincsError> {
        if self.used_leaves.contains(&leaf) {
            return Err(ShrincsError::LeafAlreadyUsed(leaf));
        }
        self.used_leaves.insert(leaf);
        if leaf >= self.next_leaf {
            self.next_leaf = leaf + 1;
        }
        Ok(())
    }

    /// Check if a leaf index has been used.
    pub fn is_used(&self, leaf: u64) -> bool {
        self.used_leaves.contains(&leaf)
    }

    /// Get the number of remaining available leaves.
    pub fn remaining_leaves(&self) -> u64 {
        self.max_leaves.saturating_sub(self.next_leaf)
    }

    /// Check if state is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.next_leaf >= self.max_leaves
    }

    /// Force fallback mode (e.g., after detecting corruption).
    pub fn force_fallback_mode(&mut self) {
        self.force_fallback = true;
    }

    /// Serialize state to bytes for persistence.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Version byte
        out.push(0x01);

        // Flags
        out.push(if self.force_fallback { 0x01 } else { 0x00 });

        // next_leaf (8 bytes, big-endian)
        out.extend_from_slice(&self.next_leaf.to_be_bytes());

        // max_leaves (8 bytes, big-endian)
        out.extend_from_slice(&self.max_leaves.to_be_bytes());

        // used_leaves count (4 bytes, big-endian)
        let count = self.used_leaves.len() as u32;
        out.extend_from_slice(&count.to_be_bytes());

        // used_leaves indices (8 bytes each, sorted for determinism)
        let mut leaves: Vec<_> = self.used_leaves.iter().copied().collect();
        leaves.sort();
        for leaf in leaves {
            out.extend_from_slice(&leaf.to_be_bytes());
        }

        out
    }

    /// Deserialize state from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShrincsError> {
        if bytes.len() < 22 {
            return Err(ShrincsError::StateCorrupted("too short".to_string()));
        }

        let version = bytes[0];
        if version != 0x01 {
            return Err(ShrincsError::StateCorrupted(format!(
                "unknown version: {}",
                version
            )));
        }

        let force_fallback = bytes[1] == 0x01;
        let next_leaf = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
        let max_leaves = u64::from_be_bytes(bytes[10..18].try_into().unwrap());
        let count = u32::from_be_bytes(bytes[18..22].try_into().unwrap()) as usize;

        if bytes.len() < 22 + count * 8 {
            return Err(ShrincsError::StateCorrupted(
                "truncated used_leaves".to_string(),
            ));
        }

        let mut used_leaves = HashSet::with_capacity(count);
        for i in 0..count {
            let offset = 22 + i * 8;
            let leaf = u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap());
            used_leaves.insert(leaf);
        }

        Ok(Self {
            next_leaf,
            used_leaves,
            force_fallback,
            max_leaves,
        })
    }
}

/// Trait for state persistence backends.
pub trait StateManager {
    /// Load state from storage.
    fn load(&self) -> Result<SigningState, ShrincsError>;

    /// Save state to storage atomically.
    fn save(&self, state: &SigningState) -> Result<(), ShrincsError>;

    /// Check if state exists.
    fn exists(&self) -> bool;

    /// Delete state (for testing/reset).
    fn delete(&self) -> Result<(), ShrincsError>;
}

/// File-based state manager with atomic updates.
pub struct FileStateManager {
    path: std::path::PathBuf,
}

impl FileStateManager {
    /// Create a new file-based state manager.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl StateManager for FileStateManager {
    fn load(&self) -> Result<SigningState, ShrincsError> {
        if !self.path.exists() {
            return Err(ShrincsError::StateNotFound);
        }
        let bytes = std::fs::read(&self.path)?;
        SigningState::from_bytes(&bytes)
    }

    fn save(&self, state: &SigningState) -> Result<(), ShrincsError> {
        let bytes = state.to_bytes();

        // Write to temp file first, then atomic rename
        let temp_path = self.path.with_extension("tmp");
        std::fs::write(&temp_path, &bytes)?;
        std::fs::rename(&temp_path, &self.path)?;

        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn delete(&self) -> Result<(), ShrincsError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_allocation() {
        let mut state = SigningState::new(1000);

        assert_eq!(state.allocate_leaf().unwrap(), 0);
        assert_eq!(state.allocate_leaf().unwrap(), 1);
        assert_eq!(state.allocate_leaf().unwrap(), 2);

        assert!(state.is_used(0));
        assert!(state.is_used(1));
        assert!(!state.is_used(100));

        assert_eq!(state.remaining_leaves(), 997);
    }

    #[test]
    fn state_exhaustion() {
        let mut state = SigningState::new(2);

        assert_eq!(state.allocate_leaf().unwrap(), 0);
        assert_eq!(state.allocate_leaf().unwrap(), 1);
        assert!(matches!(
            state.allocate_leaf(),
            Err(ShrincsError::StateExhausted)
        ));
    }

    #[test]
    fn state_serialization_roundtrip() {
        let mut state = SigningState::new(1_000_000);
        state.allocate_leaf().unwrap();
        state.allocate_leaf().unwrap();
        state.allocate_leaf().unwrap();

        let bytes = state.to_bytes();
        let restored = SigningState::from_bytes(&bytes).unwrap();

        assert_eq!(restored.next_leaf, 3);
        assert_eq!(restored.used_leaves.len(), 3);
        assert!(restored.is_used(0));
        assert!(restored.is_used(1));
        assert!(restored.is_used(2));
    }

    #[test]
    fn force_fallback() {
        let mut state = SigningState::new(1000);
        state.force_fallback_mode();

        assert!(matches!(
            state.allocate_leaf(),
            Err(ShrincsError::StateCorrupted(_))
        ));
    }
}
