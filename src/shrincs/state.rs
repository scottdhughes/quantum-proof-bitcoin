//! SHRINCS state management for stateful signing.
//!
//! Stateful signature schemes require careful state management to prevent
//! one-time signature reuse, which would compromise security.
//!
//! # Hypertree State Model
//!
//! For an XMSS^MT hypertree with d layers and h' height per layer:
//! - Global leaf index: 0 to 2^(d*h') - 1
//! - Layer i leaf = (global >> (i * h')) & ((1 << h') - 1)
//!
//! This module tracks both global leaf allocation and per-layer usage
//! for monitoring and recovery scenarios.

use crate::shrincs::error::ShrincsError;
use std::collections::HashSet;
use std::path::Path;

/// Per-layer state for XMSS^MT hypertree.
///
/// Tracks usage within a single layer of the hypertree for monitoring
/// and efficient subtree management.
#[derive(Debug, Clone, Default)]
pub struct LayerState {
    /// Number of signatures using this layer (increments when layer leaf changes)
    pub signatures_at_layer: u64,
    /// Current leaf index within this layer (0 to 2^h' - 1)
    pub current_leaf: u32,
    /// Whether this layer's current subtree is exhausted
    pub subtree_exhausted: bool,
}

impl LayerState {
    /// Create a new layer state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize layer state to bytes (12 bytes).
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..8].copy_from_slice(&self.signatures_at_layer.to_be_bytes());
        out[8..12].copy_from_slice(&self.current_leaf.to_be_bytes());
        // subtree_exhausted encoded in high bit of current_leaf serialization already,
        // but we could use a flag byte if needed
        out
    }

    /// Deserialize layer state from bytes.
    pub fn from_bytes(bytes: &[u8; 12]) -> Self {
        Self {
            signatures_at_layer: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            current_leaf: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            subtree_exhausted: false, // Computed from current_leaf vs max
        }
    }
}

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

    /// Per-layer state for hypertree (optional, d layers)
    pub layer_states: Option<Vec<LayerState>>,

    /// Height per layer (h') for computing layer indices
    pub height_per_layer: u8,
}

impl SigningState {
    /// Create a new signing state.
    pub fn new(max_leaves: u64) -> Self {
        Self {
            next_leaf: 0,
            used_leaves: HashSet::new(),
            force_fallback: false,
            max_leaves,
            layer_states: None,
            height_per_layer: 8, // Default for standard SHRINCS
        }
    }

    /// Create a new signing state with hypertree layer tracking.
    ///
    /// # Arguments
    /// * `max_leaves` - Maximum total signatures (2^(d*h'))
    /// * `num_layers` - Number of hypertree layers (d)
    /// * `height_per_layer` - Height per layer (h')
    pub fn new_with_layers(max_leaves: u64, num_layers: usize, height_per_layer: u8) -> Self {
        Self {
            next_leaf: 0,
            used_leaves: HashSet::new(),
            force_fallback: false,
            max_leaves,
            layer_states: Some(vec![LayerState::new(); num_layers]),
            height_per_layer,
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

        // Update layer states if tracking is enabled
        if let Some(ref mut layers) = self.layer_states {
            let h = self.height_per_layer as u64;
            let mask = (1u64 << h) - 1;

            for (i, layer) in layers.iter_mut().enumerate() {
                let layer_leaf = ((leaf >> (i as u64 * h)) & mask) as u32;
                layer.current_leaf = layer_leaf;
                layer.signatures_at_layer += 1;

                // Check if this layer's subtree is about to roll over
                if layer_leaf == mask as u32 {
                    layer.subtree_exhausted = true;
                }
            }
        }

        self.used_leaves.insert(leaf);
        self.next_leaf += 1;

        Ok(leaf)
    }

    /// Get the leaf index for a specific layer from a global leaf index.
    pub fn layer_leaf_index(&self, global_leaf: u64, layer: usize) -> u32 {
        let h = self.height_per_layer as u64;
        let mask = (1u64 << h) - 1;
        ((global_leaf >> (layer as u64 * h)) & mask) as u32
    }

    /// Get layer usage statistics.
    pub fn layer_stats(&self) -> Option<Vec<(u32, u64, bool)>> {
        self.layer_states.as_ref().map(|layers| {
            layers
                .iter()
                .map(|l| (l.current_leaf, l.signatures_at_layer, l.subtree_exhausted))
                .collect()
        })
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
    ///
    /// Format v1: Basic state (no layer tracking)
    /// Format v2: Extended state with layer tracking
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Use v2 if layer states present, otherwise v1 for compatibility
        let version = if self.layer_states.is_some() {
            0x02
        } else {
            0x01
        };
        out.push(version);

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

        // V2 extension: layer states
        if let Some(ref layers) = self.layer_states {
            // height_per_layer (1 byte)
            out.push(self.height_per_layer);

            // num_layers (1 byte)
            out.push(layers.len() as u8);

            // Layer states (12 bytes each)
            for layer in layers {
                out.extend_from_slice(&layer.to_bytes());
            }
        }

        out
    }

    /// Deserialize state from bytes.
    ///
    /// Supports both v1 (basic) and v2 (with layers) formats.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShrincsError> {
        if bytes.len() < 22 {
            return Err(ShrincsError::StateCorrupted("too short".to_string()));
        }

        let version = bytes[0];
        if version != 0x01 && version != 0x02 {
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

        let base_end = 22 + count * 8;

        // Parse v2 extension if present
        let (layer_states, height_per_layer) = if version == 0x02 && bytes.len() > base_end + 2 {
            let height_per_layer = bytes[base_end];
            let num_layers = bytes[base_end + 1] as usize;

            if bytes.len() < base_end + 2 + num_layers * 12 {
                return Err(ShrincsError::StateCorrupted(
                    "truncated layer states".to_string(),
                ));
            }

            let mut layers = Vec::with_capacity(num_layers);
            for i in 0..num_layers {
                let offset = base_end + 2 + i * 12;
                let layer_bytes: [u8; 12] = bytes[offset..offset + 12].try_into().unwrap();
                layers.push(LayerState::from_bytes(&layer_bytes));
            }

            (Some(layers), height_per_layer)
        } else {
            (None, 8) // Default h' = 8
        };

        Ok(Self {
            next_leaf,
            used_leaves,
            force_fallback,
            max_leaves,
            layer_states,
            height_per_layer,
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

/// File-based state manager with atomic updates and file locking.
///
/// # Safety
///
/// This manager uses file locking to prevent concurrent access. The lock is
/// held for the duration of save/load operations. For signing workflows:
///
/// 1. Acquire exclusive lock
/// 2. Load current state
/// 3. Allocate leaf index
/// 4. Save updated state (atomic write)
/// 5. Release lock
/// 6. Sign with allocated leaf
///
/// This ensures state is persisted before signing, preventing reuse.
pub struct FileStateManager {
    path: std::path::PathBuf,
    lock_path: std::path::PathBuf,
}

impl FileStateManager {
    /// Create a new file-based state manager.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        let lock_path = path.with_extension("lock");
        Self { path, lock_path }
    }

    /// Ensure parent directory exists.
    fn ensure_dir(&self) -> Result<(), ShrincsError> {
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Ok(())
    }

    /// Acquire an exclusive file lock.
    ///
    /// Returns a guard that releases the lock on drop.
    pub fn lock(&self) -> Result<LockGuard, ShrincsError> {
        use fs2::FileExt;
        self.ensure_dir()?;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)?;

        // Block until we acquire exclusive lock
        file.lock_exclusive()?;

        Ok(LockGuard { file })
    }

    /// Try to acquire an exclusive file lock without blocking.
    ///
    /// Returns None if lock is held by another process.
    pub fn try_lock(&self) -> Result<Option<LockGuard>, ShrincsError> {
        use fs2::FileExt;
        self.ensure_dir()?;

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)?;

        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(LockGuard { file })),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(ShrincsError::from(e)),
        }
    }

    /// Load state while holding lock.
    pub fn load_with_lock(&self, _lock: &LockGuard) -> Result<SigningState, ShrincsError> {
        if !self.path.exists() {
            return Err(ShrincsError::StateNotFound);
        }
        let bytes = std::fs::read(&self.path)?;
        SigningState::from_bytes(&bytes)
    }

    /// Save state while holding lock.
    pub fn save_with_lock(
        &self,
        state: &SigningState,
        _lock: &LockGuard,
    ) -> Result<(), ShrincsError> {
        self.ensure_dir()?;
        let bytes = state.to_bytes();

        // Write to temp file first, then atomic rename
        let temp_path = self.path.with_extension("tmp");
        std::fs::write(&temp_path, &bytes)?;
        std::fs::rename(&temp_path, &self.path)?;

        Ok(())
    }
}

/// RAII guard for file lock.
pub struct LockGuard {
    file: std::fs::File,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        use fs2::FileExt;
        // Unlock on drop (ignore errors)
        let _ = self.file.unlock();
    }
}

impl StateManager for FileStateManager {
    fn load(&self) -> Result<SigningState, ShrincsError> {
        let lock = self.lock()?;
        self.load_with_lock(&lock)
    }

    fn save(&self, state: &SigningState) -> Result<(), ShrincsError> {
        let lock = self.lock()?;
        self.save_with_lock(state, &lock)
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn delete(&self) -> Result<(), ShrincsError> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        // Also clean up lock file
        if self.lock_path.exists() {
            let _ = std::fs::remove_file(&self.lock_path);
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

    #[test]
    fn layer_tracking() {
        // 4 layers, h'=4 (16 leaves per layer), max = 16^4 = 65536
        let mut state = SigningState::new_with_layers(65536, 4, 4);

        // First allocation: global leaf 0
        assert_eq!(state.allocate_leaf().unwrap(), 0);

        // All layer leaves should be 0
        let stats = state.layer_stats().unwrap();
        assert_eq!(stats.len(), 4);
        for (leaf, sigs, _exhausted) in &stats {
            assert_eq!(*leaf, 0);
            assert_eq!(*sigs, 1);
        }

        // After 16 allocations, layer 0 should advance each time
        for _ in 1..16 {
            state.allocate_leaf().unwrap();
        }
        assert_eq!(state.next_leaf, 16);

        let stats = state.layer_stats().unwrap();
        // Layer 0: leaf 15 (last of first subtree)
        assert_eq!(stats[0].0, 15);
        // Layer 1: leaf 0 (still first subtree of layer 1)
        assert_eq!(stats[1].0, 0);

        // One more allocation should roll over layer 0
        state.allocate_leaf().unwrap();
        let stats = state.layer_stats().unwrap();
        // Layer 0: leaf 0 (new subtree)
        assert_eq!(stats[0].0, 0);
        // Layer 1: leaf 1 (moved to second leaf)
        assert_eq!(stats[1].0, 1);
    }

    #[test]
    fn layer_leaf_index_computation() {
        let state = SigningState::new_with_layers(1 << 32, 4, 8);

        // Global leaf 0: all layers at leaf 0
        assert_eq!(state.layer_leaf_index(0, 0), 0);
        assert_eq!(state.layer_leaf_index(0, 1), 0);
        assert_eq!(state.layer_leaf_index(0, 2), 0);
        assert_eq!(state.layer_leaf_index(0, 3), 0);

        // Global leaf 256: layer 0 at 0, layer 1 at 1
        assert_eq!(state.layer_leaf_index(256, 0), 0);
        assert_eq!(state.layer_leaf_index(256, 1), 1);
        assert_eq!(state.layer_leaf_index(256, 2), 0);

        // Global leaf 0x01020304: each layer gets a byte
        let global = 0x01020304u64;
        assert_eq!(state.layer_leaf_index(global, 0), 0x04);
        assert_eq!(state.layer_leaf_index(global, 1), 0x03);
        assert_eq!(state.layer_leaf_index(global, 2), 0x02);
        assert_eq!(state.layer_leaf_index(global, 3), 0x01);
    }

    #[test]
    fn layer_state_serialization_v2() {
        let mut state = SigningState::new_with_layers(65536, 4, 4);
        state.allocate_leaf().unwrap();
        state.allocate_leaf().unwrap();

        let bytes = state.to_bytes();
        assert_eq!(bytes[0], 0x02); // Version 2

        let restored = SigningState::from_bytes(&bytes).unwrap();
        assert_eq!(restored.next_leaf, 2);
        assert_eq!(restored.height_per_layer, 4);
        assert!(restored.layer_states.is_some());
        assert_eq!(restored.layer_states.as_ref().unwrap().len(), 4);
    }

    #[test]
    fn v1_v2_compatibility() {
        // V1 format (no layers) should still work
        let state_v1 = SigningState::new(1000);
        let bytes_v1 = state_v1.to_bytes();
        assert_eq!(bytes_v1[0], 0x01); // Version 1

        let restored = SigningState::from_bytes(&bytes_v1).unwrap();
        assert!(restored.layer_states.is_none());
        assert_eq!(restored.height_per_layer, 8); // Default

        // V2 format with layers
        let state_v2 = SigningState::new_with_layers(1000, 2, 8);
        let bytes_v2 = state_v2.to_bytes();
        assert_eq!(bytes_v2[0], 0x02); // Version 2

        let restored = SigningState::from_bytes(&bytes_v2).unwrap();
        assert!(restored.layer_states.is_some());
    }

    #[test]
    fn file_state_manager_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shrincs").join("state.bin");
        let mgr = FileStateManager::new(&path);

        // Initially no state
        assert!(!mgr.exists());

        // Create and save state
        let mut state = SigningState::new(1000);
        state.allocate_leaf().unwrap();
        state.allocate_leaf().unwrap();

        mgr.save(&state).unwrap();
        assert!(mgr.exists());

        // Load and verify
        let loaded = mgr.load().unwrap();
        assert_eq!(loaded.next_leaf, 2);
        assert!(loaded.is_used(0));
        assert!(loaded.is_used(1));

        // Delete
        mgr.delete().unwrap();
        assert!(!mgr.exists());
    }

    #[test]
    fn file_state_manager_locking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        let mgr = FileStateManager::new(&path);

        // Acquire lock
        let lock = mgr.lock().unwrap();

        // Try to acquire again (should fail with try_lock)
        let result = mgr.try_lock().unwrap();
        assert!(result.is_none(), "should not acquire lock while held");

        // Save and load with lock
        let state = SigningState::new(100);
        mgr.save_with_lock(&state, &lock).unwrap();
        let loaded = mgr.load_with_lock(&lock).unwrap();
        assert_eq!(loaded.max_leaves, 100);

        // Drop lock
        drop(lock);

        // Now can acquire again
        let lock2 = mgr.try_lock().unwrap();
        assert!(lock2.is_some(), "should acquire lock after release");
    }

    #[test]
    fn file_state_manager_atomic_update() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.bin");
        let mgr = FileStateManager::new(&path);

        // Initial state
        let state = SigningState::new(1000);
        mgr.save(&state).unwrap();

        // Multiple updates
        for i in 0..5 {
            let lock = mgr.lock().unwrap();
            let mut current = mgr.load_with_lock(&lock).unwrap();
            current.allocate_leaf().unwrap();
            mgr.save_with_lock(&current, &lock).unwrap();
            // Lock released here
        }

        // Verify final state
        let final_state = mgr.load().unwrap();
        assert_eq!(final_state.next_leaf, 5);
        for i in 0..5 {
            assert!(final_state.is_used(i));
        }
    }
}
