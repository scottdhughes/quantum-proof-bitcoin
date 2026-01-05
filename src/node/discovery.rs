//! Peer discovery via DNS seeds and P2P address exchange.

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};

/// Maximum DNS seeds to try per network.
pub const MAX_DNS_SEEDS: usize = 3;

/// Maximum addresses to return per DNS seed.
pub const MAX_ADDRS_PER_SEED: usize = 25;

/// Maximum addresses to store in address manager.
pub const MAX_ADDR_MANAGER_SIZE: usize = 1000;

/// Resolve DNS seed hostnames to socket addresses.
///
/// Returns a list of peer addresses from DNS seeds. Resolution is
/// synchronous and may block for DNS timeouts.
pub fn resolve_dns_seeds(seeds: &[String], default_port: u16) -> Vec<SocketAddr> {
    let mut addresses = Vec::new();

    for seed in seeds.iter().take(MAX_DNS_SEEDS) {
        // Append default port for DNS resolution
        let seed_with_port = if seed.contains(':') {
            seed.clone()
        } else {
            format!("{}:{}", seed, default_port)
        };

        // Resolve DNS A/AAAA records
        match seed_with_port.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs.take(MAX_ADDRS_PER_SEED) {
                    if !addresses.contains(&addr) {
                        addresses.push(addr);
                    }
                }
            }
            Err(e) => {
                eprintln!("DNS resolution failed for {}: {}", seed, e);
            }
        }
    }

    addresses
}

// ============================================================================
// Address Manager
// ============================================================================

/// Entry for a known peer address.
#[derive(Clone)]
struct AddrEntry {
    /// Service flags advertised by this peer.
    services: u64,
    /// Unix timestamp when last seen.
    last_seen: u64,
    /// Unix timestamp of last connection attempt.
    last_try: u64,
    /// Number of connection attempts.
    attempts: u32,
    /// Whether last connection was successful.
    success: bool,
}

/// Simple in-memory address manager.
///
/// Tracks known peer addresses and their connection history.
pub struct AddrManager {
    /// Known addresses with metadata.
    addrs: HashMap<SocketAddr, AddrEntry>,
    /// Maximum addresses to store.
    max_size: usize,
}

impl AddrManager {
    /// Create a new address manager with the given capacity.
    pub fn new(max_size: usize) -> Self {
        Self {
            addrs: HashMap::new(),
            max_size,
        }
    }

    /// Add an address (from ADDR message or DNS seed).
    pub fn add(&mut self, addr: SocketAddr, services: u64, time: u64) {
        if self.addrs.len() >= self.max_size && !self.addrs.contains_key(&addr) {
            // Evict oldest entry
            if let Some(oldest) = self
                .addrs
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| *k)
            {
                self.addrs.remove(&oldest);
            }
        }

        self.addrs
            .entry(addr)
            .and_modify(|e| {
                e.last_seen = time.max(e.last_seen);
                e.services = services;
            })
            .or_insert(AddrEntry {
                services,
                last_seen: time,
                last_try: 0,
                attempts: 0,
                success: false,
            });
    }

    /// Mark an address as successfully connected.
    pub fn mark_good(&mut self, addr: &SocketAddr) {
        let now = current_unix_time();
        if let Some(entry) = self.addrs.get_mut(addr) {
            entry.success = true;
            entry.last_try = now;
            entry.last_seen = now;
        }
    }

    /// Mark a connection attempt as failed.
    pub fn mark_attempt(&mut self, addr: &SocketAddr, success: bool) {
        if let Some(entry) = self.addrs.get_mut(addr) {
            entry.last_try = current_unix_time();
            entry.attempts += 1;
            entry.success = success;
        }
    }

    /// Get addresses to try connecting to.
    ///
    /// Prioritizes recently-seen addresses that haven't been tried recently.
    pub fn get_addrs_to_try(&self, count: usize) -> Vec<SocketAddr> {
        let now = current_unix_time();
        let retry_delay = 600; // 10 minutes

        let mut candidates: Vec<_> = self
            .addrs
            .iter()
            .filter(|(_, e)| now - e.last_try > retry_delay || e.attempts == 0)
            .collect();

        // Sort by: successful first, then by last_seen descending
        candidates.sort_by(|(_, a), (_, b)| {
            b.success
                .cmp(&a.success)
                .then(b.last_seen.cmp(&a.last_seen))
        });

        candidates
            .into_iter()
            .take(count)
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Get addresses to send in ADDR message.
    ///
    /// Returns (address, services, last_seen_time) for recent addresses.
    pub fn get_addrs_to_share(&self, count: usize) -> Vec<(SocketAddr, u64, u64)> {
        let now = current_unix_time();
        let max_age = 3 * 60 * 60; // 3 hours

        let mut candidates: Vec<_> = self
            .addrs
            .iter()
            .filter(|(_, e)| now - e.last_seen < max_age)
            .collect();

        candidates.sort_by(|(_, a), (_, b)| b.last_seen.cmp(&a.last_seen));

        candidates
            .into_iter()
            .take(count)
            .map(|(addr, e)| (*addr, e.services, e.last_seen))
            .collect()
    }

    /// Number of known addresses.
    pub fn len(&self) -> usize {
        self.addrs.len()
    }

    /// Check if address manager is empty.
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }
}

/// Get current Unix timestamp in seconds.
fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn addr_manager_basic() {
        let mut mgr = AddrManager::new(100);

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333);

        mgr.add(addr1, 1, 1000);
        mgr.add(addr2, 1, 2000);

        assert_eq!(mgr.len(), 2);

        let to_try = mgr.get_addrs_to_try(10);
        assert_eq!(to_try.len(), 2);
        // addr2 should be first (more recent)
        assert_eq!(to_try[0], addr2);
    }

    #[test]
    fn addr_manager_eviction() {
        let mut mgr = AddrManager::new(2);

        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 8333);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 8333);
        let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)), 8333);

        mgr.add(addr1, 1, 1000);
        mgr.add(addr2, 1, 2000);
        assert_eq!(mgr.len(), 2);

        // Adding third should evict oldest (addr1)
        mgr.add(addr3, 1, 3000);
        assert_eq!(mgr.len(), 2);

        let to_try = mgr.get_addrs_to_try(10);
        assert!(!to_try.contains(&addr1));
        assert!(to_try.contains(&addr2));
        assert!(to_try.contains(&addr3));
    }

    #[test]
    fn addr_manager_mark_good() {
        let mut mgr = AddrManager::new(100);

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        mgr.add(addr, 1, 1000);
        mgr.mark_good(&addr);

        let to_share = mgr.get_addrs_to_share(10);
        assert!(!to_share.is_empty());
    }
}
