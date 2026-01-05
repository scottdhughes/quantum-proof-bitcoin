//! RPC rate limiting with per-client tracking.
//!
//! Implements a token bucket algorithm per client IP to prevent DoS attacks
//! on the RPC endpoint.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{RPC_BUCKET_CAPACITY, RPC_CLIENT_MAX_AGE_SECS, RPC_MAX_REQUESTS_PER_SECOND};

/// Per-client rate limiting state.
struct ClientState {
    /// Token bucket for this client.
    tokens: u32,
    /// Last refill timestamp (unix seconds).
    last_refill: u64,
    /// Last activity timestamp for pruning stale entries.
    last_seen: u64,
}

impl ClientState {
    fn new(max_tokens: u32) -> Self {
        let now = current_unix_time();
        Self {
            tokens: max_tokens,
            last_refill: now,
            last_seen: now,
        }
    }

    fn refill(&mut self, max_tokens: u32, refill_rate: u32) {
        let now = current_unix_time();
        let elapsed = now.saturating_sub(self.last_refill);

        if elapsed > 0 {
            let refill_amount = (elapsed as u32).saturating_mul(refill_rate);
            self.tokens = self.tokens.saturating_add(refill_amount).min(max_tokens);
            self.last_refill = now;
        }
        self.last_seen = now;
    }

    fn try_consume(&mut self, max_tokens: u32, refill_rate: u32) -> bool {
        self.refill(max_tokens, refill_rate);

        if self.tokens >= 1 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// RPC rate limiter with per-IP tracking.
///
/// Each client IP gets its own token bucket. Stale entries are pruned
/// periodically to prevent memory growth.
pub struct RpcRateLimiter {
    clients: Mutex<HashMap<IpAddr, ClientState>>,
    max_tokens: u32,
    refill_rate: u32,
    last_prune: Mutex<u64>,
}

impl RpcRateLimiter {
    /// Create a new RPC rate limiter with specified limits.
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            max_tokens,
            refill_rate,
            last_prune: Mutex::new(current_unix_time()),
        }
    }

    /// Create a rate limiter with default RPC limits.
    pub fn default_rpc() -> Self {
        Self::new(RPC_BUCKET_CAPACITY, RPC_MAX_REQUESTS_PER_SECOND)
    }

    /// Try to consume a token for the given client IP.
    /// Returns true if allowed, false if rate limited.
    pub fn try_consume(&self, ip: IpAddr) -> bool {
        // Maybe prune stale entries
        self.maybe_prune();

        let mut clients = self.clients.lock().unwrap();
        let state = clients
            .entry(ip)
            .or_insert_with(|| ClientState::new(self.max_tokens));

        state.try_consume(self.max_tokens, self.refill_rate)
    }

    /// Get the number of tracked clients.
    pub fn client_count(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    /// Prune stale client entries if enough time has passed.
    fn maybe_prune(&self) {
        let now = current_unix_time();
        let mut last_prune = self.last_prune.lock().unwrap();

        // Prune every 60 seconds
        if now.saturating_sub(*last_prune) < 60 {
            return;
        }
        *last_prune = now;
        drop(last_prune);

        let mut clients = self.clients.lock().unwrap();
        clients.retain(|_, state| now.saturating_sub(state.last_seen) < RPC_CLIENT_MAX_AGE_SECS);
    }
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn single_client_within_limit() {
        let limiter = RpcRateLimiter::new(10, 10);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow 10 requests (bucket capacity)
        for _ in 0..10 {
            assert!(limiter.try_consume(ip));
        }
    }

    #[test]
    fn single_client_exceeds_limit() {
        let limiter = RpcRateLimiter::new(5, 5);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Exhaust the bucket
        for _ in 0..5 {
            assert!(limiter.try_consume(ip));
        }

        // 6th request should be blocked
        assert!(!limiter.try_consume(ip));
    }

    #[test]
    fn multiple_clients_independent() {
        let limiter = RpcRateLimiter::new(3, 3);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust ip1's bucket
        for _ in 0..3 {
            assert!(limiter.try_consume(ip1));
        }
        assert!(!limiter.try_consume(ip1));

        // ip2 should still have full bucket
        for _ in 0..3 {
            assert!(limiter.try_consume(ip2));
        }

        assert_eq!(limiter.client_count(), 2);
    }

    #[test]
    fn default_rpc_limiter_uses_constants() {
        let limiter = RpcRateLimiter::default_rpc();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Should allow RPC_BUCKET_CAPACITY requests
        for _ in 0..RPC_BUCKET_CAPACITY {
            assert!(limiter.try_consume(ip));
        }

        // Next should be blocked
        assert!(!limiter.try_consume(ip));
    }
}
