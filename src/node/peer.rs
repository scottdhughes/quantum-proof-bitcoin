//! Peer scoring, banning, and rate limiting for P2P network protection.
//!
//! This module provides:
//! - `Misbehavior`: Categories of peer misbehavior with penalty scores
//! - `PeerScore`: Per-peer score tracking with time-based decay
//! - `BanList`: Persistent ban list with temporary and permanent bans
//! - `RateLimiter`: Token bucket rate limiting
//! - `ConnectionLimiter`: Limits connections per IP/subnet

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::constants::{
    MAX_CONNECTIONS_PER_IP, MAX_CONNECTIONS_PER_SUBNET, MAX_INBOUND_CONNECTIONS,
    MAX_MISBEHAVIOR_LOG, MAX_OUTBOUND_CONNECTIONS, MESSAGE_BUCKET_CAPACITY, PEER_BAN_THRESHOLD,
    PEER_SCORE_DECAY_PER_HOUR,
};

// ============================================================================
// Misbehavior
// ============================================================================

/// Categories of peer misbehavior with associated penalty points.
///
/// When a peer's accumulated score reaches `PEER_BAN_THRESHOLD` (100),
/// they are disconnected and banned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Misbehavior {
    /// Invalid block header (bad PoW, invalid timestamp, etc.)
    InvalidBlockHeader,
    /// Invalid block content (bad merkle root, invalid transactions)
    InvalidBlock,
    /// Invalid transaction (consensus rule violation)
    InvalidTransaction,
    /// Malformed P2P message (unparseable)
    MalformedMessage,
    /// Message checksum mismatch
    ChecksumMismatch,
    /// Peer timeout / unresponsive
    Timeout,
    /// Unsolicited message (e.g., unrequested block)
    UnsolicitedMessage,
    /// Submitted too many orphan transactions
    ExcessiveOrphans,
    /// Message rate limit exceeded
    RateLimitExceeded,
    /// Block violates a checkpoint
    CheckpointViolation,
}

impl Misbehavior {
    /// Get the penalty points for this misbehavior.
    ///
    /// Scores >= 100 result in immediate ban.
    pub fn penalty(&self) -> u32 {
        match self {
            Misbehavior::InvalidBlockHeader => 50,
            Misbehavior::InvalidBlock => 100, // Immediate ban
            Misbehavior::InvalidTransaction => 10,
            Misbehavior::MalformedMessage => 20,
            Misbehavior::ChecksumMismatch => 50,
            Misbehavior::Timeout => 5,
            Misbehavior::UnsolicitedMessage => 10,
            Misbehavior::ExcessiveOrphans => 20,
            Misbehavior::RateLimitExceeded => 30,
            Misbehavior::CheckpointViolation => 100, // Immediate ban
        }
    }

    /// Get a human-readable description of this misbehavior.
    pub fn description(&self) -> &'static str {
        match self {
            Misbehavior::InvalidBlockHeader => "sent invalid block header",
            Misbehavior::InvalidBlock => "sent invalid block",
            Misbehavior::InvalidTransaction => "sent invalid transaction",
            Misbehavior::MalformedMessage => "sent malformed message",
            Misbehavior::ChecksumMismatch => "message checksum mismatch",
            Misbehavior::Timeout => "connection timeout",
            Misbehavior::UnsolicitedMessage => "sent unsolicited message",
            Misbehavior::ExcessiveOrphans => "submitted too many orphans",
            Misbehavior::RateLimitExceeded => "exceeded rate limit",
            Misbehavior::CheckpointViolation => "sent checkpoint-violating block",
        }
    }
}

// ============================================================================
// PeerScore
// ============================================================================

/// Entry in the misbehavior log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisbehaviorEntry {
    /// Unix timestamp when misbehavior occurred.
    pub timestamp: u64,
    /// The type of misbehavior.
    pub behavior: Misbehavior,
    /// Points assigned.
    pub points: u32,
}

/// Per-peer scoring state.
///
/// Tracks misbehavior and allows score decay over time.
#[derive(Debug, Clone, Default)]
pub struct PeerScore {
    /// Current misbehavior score (0 = good, 100+ = should ban).
    score: u32,
    /// Unix timestamp of last score update (for decay calculation).
    last_update: u64,
    /// Recent misbehavior log for debugging.
    log: Vec<MisbehaviorEntry>,
}

impl PeerScore {
    /// Create a new peer score starting at 0.
    pub fn new() -> Self {
        Self {
            score: 0,
            last_update: current_unix_time(),
            log: Vec::new(),
        }
    }

    /// Get the current score (after applying decay).
    pub fn current_score(&mut self) -> u32 {
        self.apply_decay();
        self.score
    }

    /// Record a misbehavior and return true if the peer should be banned.
    pub fn record(&mut self, behavior: Misbehavior) -> bool {
        self.apply_decay();

        let points = behavior.penalty();
        self.score = self.score.saturating_add(points);
        self.last_update = current_unix_time();

        // Add to log
        self.log.push(MisbehaviorEntry {
            timestamp: self.last_update,
            behavior,
            points,
        });

        // Trim log if too long
        if self.log.len() > MAX_MISBEHAVIOR_LOG {
            self.log.remove(0);
        }

        self.score >= PEER_BAN_THRESHOLD
    }

    /// Check if this peer should be banned based on current score.
    pub fn should_ban(&mut self) -> bool {
        self.current_score() >= PEER_BAN_THRESHOLD
    }

    /// Apply time-based score decay.
    fn apply_decay(&mut self) {
        let now = current_unix_time();
        let elapsed_secs = now.saturating_sub(self.last_update);
        let elapsed_hours = elapsed_secs / 3600;

        if elapsed_hours > 0 {
            let decay = (elapsed_hours as u32).saturating_mul(PEER_SCORE_DECAY_PER_HOUR);
            self.score = self.score.saturating_sub(decay);
            self.last_update = now;
        }
    }

    /// Get the misbehavior log.
    pub fn get_log(&self) -> &[MisbehaviorEntry] {
        &self.log
    }

    /// Get the raw score without applying decay.
    pub fn raw_score(&self) -> u32 {
        self.score
    }
}

// ============================================================================
// BanList
// ============================================================================

/// A ban entry for a specific address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEntry {
    /// IP address (stored as string for flexibility).
    pub address: String,
    /// Unix timestamp when ban was created.
    pub ban_time: u64,
    /// Unix timestamp when ban expires (0 = permanent).
    pub unban_time: u64,
    /// Reason for the ban.
    pub reason: String,
}

impl BanEntry {
    /// Check if this ban has expired.
    pub fn is_expired(&self) -> bool {
        if self.unban_time == 0 {
            return false; // Permanent ban
        }
        current_unix_time() >= self.unban_time
    }

    /// Check if this is a permanent ban.
    pub fn is_permanent(&self) -> bool {
        self.unban_time == 0
    }
}

/// Persistent ban list manager.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BanList {
    /// Map of IP address to ban entry.
    bans: HashMap<String, BanEntry>,
    /// Path to persistence file (not serialized).
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl BanList {
    /// Create a new empty ban list.
    pub fn new() -> Self {
        Self {
            bans: HashMap::new(),
            path: None,
        }
    }

    /// Load ban list from a file, or create empty if file doesn't exist.
    pub fn load(datadir: &Path) -> Result<Self> {
        let path = datadir.join("banlist.json");

        let mut ban_list = if path.exists() {
            let data = fs::read_to_string(&path)?;
            let mut list: BanList = serde_json::from_str(&data)?;
            list.path = Some(path);
            list
        } else {
            let mut list = BanList::new();
            list.path = Some(path);
            list
        };

        // Prune expired bans on load
        ban_list.prune_expired();

        Ok(ban_list)
    }

    /// Save the ban list to disk.
    pub fn save(&self) -> Result<()> {
        if let Some(ref path) = self.path {
            let data = serde_json::to_string_pretty(self)?;
            fs::write(path, data)?;
        }
        Ok(())
    }

    /// Add a temporary ban.
    pub fn ban_temporarily(&mut self, addr: &str, duration_secs: u64, reason: &str) {
        let now = current_unix_time();
        let entry = BanEntry {
            address: normalize_address(addr),
            ban_time: now,
            unban_time: now + duration_secs,
            reason: reason.to_string(),
        };
        self.bans.insert(entry.address.clone(), entry);
        let _ = self.save();
    }

    /// Add a permanent ban.
    pub fn ban_permanently(&mut self, addr: &str, reason: &str) {
        let entry = BanEntry {
            address: normalize_address(addr),
            ban_time: current_unix_time(),
            unban_time: 0,
            reason: reason.to_string(),
        };
        self.bans.insert(entry.address.clone(), entry);
        let _ = self.save();
    }

    /// Check if an address is banned.
    pub fn is_banned(&self, addr: &str) -> bool {
        let normalized = normalize_address(addr);
        if let Some(entry) = self.bans.get(&normalized) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Remove expired bans and return count removed.
    pub fn prune_expired(&mut self) -> usize {
        let before = self.bans.len();
        self.bans.retain(|_, entry| !entry.is_expired());
        let removed = before - self.bans.len();
        if removed > 0 {
            let _ = self.save();
        }
        removed
    }

    /// Manually unban an address.
    pub fn unban(&mut self, addr: &str) -> bool {
        let normalized = normalize_address(addr);
        let removed = self.bans.remove(&normalized).is_some();
        if removed {
            let _ = self.save();
        }
        removed
    }

    /// Clear all bans.
    pub fn clear(&mut self) {
        self.bans.clear();
        let _ = self.save();
    }

    /// List all current bans (excluding expired).
    pub fn list_bans(&self) -> Vec<&BanEntry> {
        self.bans.values().filter(|e| !e.is_expired()).collect()
    }

    /// Get ban entry for an address if it exists and is active.
    pub fn get_ban(&self, addr: &str) -> Option<&BanEntry> {
        let normalized = normalize_address(addr);
        self.bans.get(&normalized).filter(|e| !e.is_expired())
    }

    /// Get number of active bans.
    pub fn len(&self) -> usize {
        self.bans.values().filter(|e| !e.is_expired()).count()
    }

    /// Check if ban list is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// RateLimiter
// ============================================================================

/// Token bucket rate limiter.
///
/// Allows bursts up to `max_tokens`, refills at `refill_rate` per second.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Current token count.
    tokens: u32,
    /// Maximum tokens (bucket capacity).
    max_tokens: u32,
    /// Tokens added per second.
    refill_rate: u32,
    /// Last refill timestamp (unix seconds).
    last_refill: u64,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            tokens: max_tokens, // Start full
            max_tokens,
            refill_rate,
            last_refill: current_unix_time(),
        }
    }

    /// Create a rate limiter for general messages.
    pub fn for_messages() -> Self {
        Self::new(
            MESSAGE_BUCKET_CAPACITY,
            crate::constants::MAX_MESSAGES_PER_SECOND,
        )
    }

    /// Create a rate limiter for transaction relay.
    pub fn for_tx_relay() -> Self {
        Self::new(
            crate::constants::TX_RELAY_BUCKET_CAPACITY,
            crate::constants::MAX_TX_RELAY_PER_SECOND,
        )
    }

    /// Refill tokens based on time elapsed.
    pub fn refill(&mut self) {
        let now = current_unix_time();
        let elapsed = now.saturating_sub(self.last_refill);

        if elapsed > 0 {
            let refill_amount = (elapsed as u32).saturating_mul(self.refill_rate);
            self.tokens = self
                .tokens
                .saturating_add(refill_amount)
                .min(self.max_tokens);
            self.last_refill = now;
        }
    }

    /// Try to consume tokens. Returns true if allowed, false if rate limited.
    pub fn try_consume(&mut self, count: u32) -> bool {
        self.refill();

        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }

    /// Check if a consumption would be allowed without actually consuming.
    pub fn would_allow(&mut self, count: u32) -> bool {
        self.refill();
        self.tokens >= count
    }

    /// Get current token count.
    pub fn tokens(&self) -> u32 {
        self.tokens
    }
}

// ============================================================================
// ConnectionLimiter
// ============================================================================

/// Connection limit enforcement per IP and subnet.
#[derive(Debug, Default)]
pub struct ConnectionLimiter {
    /// Connection count by IP address.
    by_ip: HashMap<String, usize>,
    /// Connection count by /16 subnet.
    by_subnet: HashMap<String, usize>,
    /// Total connection count.
    total: usize,
}

/// Reason a connection was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionDenied {
    /// Maximum total connections reached.
    MaxConnections,
    /// Maximum connections from this IP reached.
    MaxPerIP,
    /// Maximum connections from this subnet reached.
    MaxPerSubnet,
    /// Address is banned.
    Banned,
}

impl std::fmt::Display for ConnectionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionDenied::MaxConnections => write!(f, "maximum connections reached"),
            ConnectionDenied::MaxPerIP => write!(f, "too many connections from this IP"),
            ConnectionDenied::MaxPerSubnet => write!(f, "too many connections from this subnet"),
            ConnectionDenied::Banned => write!(f, "address is banned"),
        }
    }
}

impl ConnectionLimiter {
    /// Create a new connection limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a new connection from this address would be allowed.
    pub fn can_connect(
        &self,
        addr: &str,
        ban_list: Option<&BanList>,
    ) -> Result<(), ConnectionDenied> {
        // Check ban list first
        if let Some(bans) = ban_list
            && bans.is_banned(addr)
        {
            return Err(ConnectionDenied::Banned);
        }

        // Check total connections
        if self.total >= MAX_OUTBOUND_CONNECTIONS {
            return Err(ConnectionDenied::MaxConnections);
        }

        let ip = normalize_address(addr);
        let subnet = extract_subnet(&ip);

        // Check per-IP limit
        if let Some(&count) = self.by_ip.get(&ip)
            && count >= MAX_CONNECTIONS_PER_IP
        {
            return Err(ConnectionDenied::MaxPerIP);
        }

        // Check per-subnet limit
        if let Some(&count) = self.by_subnet.get(&subnet)
            && count >= MAX_CONNECTIONS_PER_SUBNET
        {
            return Err(ConnectionDenied::MaxPerSubnet);
        }

        Ok(())
    }

    /// Record a new connection.
    pub fn add_connection(&mut self, addr: &str) {
        let ip = normalize_address(addr);
        let subnet = extract_subnet(&ip);

        *self.by_ip.entry(ip).or_insert(0) += 1;
        *self.by_subnet.entry(subnet).or_insert(0) += 1;
        self.total += 1;
    }

    /// Remove a connection.
    pub fn remove_connection(&mut self, addr: &str) {
        let ip = normalize_address(addr);
        let subnet = extract_subnet(&ip);

        if let Some(count) = self.by_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.by_ip.remove(&ip);
            }
        }

        if let Some(count) = self.by_subnet.get_mut(&subnet) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.by_subnet.remove(&subnet);
            }
        }

        self.total = self.total.saturating_sub(1);
    }

    /// Get total connection count.
    pub fn total_connections(&self) -> usize {
        self.total
    }

    /// Get connection count for an IP.
    pub fn connections_from_ip(&self, addr: &str) -> usize {
        let ip = normalize_address(addr);
        self.by_ip.get(&ip).copied().unwrap_or(0)
    }

    /// Check if a new inbound connection would be allowed.
    ///
    /// Uses inbound-specific limits (MAX_INBOUND_CONNECTIONS) instead of outbound.
    pub fn can_accept_inbound(
        &self,
        addr: &str,
        current_inbound: usize,
        ban_list: Option<&BanList>,
    ) -> Result<(), ConnectionDenied> {
        // Check ban list first
        if let Some(bans) = ban_list
            && bans.is_banned(addr)
        {
            return Err(ConnectionDenied::Banned);
        }

        // Check inbound-specific limit
        if current_inbound >= MAX_INBOUND_CONNECTIONS {
            return Err(ConnectionDenied::MaxConnections);
        }

        let ip = normalize_address(addr);
        let subnet = extract_subnet(&ip);

        // Check per-IP limit
        if let Some(&count) = self.by_ip.get(&ip)
            && count >= MAX_CONNECTIONS_PER_IP
        {
            return Err(ConnectionDenied::MaxPerIP);
        }

        // Check per-subnet limit
        if let Some(&count) = self.by_subnet.get(&subnet)
            && count >= MAX_CONNECTIONS_PER_SUBNET
        {
            return Err(ConnectionDenied::MaxPerSubnet);
        }

        Ok(())
    }
}

// ============================================================================
// Peer Direction & Info
// ============================================================================

/// Direction of a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerDirection {
    /// We connected to the peer (outbound).
    Outbound,
    /// The peer connected to us (inbound).
    Inbound,
}

impl std::fmt::Display for PeerDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerDirection::Outbound => write!(f, "outbound"),
            PeerDirection::Inbound => write!(f, "inbound"),
        }
    }
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Unique peer identifier for this session.
    pub id: u64,
    /// Peer's socket address.
    pub addr: String,
    /// Connection direction.
    pub direction: PeerDirection,
    /// Peer's protocol version.
    pub version: i32,
    /// Peer's advertised services.
    pub services: u64,
    /// Peer's best block height at connection time.
    pub start_height: i32,
    /// Unix timestamp when connection was established.
    pub connected_at: u64,
    /// Peer's misbehavior score.
    pub score: PeerScore,
    /// Rate limiter for messages.
    pub msg_limiter: RateLimiter,
    /// Rate limiter for transaction relay.
    pub tx_limiter: RateLimiter,
    /// Txids we've sent INV for to this peer (avoid duplicate announcements).
    pub sent_inv: HashSet<[u8; 32]>,
    /// Txids we've received from this peer (avoid relaying back).
    pub received_from: HashSet<[u8; 32]>,
}

impl PeerInfo {
    /// Create a new PeerInfo for a connection.
    pub fn new(
        id: u64,
        addr: String,
        direction: PeerDirection,
        version: i32,
        services: u64,
        start_height: i32,
    ) -> Self {
        Self {
            id,
            addr,
            direction,
            version,
            services,
            start_height,
            connected_at: current_unix_time(),
            score: PeerScore::new(),
            msg_limiter: RateLimiter::for_messages(),
            tx_limiter: RateLimiter::for_tx_relay(),
            sent_inv: HashSet::new(),
            received_from: HashSet::new(),
        }
    }
}

// ============================================================================
// PeerManager
// ============================================================================

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Manages connected peers with thread-safe operations.
///
/// Tracks inbound/outbound connections, enforces limits, and provides
/// peer lookup by ID.
pub struct PeerManager {
    /// Connected peers indexed by ID.
    peers: Mutex<HashMap<u64, Arc<Mutex<PeerInfo>>>>,
    /// Connection limiter for IP/subnet enforcement.
    connection_limiter: Mutex<ConnectionLimiter>,
    /// Ban list reference.
    ban_list: Arc<Mutex<BanList>>,
    /// Next peer ID to assign.
    next_id: AtomicU64,
    /// Current inbound connection count.
    inbound_count: AtomicUsize,
    /// Current outbound connection count.
    outbound_count: AtomicUsize,
    /// Queue of (sender_peer_id, txid) for relay to other peers.
    relay_queue: Mutex<Vec<(u64, [u8; 32])>>,
}

impl PeerManager {
    /// Create a new peer manager with the given ban list.
    pub fn new(ban_list: Arc<Mutex<BanList>>) -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            connection_limiter: Mutex::new(ConnectionLimiter::new()),
            ban_list,
            next_id: AtomicU64::new(1),
            inbound_count: AtomicUsize::new(0),
            outbound_count: AtomicUsize::new(0),
            relay_queue: Mutex::new(Vec::new()),
        }
    }

    /// Check if a new inbound connection from this address is allowed.
    pub fn can_accept_inbound(&self, addr: &str) -> Result<(), ConnectionDenied> {
        let limiter = self.connection_limiter.lock().unwrap();
        let ban_list = self.ban_list.lock().unwrap();
        let inbound = self.inbound_count.load(Ordering::SeqCst);
        limiter.can_accept_inbound(addr, inbound, Some(&*ban_list))
    }

    /// Register a new peer and return its assigned ID.
    pub fn add_peer(
        &self,
        addr: String,
        direction: PeerDirection,
        version: i32,
        services: u64,
        start_height: i32,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let info = PeerInfo::new(id, addr.clone(), direction, version, services, start_height);

        // Update connection limiter
        {
            let mut limiter = self.connection_limiter.lock().unwrap();
            limiter.add_connection(&addr);
        }

        // Update counts
        match direction {
            PeerDirection::Inbound => {
                self.inbound_count.fetch_add(1, Ordering::SeqCst);
            }
            PeerDirection::Outbound => {
                self.outbound_count.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Store peer
        {
            let mut peers = self.peers.lock().unwrap();
            peers.insert(id, Arc::new(Mutex::new(info)));
        }

        id
    }

    /// Remove a peer by ID.
    pub fn remove_peer(&self, id: u64) -> Option<PeerInfo> {
        let peer_arc = {
            let mut peers = self.peers.lock().unwrap();
            peers.remove(&id)
        };

        if let Some(arc) = peer_arc {
            let info = arc.lock().unwrap().clone();

            // Update connection limiter
            {
                let mut limiter = self.connection_limiter.lock().unwrap();
                limiter.remove_connection(&info.addr);
            }

            // Update counts
            match info.direction {
                PeerDirection::Inbound => {
                    self.inbound_count.fetch_sub(1, Ordering::SeqCst);
                }
                PeerDirection::Outbound => {
                    self.outbound_count.fetch_sub(1, Ordering::SeqCst);
                }
            }

            Some(info)
        } else {
            None
        }
    }

    /// Get a peer by ID.
    pub fn get_peer(&self, id: u64) -> Option<Arc<Mutex<PeerInfo>>> {
        let peers = self.peers.lock().unwrap();
        peers.get(&id).cloned()
    }

    /// Get current peer counts: (inbound, outbound).
    pub fn peer_counts(&self) -> (usize, usize) {
        (
            self.inbound_count.load(Ordering::SeqCst),
            self.outbound_count.load(Ordering::SeqCst),
        )
    }

    /// Get total peer count.
    pub fn total_peers(&self) -> usize {
        let (inbound, outbound) = self.peer_counts();
        inbound + outbound
    }

    /// Get info for all connected peers.
    pub fn list_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers
            .values()
            .map(|arc| arc.lock().unwrap().clone())
            .collect()
    }

    /// Record misbehavior for a peer. Returns true if peer should be banned.
    pub fn record_misbehavior(&self, id: u64, behavior: Misbehavior) -> bool {
        if let Some(arc) = self.get_peer(id) {
            let mut info = arc.lock().unwrap();
            let should_ban = info.score.record(behavior);
            if should_ban {
                // Add to ban list
                let mut ban_list = self.ban_list.lock().unwrap();
                ban_list.ban_temporarily(
                    &info.addr,
                    crate::constants::DEFAULT_BAN_DURATION_SECS,
                    behavior.description(),
                );
            }
            should_ban
        } else {
            false
        }
    }

    /// Check if an address is banned.
    pub fn is_banned(&self, addr: &str) -> bool {
        let ban_list = self.ban_list.lock().unwrap();
        ban_list.is_banned(addr)
    }

    /// Queue a transaction for relay to other peers.
    /// The sender_id is excluded from relay targets.
    pub fn queue_relay(&self, sender_id: u64, txid: [u8; 32]) {
        let mut queue = self.relay_queue.lock().unwrap();
        queue.push((sender_id, txid));
    }

    /// Take pending relay items for a specific peer.
    /// Returns txids that should be announced to this peer (excludes sender, already-sent).
    pub fn take_relay_for_peer(&self, peer_id: u64) -> Vec<[u8; 32]> {
        let queue = self.relay_queue.lock().unwrap();
        let peer_arc = match self.get_peer(peer_id) {
            Some(arc) => arc,
            None => return Vec::new(),
        };

        let mut peer = peer_arc.lock().unwrap();
        let mut to_relay = Vec::new();

        for (sender_id, txid) in queue.iter() {
            // Skip if we're the sender
            if *sender_id == peer_id {
                continue;
            }
            // Skip if we received this tx from this peer
            if peer.received_from.contains(txid) {
                continue;
            }
            // Skip if we already announced to this peer
            if peer.sent_inv.contains(txid) {
                continue;
            }
            // Mark as sent and queue for relay
            peer.sent_inv.insert(*txid);
            to_relay.push(*txid);
        }

        to_relay
    }

    /// Clear processed relay items (call periodically to prevent unbounded growth).
    pub fn clear_relay_queue(&self) {
        let mut queue = self.relay_queue.lock().unwrap();
        queue.clear();
    }
}

impl std::fmt::Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (inbound, outbound) = self.peer_counts();
        f.debug_struct("PeerManager")
            .field("inbound_count", &inbound)
            .field("outbound_count", &outbound)
            .field(
                "next_id",
                &self.next_id.load(std::sync::atomic::Ordering::SeqCst),
            )
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current Unix timestamp in seconds.
fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Normalize an address string (extract IP, remove port).
fn normalize_address(addr: &str) -> String {
    // Handle formats: "1.2.3.4", "1.2.3.4:8333", "[::1]:8333"
    let addr = addr.trim();

    // IPv6 with brackets
    if addr.starts_with('[')
        && let Some(end) = addr.find(']')
    {
        return addr[1..end].to_string();
    }

    // IPv4 or IPv6 with port
    if let Some(idx) = addr.rfind(':') {
        // Check if this is IPv6 (multiple colons) or IPv4:port
        let before_colon = &addr[..idx];
        if before_colon.contains(':') {
            // IPv6 address, keep as-is if no brackets
            return addr.to_string();
        } else {
            // IPv4:port, strip port
            return before_colon.to_string();
        }
    }

    addr.to_string()
}

/// Extract /16 subnet from an IPv4 address.
fn extract_subnet(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}.0.0/16", parts[0], parts[1])
    } else {
        // IPv6 or invalid, use full address as "subnet"
        ip.to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn misbehavior_penalties() {
        assert_eq!(Misbehavior::InvalidBlock.penalty(), 100);
        assert_eq!(Misbehavior::Timeout.penalty(), 5);
        assert_eq!(Misbehavior::CheckpointViolation.penalty(), 100);
    }

    #[test]
    fn peer_score_accumulation() {
        let mut score = PeerScore::new();

        // Record minor infractions
        assert!(!score.record(Misbehavior::Timeout)); // 5 pts
        assert!(!score.record(Misbehavior::Timeout)); // 10 pts
        assert_eq!(score.raw_score(), 10);

        // Record medium infraction
        assert!(!score.record(Misbehavior::InvalidTransaction)); // 20 pts
        assert_eq!(score.raw_score(), 20);
    }

    #[test]
    fn peer_score_immediate_ban() {
        let mut score = PeerScore::new();

        // InvalidBlock triggers immediate ban
        let should_ban = score.record(Misbehavior::InvalidBlock);
        assert!(should_ban);
        assert!(score.should_ban());
    }

    #[test]
    fn peer_score_accumulates_to_ban() {
        let mut score = PeerScore::new();

        // Accumulate to ban threshold
        score.record(Misbehavior::InvalidBlockHeader); // 50
        assert!(!score.should_ban());

        score.record(Misbehavior::InvalidBlockHeader); // 100
        assert!(score.should_ban());
    }

    #[test]
    fn ban_list_temporary() {
        let dir = tempdir().unwrap();
        let mut bans = BanList::load(dir.path()).unwrap();

        bans.ban_temporarily("1.2.3.4", 3600, "test ban");
        assert!(bans.is_banned("1.2.3.4"));
        assert!(bans.is_banned("1.2.3.4:8333")); // Port stripped

        bans.unban("1.2.3.4");
        assert!(!bans.is_banned("1.2.3.4"));
    }

    #[test]
    fn ban_list_permanent() {
        let dir = tempdir().unwrap();
        let mut bans = BanList::load(dir.path()).unwrap();

        bans.ban_permanently("5.6.7.8", "permanent test");
        let entry = bans.get_ban("5.6.7.8").unwrap();
        assert!(entry.is_permanent());
        assert!(!entry.is_expired());
    }

    #[test]
    fn ban_list_persistence() {
        let dir = tempdir().unwrap();

        // Create and save
        {
            let mut bans = BanList::load(dir.path()).unwrap();
            bans.ban_permanently("10.0.0.1", "persist test");
        }

        // Reload and verify
        let bans = BanList::load(dir.path()).unwrap();
        assert!(bans.is_banned("10.0.0.1"));
    }

    #[test]
    fn rate_limiter_basic() {
        let mut limiter = RateLimiter::new(10, 1);

        // Can consume up to capacity
        assert!(limiter.try_consume(5));
        assert!(limiter.try_consume(5));
        assert!(!limiter.try_consume(1)); // Empty
    }

    #[test]
    fn connection_limiter_basic() {
        let mut limiter = ConnectionLimiter::new();

        assert!(limiter.can_connect("1.2.3.4", None).is_ok());
        limiter.add_connection("1.2.3.4");

        // Second connection from same IP should fail
        assert_eq!(
            limiter.can_connect("1.2.3.4", None),
            Err(ConnectionDenied::MaxPerIP)
        );

        // Different IP should work
        assert!(limiter.can_connect("5.6.7.8", None).is_ok());
    }

    #[test]
    fn connection_limiter_subnet() {
        let mut limiter = ConnectionLimiter::new();

        limiter.add_connection("1.2.3.4");
        limiter.add_connection("1.2.5.6"); // Same /16 subnet

        // Third from same subnet should fail
        assert_eq!(
            limiter.can_connect("1.2.9.9", None),
            Err(ConnectionDenied::MaxPerSubnet)
        );
    }

    #[test]
    fn normalize_address_variants() {
        assert_eq!(normalize_address("1.2.3.4"), "1.2.3.4");
        assert_eq!(normalize_address("1.2.3.4:8333"), "1.2.3.4");
        assert_eq!(normalize_address("[::1]:8333"), "::1");
    }

    #[test]
    fn extract_subnet_ipv4() {
        assert_eq!(extract_subnet("192.168.1.1"), "192.168.0.0/16");
        assert_eq!(extract_subnet("10.20.30.40"), "10.20.0.0/16");
    }
}
