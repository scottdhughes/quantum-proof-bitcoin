use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::node::chainparams::NetworkParams;
use crate::node::node::{AddTxResult, Node};
use crate::pow::pow_hash;
use crate::types::BlockHeader;
use crate::varint::{read_compact_size, write_compact_size};

pub const CMD_VERSION: &str = "version";
pub const CMD_VERACK: &str = "verack";
#[allow(dead_code)]
pub const CMD_PING: &str = "ping";
#[allow(dead_code)]
pub const CMD_PONG: &str = "pong";
pub const CMD_GETHEADERS: &str = "getheaders";
pub const CMD_HEADERS: &str = "headers";
pub const CMD_GETDATA: &str = "getdata";
pub const CMD_BLOCK: &str = "block";
pub const CMD_INV: &str = "inv";
pub const CMD_TX: &str = "tx";
pub const CMD_GETADDR: &str = "getaddr";
pub const CMD_ADDR: &str = "addr";

/// Inventory type for transactions.
pub const MSG_TX: u32 = 1;
/// Inventory type for blocks.
pub const MSG_BLOCK: u32 = 2;

pub const DEFAULT_READ_TIMEOUT_MS: u64 = 2000;
pub const DEFAULT_WRITE_TIMEOUT_MS: u64 = 2000;
pub const MAX_MESSAGE_BYTES: u32 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct SyncOpts {
    pub max_attempts_per_peer: usize,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub total_deadline_ms: u64,
}

impl Default for SyncOpts {
    fn default() -> Self {
        Self {
            max_attempts_per_peer: 3,
            initial_backoff_ms: 250,
            max_backoff_ms: 5_000,
            total_deadline_ms: 30_000,
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub command: String,
    pub payload: Vec<u8>,
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let h = Sha256::digest(Sha256::digest(payload));
    let mut c = [0u8; 4];
    c.copy_from_slice(&h[..4]);
    c
}

pub fn write_message(
    stream: &mut TcpStream,
    magic: [u8; 4],
    command: &str,
    payload: &[u8],
) -> Result<()> {
    stream.set_write_timeout(Some(Duration::from_millis(DEFAULT_WRITE_TIMEOUT_MS)))?;
    let mut header = Vec::with_capacity(24 + payload.len());
    header.extend_from_slice(&magic);
    let mut cmd_bytes = [0u8; 12];
    let b = command.as_bytes();
    let n = b.len().min(12);
    cmd_bytes[..n].copy_from_slice(&b[..n]);
    header.extend_from_slice(&cmd_bytes);
    header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    header.extend_from_slice(&checksum(payload));
    header.extend_from_slice(payload);
    stream.write_all(&header)?;
    Ok(())
}

fn read_exact_timeout(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)))?;
    let mut buf = vec![0u8; len];
    let mut read = 0;
    while read < len {
        let n = stream.read(&mut buf[read..])?;
        if n == 0 {
            return Err(anyhow!("unexpected EOF"));
        }
        read += n;
    }
    Ok(buf)
}

pub fn read_message(stream: &mut TcpStream, magic: [u8; 4]) -> Result<Message> {
    let mut header = [0u8; 24];
    stream.set_read_timeout(Some(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)))?;
    stream.read_exact(&mut header)?;
    if header[..4] != magic {
        return Err(anyhow!("magic mismatch"));
    }
    let cmd_raw = &header[4..16];
    if !cmd_raw.iter().all(|b| *b == 0 || (0x20..=0x7e).contains(b)) {
        return Err(anyhow!("invalid command bytes"));
    }
    let cmd = String::from_utf8_lossy(cmd_raw)
        .trim_end_matches('\0')
        .to_string();
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap());
    if len > MAX_MESSAGE_BYTES {
        return Err(anyhow!("message too large"));
    }
    let cksum = &header[20..24];
    let payload = read_exact_timeout(stream, len as usize)?;
    if checksum(&payload) != cksum {
        return Err(anyhow!("checksum mismatch"));
    }
    Ok(Message {
        command: cmd,
        payload,
    })
}

pub fn ser_version(start_height: i32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&70015i32.to_le_bytes()); // version
    p.extend_from_slice(&0u64.to_le_bytes()); // services
    p.extend_from_slice(&(0i64).to_le_bytes()); // time
    // addr_recv
    p.extend_from_slice(&0u64.to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&0u16.to_be_bytes());
    // addr_from
    p.extend_from_slice(&0u64.to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u64.to_le_bytes()); // nonce
    write_compact_size(0, &mut p); // user agent empty
    p.extend_from_slice(&start_height.to_le_bytes());
    p.push(0); // relay false
    p
}

pub fn ser_getheaders(locator_hashes: Vec<[u8; 32]>) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&70015i32.to_le_bytes());
    write_compact_size(locator_hashes.len() as u64, &mut p);
    for h in locator_hashes {
        let mut le = h;
        le.reverse();
        p.extend_from_slice(&le);
    }
    p.extend_from_slice(&[0u8; 32]); // stop
    p
}

fn parse_headers(payload: &[u8]) -> Result<Vec<BlockHeader>> {
    let mut cur = std::io::Cursor::new(payload.to_vec());
    let count = read_compact_size(&mut cur)? as usize;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let mut hbuf = [0u8; 80];
        cur.read_exact(&mut hbuf)?;
        let header = parse_header_bytes(&hbuf)?;
        let _txcount = read_compact_size(&mut cur)?; // should be 0
        headers.push(header);
    }
    Ok(headers)
}

fn parse_header_bytes(hbuf: &[u8; 80]) -> Result<BlockHeader> {
    let mut cur = std::io::Cursor::new(hbuf.to_vec());
    let mut vbuf = [0u8; 4];
    cur.read_exact(&mut vbuf)?;
    let version = u32::from_le_bytes(vbuf);

    let mut prev_le = [0u8; 32];
    cur.read_exact(&mut prev_le)?;
    let mut prev_blockhash = [0u8; 32];
    prev_blockhash.copy_from_slice(&prev_le.iter().rev().cloned().collect::<Vec<_>>());

    let mut merkle_le = [0u8; 32];
    cur.read_exact(&mut merkle_le)?;
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&merkle_le.iter().rev().cloned().collect::<Vec<_>>());

    cur.read_exact(&mut vbuf)?;
    let time = u32::from_le_bytes(vbuf);
    cur.read_exact(&mut vbuf)?;
    let bits = u32::from_le_bytes(vbuf);
    cur.read_exact(&mut vbuf)?;
    let nonce = u32::from_le_bytes(vbuf);

    Ok(BlockHeader {
        version,
        prev_blockhash,
        merkle_root,
        time,
        bits,
        nonce,
    })
}

pub fn ser_getdata_block(hash: [u8; 32]) -> Vec<u8> {
    let mut p = Vec::new();
    write_compact_size(1, &mut p);
    p.extend_from_slice(&MSG_BLOCK.to_le_bytes());
    let mut le = hash;
    le.reverse();
    p.extend_from_slice(&le);
    p
}

/// Serialize an INV message for transaction announcements.
pub fn ser_inv_tx(txids: &[[u8; 32]]) -> Vec<u8> {
    let mut p = Vec::new();
    write_compact_size(txids.len() as u64, &mut p);
    for txid in txids {
        p.extend_from_slice(&MSG_TX.to_le_bytes());
        let mut le = *txid;
        le.reverse();
        p.extend_from_slice(&le);
    }
    p
}

/// Serialize a GETDATA message for transactions.
pub fn ser_getdata_tx(txids: &[[u8; 32]]) -> Vec<u8> {
    let mut p = Vec::new();
    write_compact_size(txids.len() as u64, &mut p);
    for txid in txids {
        p.extend_from_slice(&MSG_TX.to_le_bytes());
        let mut le = *txid;
        le.reverse();
        p.extend_from_slice(&le);
    }
    p
}

/// Inventory entry parsed from INV or GETDATA message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvEntry {
    pub inv_type: u32,
    pub hash: [u8; 32],
}

/// Parse INV or GETDATA payload into inventory entries.
pub fn parse_inv(payload: &[u8]) -> Result<Vec<InvEntry>> {
    let mut cur = std::io::Cursor::new(payload.to_vec());
    let count = read_compact_size(&mut cur)? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let mut type_buf = [0u8; 4];
        cur.read_exact(&mut type_buf)?;
        let inv_type = u32::from_le_bytes(type_buf);

        let mut hash_le = [0u8; 32];
        cur.read_exact(&mut hash_le)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_le.iter().rev().cloned().collect::<Vec<_>>());

        entries.push(InvEntry { inv_type, hash });
    }
    Ok(entries)
}

pub fn write_headers_payload(buf: &mut Vec<u8>, headers: &[BlockHeader]) {
    write_compact_size(headers.len() as u64, buf);
    for h in headers {
        buf.extend_from_slice(&h.serialize());
        buf.push(0); // tx count
    }
}

// ============================================================================
// Address Messages (getaddr/addr)
// ============================================================================

/// Maximum addresses to send in a single ADDR message.
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Maximum addresses to accept in a single ADDR message.
pub const MAX_ADDR_TO_RECEIVE: usize = 1000;

/// Network address entry as sent in ADDR messages.
///
/// Bitcoin protocol format: time(4) + services(8) + IPv6(16) + port(2) = 30 bytes
#[derive(Debug, Clone)]
pub struct NetAddr {
    /// Unix timestamp when this address was last seen.
    pub time: u32,
    /// Service flags (NODE_NETWORK, etc.).
    pub services: u64,
    /// IPv6 address (IPv4 mapped to ::ffff:a.b.c.d).
    pub ip: [u8; 16],
    /// Network port in network byte order.
    pub port: u16,
}

impl NetAddr {
    /// Create from a SocketAddr with current timestamp.
    pub fn from_socket_addr(addr: &std::net::SocketAddr, services: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        Self::from_socket_addr_with_time(addr, services, now)
    }

    /// Create from a SocketAddr with specific timestamp.
    pub fn from_socket_addr_with_time(
        addr: &std::net::SocketAddr,
        services: u64,
        time: u32,
    ) -> Self {
        use std::net::SocketAddr;

        let ip = match addr {
            SocketAddr::V4(v4) => {
                // IPv4-mapped IPv6 address: ::ffff:a.b.c.d
                let octets = v4.ip().octets();
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1], octets[2],
                    octets[3],
                ]
            }
            SocketAddr::V6(v6) => v6.ip().octets(),
        };

        Self {
            time,
            services,
            ip,
            port: addr.port(),
        }
    }

    /// Convert to SocketAddr.
    pub fn to_socket_addr(&self) -> Option<std::net::SocketAddr> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        // Check for IPv4-mapped address
        if self.ip[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
            let ip = Ipv4Addr::new(self.ip[12], self.ip[13], self.ip[14], self.ip[15]);
            Some(SocketAddr::new(IpAddr::V4(ip), self.port))
        } else {
            let ip = Ipv6Addr::from(self.ip);
            Some(SocketAddr::new(IpAddr::V6(ip), self.port))
        }
    }

    /// Serialize for wire format (30 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(30);
        buf.extend_from_slice(&self.time.to_le_bytes());
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(&self.ip);
        buf.extend_from_slice(&self.port.to_be_bytes()); // Network byte order!
        buf
    }
}

/// Parse ADDR message payload.
pub fn parse_addr(payload: &[u8]) -> Result<Vec<NetAddr>> {
    let mut cur = std::io::Cursor::new(payload.to_vec());
    let count = read_compact_size(&mut cur)? as usize;

    if count > MAX_ADDR_TO_RECEIVE {
        return Err(anyhow!("too many addresses: {}", count));
    }

    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut time_buf = [0u8; 4];
        let mut services_buf = [0u8; 8];
        let mut ip_buf = [0u8; 16];
        let mut port_buf = [0u8; 2];

        cur.read_exact(&mut time_buf)?;
        cur.read_exact(&mut services_buf)?;
        cur.read_exact(&mut ip_buf)?;
        cur.read_exact(&mut port_buf)?;

        addrs.push(NetAddr {
            time: u32::from_le_bytes(time_buf),
            services: u64::from_le_bytes(services_buf),
            ip: ip_buf,
            port: u16::from_be_bytes(port_buf), // Network byte order!
        });
    }

    Ok(addrs)
}

/// Serialize ADDR message payload.
pub fn ser_addr(addrs: &[NetAddr]) -> Vec<u8> {
    let mut buf = Vec::new();
    let count = addrs.len().min(MAX_ADDR_TO_SEND);
    write_compact_size(count as u64, &mut buf);
    for addr in addrs.iter().take(count) {
        buf.extend_from_slice(&addr.serialize());
    }
    buf
}

/// Serialize empty GETADDR message (no payload).
pub fn ser_getaddr() -> Vec<u8> {
    Vec::new()
}

pub fn sync_headers_and_blocks(node: &mut Node, net: &NetworkParams, addr: &str) -> Result<()> {
    let magic_bytes = hex::decode(&net.p2p_magic)?
        .try_into()
        .map_err(|_| anyhow!("bad magic"))?;
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(DEFAULT_WRITE_TIMEOUT_MS)))?;

    // handshake
    let version_payload = ser_version(node.height() as i32);
    write_message(&mut stream, magic_bytes, CMD_VERSION, &version_payload)?;
    // expect peer version then verack
    let msg = read_message(&mut stream, magic_bytes)?;
    if msg.command != CMD_VERSION {
        return Err(anyhow!("expected version"));
    }
    write_message(&mut stream, magic_bytes, CMD_VERACK, &[])?;
    let _ = read_message(&mut stream, magic_bytes)?; // peer verack or version; tolerate one extra

    // getheaders with locator = tip
    let tip_hash = hex::decode(node.best_hash_hex())?;
    let mut h = [0u8; 32];
    h.copy_from_slice(&tip_hash);
    let gh_payload = ser_getheaders(vec![h]);
    write_message(&mut stream, magic_bytes, CMD_GETHEADERS, &gh_payload)?;

    let headers_msg = read_message(&mut stream, magic_bytes)?;
    if headers_msg.command != CMD_HEADERS {
        return Err(anyhow!("expected headers"));
    }
    let headers = parse_headers(&headers_msg.payload)?;

    for header in headers {
        if hex::encode(header.prev_blockhash) != node.best_hash_hex() {
            return Err(anyhow!("header does not extend tip"));
        }
        let block_hash = pow_hash(&header)?;
        let block_hash_hex = hex::encode(block_hash);
        let gd_payload = ser_getdata_block(block_hash);
        write_message(&mut stream, magic_bytes, CMD_GETDATA, &gd_payload)?;
        let blk_msg = read_message(&mut stream, magic_bytes)?;
        if blk_msg.command != CMD_BLOCK {
            return Err(anyhow!("expected block"));
        }
        node.submit_block_bytes(&blk_msg.payload)?;
        // ensure tip advanced
        if node.best_hash_hex() != block_hash_hex {
            return Err(anyhow!("submit did not advance tip"));
        }
    }
    Ok(())
}

pub fn sync_with_retries(
    node: &mut Node,
    net: &NetworkParams,
    peers: &[std::net::SocketAddr],
    opts: &SyncOpts,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(opts.total_deadline_ms))
        .unwrap_or_else(Instant::now);
    for peer in peers {
        let mut backoff = Duration::from_millis(opts.initial_backoff_ms);
        for attempt in 0..opts.max_attempts_per_peer {
            if Instant::now() >= deadline {
                return Err(anyhow!("p2p sync deadline exceeded"));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let addr_str = peer.to_string();
            match sync_headers_and_blocks(node, net, &addr_str) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    // last attempt or deadline exceeded
                    if attempt + 1 == opts.max_attempts_per_peer {
                        break;
                    }
                    let sleep_dur = backoff.min(remaining);
                    std::thread::sleep(sleep_dur);
                    backoff = std::cmp::min(
                        Duration::from_millis(opts.max_backoff_ms),
                        backoff.saturating_mul(2),
                    );
                    // continue to next attempt
                    let _ = e; // silence unused in non-logging builds
                }
            }
        }
    }
    Err(anyhow!("p2p sync failed for all peers"))
}

// ============================================================================
// Transaction Relay
// ============================================================================

use crate::types::Transaction;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// A connected peer for transaction relay.
pub struct PeerConnection {
    stream: TcpStream,
    magic: [u8; 4],
    /// Txids we've already sent to this peer (avoid duplicates).
    sent_txids: HashSet<[u8; 32]>,
    /// Txids we've received INV for but not yet requested.
    #[allow(dead_code)]
    pending_inv: HashSet<[u8; 32]>,
}

impl PeerConnection {
    /// Connect to a peer and complete handshake.
    pub fn connect(addr: &str, magic: [u8; 4], height: i32) -> Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)))?;
        stream.set_write_timeout(Some(Duration::from_millis(DEFAULT_WRITE_TIMEOUT_MS)))?;

        // Handshake
        let version_payload = ser_version(height);
        write_message(&mut stream, magic, CMD_VERSION, &version_payload)?;
        let msg = read_message(&mut stream, magic)?;
        if msg.command != CMD_VERSION {
            return Err(anyhow!("expected version"));
        }
        write_message(&mut stream, magic, CMD_VERACK, &[])?;
        let _ = read_message(&mut stream, magic)?; // peer verack

        Ok(Self {
            stream,
            magic,
            sent_txids: HashSet::new(),
            pending_inv: HashSet::new(),
        })
    }

    /// Announce a transaction via INV message.
    pub fn announce_tx(&mut self, txid: [u8; 32]) -> Result<()> {
        if self.sent_txids.contains(&txid) {
            return Ok(()); // Already announced
        }
        let payload = ser_inv_tx(&[txid]);
        write_message(&mut self.stream, self.magic, CMD_INV, &payload)?;
        self.sent_txids.insert(txid);
        Ok(())
    }

    /// Send a raw transaction.
    pub fn send_tx(&mut self, tx: &Transaction) -> Result<()> {
        let payload = tx.serialize(true);
        write_message(&mut self.stream, self.magic, CMD_TX, &payload)?;
        Ok(())
    }

    /// Request transactions by txid.
    pub fn request_txs(&mut self, txids: &[[u8; 32]]) -> Result<()> {
        if txids.is_empty() {
            return Ok(());
        }
        let payload = ser_getdata_tx(txids);
        write_message(&mut self.stream, self.magic, CMD_GETDATA, &payload)?;
        Ok(())
    }

    /// Read and handle one message. Returns parsed transaction if TX received.
    pub fn recv_message(&mut self) -> Result<Option<PeerMessage>> {
        let msg = read_message(&mut self.stream, self.magic)?;
        match msg.command.as_str() {
            CMD_INV => {
                let entries = parse_inv(&msg.payload)?;
                let txids: Vec<[u8; 32]> = entries
                    .into_iter()
                    .filter(|e| e.inv_type == MSG_TX)
                    .map(|e| e.hash)
                    .collect();
                Ok(Some(PeerMessage::Inv { txids }))
            }
            CMD_TX => {
                // Parse raw transaction
                let tx = parse_transaction(&msg.payload)?;
                Ok(Some(PeerMessage::Tx(tx)))
            }
            CMD_GETDATA => {
                let entries = parse_inv(&msg.payload)?;
                let txids: Vec<[u8; 32]> = entries
                    .into_iter()
                    .filter(|e| e.inv_type == MSG_TX)
                    .map(|e| e.hash)
                    .collect();
                Ok(Some(PeerMessage::GetData { txids }))
            }
            _ => Ok(None), // Ignore other messages
        }
    }
}

/// Messages relevant to transaction relay.
#[derive(Debug)]
pub enum PeerMessage {
    /// Received INV with transaction hashes.
    Inv { txids: Vec<[u8; 32]> },
    /// Received a transaction.
    Tx(Transaction),
    /// Peer requesting transactions.
    GetData { txids: Vec<[u8; 32]> },
}

/// Parse a raw transaction from bytes.
fn parse_transaction(bytes: &[u8]) -> Result<Transaction> {
    use std::io::Cursor;

    let mut cur = Cursor::new(bytes.to_vec());
    let mut vbuf = [0u8; 4];
    cur.read_exact(&mut vbuf)?;
    let version = i32::from_le_bytes(vbuf);

    // SegWit detection
    let mut marker = [0u8; 1];
    cur.read_exact(&mut marker)?;
    let mut segwit = false;
    if marker[0] == 0x00 {
        let mut flag = [0u8; 1];
        cur.read_exact(&mut flag)?;
        if flag[0] == 0x01 {
            segwit = true;
        } else {
            cur.set_position(cur.position() - 2);
        }
    } else {
        cur.set_position(cur.position() - 1);
    }

    use crate::types::{OutPoint, TxIn, TxOut};

    let vin_len = read_compact_size(&mut cur)? as usize;
    let mut vin = Vec::with_capacity(vin_len);
    for _ in 0..vin_len {
        let mut txid_le = [0u8; 32];
        cur.read_exact(&mut txid_le)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_le.iter().rev().cloned().collect::<Vec<_>>());
        let mut voutb = [0u8; 4];
        cur.read_exact(&mut voutb)?;
        let vout = u32::from_le_bytes(voutb);
        let script_len = read_compact_size(&mut cur)? as usize;
        let mut script_sig = vec![0u8; script_len];
        cur.read_exact(&mut script_sig)?;
        cur.read_exact(&mut voutb)?;
        let sequence = u32::from_le_bytes(voutb);
        vin.push(TxIn {
            prevout: OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }

    let vout_len = read_compact_size(&mut cur)? as usize;
    let mut vout_vec = Vec::with_capacity(vout_len);
    for _ in 0..vout_len {
        let mut valb = [0u8; 8];
        cur.read_exact(&mut valb)?;
        let value = u64::from_le_bytes(valb);
        let spk_len = read_compact_size(&mut cur)? as usize;
        let mut script_pubkey = vec![0u8; spk_len];
        cur.read_exact(&mut script_pubkey)?;
        vout_vec.push(TxOut {
            value,
            script_pubkey,
        });
    }

    if segwit {
        for txin in vin.iter_mut() {
            let items = read_compact_size(&mut cur)? as usize;
            let mut stack = Vec::with_capacity(items);
            for _ in 0..items {
                let len = read_compact_size(&mut cur)? as usize;
                let mut item = vec![0u8; len];
                cur.read_exact(&mut item)?;
                stack.push(item);
            }
            txin.witness = stack;
        }
    }

    let mut ltb = [0u8; 4];
    cur.read_exact(&mut ltb)?;
    let lock_time = u32::from_le_bytes(ltb);

    Ok(Transaction {
        version,
        vin,
        vout: vout_vec,
        lock_time,
    })
}

/// Manager for multiple peer connections with shared state.
pub struct RelayManager {
    peers: Vec<Arc<Mutex<PeerConnection>>>,
    /// Txids we know about (either in mempool or already relayed).
    known_txids: HashSet<[u8; 32]>,
}

impl RelayManager {
    /// Create a new relay manager.
    pub fn new() -> Self {
        Self {
            peers: Vec::new(),
            known_txids: HashSet::new(),
        }
    }

    /// Add a connected peer.
    pub fn add_peer(&mut self, peer: PeerConnection) {
        self.peers.push(Arc::new(Mutex::new(peer)));
    }

    /// Broadcast a transaction to all connected peers.
    pub fn broadcast_tx(&mut self, txid: [u8; 32]) {
        self.known_txids.insert(txid);
        for peer in &self.peers {
            if let Ok(mut p) = peer.lock() {
                let _ = p.announce_tx(txid);
            }
        }
    }

    /// Check if we know about a transaction.
    pub fn knows_tx(&self, txid: &[u8; 32]) -> bool {
        self.known_txids.contains(txid)
    }

    /// Mark a transaction as known.
    pub fn mark_known(&mut self, txid: [u8; 32]) {
        self.known_txids.insert(txid);
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Inbound Connection Handling
// ============================================================================

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use crate::constants::{DEFAULT_DEVNET_PORT, DEFAULT_TESTNET_PORT, HANDSHAKE_TIMEOUT_MS};
use crate::node::peer::{Misbehavior, PeerDirection, PeerManager};

/// Parsed VERSION message from a peer.
#[derive(Debug, Clone)]
pub struct PeerVersion {
    /// Protocol version (e.g., 70015).
    pub version: i32,
    /// Service flags.
    pub services: u64,
    /// Peer's reported timestamp.
    pub timestamp: i64,
    /// Peer's reported block height.
    pub start_height: i32,
    /// Whether peer wants relay.
    pub relay: bool,
}

/// Parse a VERSION message payload.
pub fn parse_version(payload: &[u8]) -> Result<PeerVersion> {
    if payload.len() < 85 {
        return Err(anyhow!("VERSION payload too short"));
    }

    let version = i32::from_le_bytes(payload[0..4].try_into().unwrap());
    let services = u64::from_le_bytes(payload[4..12].try_into().unwrap());
    let timestamp = i64::from_le_bytes(payload[12..20].try_into().unwrap());

    // Skip addr_recv (26 bytes) and addr_from (26 bytes) and nonce (8 bytes)
    // That's 20 + 26 + 26 + 8 = 80 bytes
    // Then user_agent varint + string, then start_height (4 bytes), then relay (1 byte)

    let mut cur = std::io::Cursor::new(&payload[80..]);
    let user_agent_len = read_compact_size(&mut cur)? as usize;
    let pos = cur.position() as usize;

    // Skip user agent string
    let remaining = &payload[80 + pos + user_agent_len..];
    if remaining.len() < 4 {
        return Err(anyhow!("VERSION payload missing start_height"));
    }

    let start_height = i32::from_le_bytes(remaining[0..4].try_into().unwrap());
    let relay = if remaining.len() > 4 {
        remaining[4] != 0
    } else {
        true // Default to relay if not specified
    };

    Ok(PeerVersion {
        version,
        services,
        timestamp,
        start_height,
        relay,
    })
}

/// Perform handshake as responder (for inbound connections).
///
/// Handshake order for responder:
/// 1. Receive VERSION from peer
/// 2. Send our VERSION
/// 3. Send VERACK
/// 4. Receive VERACK from peer
pub fn handle_inbound_handshake(
    stream: &mut TcpStream,
    magic: [u8; 4],
    our_height: i32,
) -> Result<PeerVersion> {
    // Set handshake-specific timeout
    stream.set_read_timeout(Some(Duration::from_millis(HANDSHAKE_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(HANDSHAKE_TIMEOUT_MS)))?;

    // 1. Wait for VERSION from peer
    let msg = read_message(stream, magic)?;
    if msg.command != CMD_VERSION {
        return Err(anyhow!("expected VERSION, got {}", msg.command));
    }
    let peer_version = parse_version(&msg.payload)?;

    // 2. Send our VERSION
    let our_version = ser_version(our_height);
    write_message(stream, magic, CMD_VERSION, &our_version)?;

    // 3. Send VERACK
    write_message(stream, magic, CMD_VERACK, &[])?;

    // 4. Wait for VERACK (tolerate VERSION if peer sends it again)
    let verack_msg = read_message(stream, magic)?;
    if verack_msg.command != CMD_VERACK && verack_msg.command != CMD_VERSION {
        return Err(anyhow!("expected VERACK, got {}", verack_msg.command));
    }

    // Restore normal timeouts
    stream.set_read_timeout(Some(Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)))?;
    stream.set_write_timeout(Some(Duration::from_millis(DEFAULT_WRITE_TIMEOUT_MS)))?;

    Ok(peer_version)
}

/// Serialize a PONG response (nonce from PING).
pub fn ser_pong(nonce: u64) -> Vec<u8> {
    nonce.to_le_bytes().to_vec()
}

/// Serialize a HEADERS response.
pub fn ser_headers(headers: &[BlockHeader]) -> Vec<u8> {
    let mut p = Vec::new();
    write_compact_size(headers.len() as u64, &mut p);
    for header in headers {
        ser_header(header, &mut p);
        p.push(0); // tx count = 0
    }
    p
}

/// Serialize a single block header.
fn ser_header(header: &BlockHeader, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&header.version.to_le_bytes());
    let mut prev_le = header.prev_blockhash;
    prev_le.reverse();
    buf.extend_from_slice(&prev_le);
    let mut merkle_le = header.merkle_root;
    merkle_le.reverse();
    buf.extend_from_slice(&merkle_le);
    buf.extend_from_slice(&header.time.to_le_bytes());
    buf.extend_from_slice(&header.bits.to_le_bytes());
    buf.extend_from_slice(&header.nonce.to_le_bytes());
}

/// Parse a GETHEADERS message.
pub fn parse_getheaders(payload: &[u8]) -> Result<(Vec<[u8; 32]>, [u8; 32])> {
    let mut cur = std::io::Cursor::new(payload.to_vec());
    let mut vbuf = [0u8; 4];
    cur.read_exact(&mut vbuf)?; // protocol version

    let count = read_compact_size(&mut cur)? as usize;
    let mut locator = Vec::with_capacity(count);
    for _ in 0..count {
        let mut hash_le = [0u8; 32];
        cur.read_exact(&mut hash_le)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_le.iter().rev().cloned().collect::<Vec<_>>());
        locator.push(hash);
    }

    let mut stop_le = [0u8; 32];
    cur.read_exact(&mut stop_le)?;
    let mut stop = [0u8; 32];
    stop.copy_from_slice(&stop_le.iter().rev().cloned().collect::<Vec<_>>());

    Ok((locator, stop))
}

/// Parse a GETDATA message.
pub fn parse_getdata(payload: &[u8]) -> Result<Vec<InvEntry>> {
    parse_inv(payload)
}

/// Configuration for the inbound listener.
#[derive(Debug, Clone)]
pub struct InboundConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Network magic bytes.
    pub magic: [u8; 4],
    /// Maximum inbound connections.
    pub max_inbound: usize,
}

/// Inbound connection listener.
///
/// Accepts incoming TCP connections, performs handshake, and spawns
/// worker threads to handle each peer.
pub struct InboundListener {
    /// TCP listener handle.
    listener: TcpListener,
    /// Network magic bytes.
    magic: [u8; 4],
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Listener thread handle.
    thread_handle: Option<JoinHandle<()>>,
}

impl InboundListener {
    /// Create a new inbound listener bound to the given address.
    pub fn bind(config: InboundConfig) -> Result<Self> {
        let listener = TcpListener::bind(config.bind_addr)?;
        listener.set_nonblocking(false)?;

        Ok(Self {
            listener,
            magic: config.magic,
            shutdown: Arc::new(AtomicBool::new(false)),
            thread_handle: None,
        })
    }

    /// Get the local address we're listening on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Start accepting connections in a background thread.
    ///
    /// The node reference is used to access chain state for serving requests.
    /// The peer manager is used for connection limits and peer tracking.
    pub fn start<F>(
        &mut self,
        node: Arc<Mutex<Node>>,
        peer_manager: Arc<PeerManager>,
        on_peer_connected: F,
    ) where
        F: Fn(u64, PeerVersion) + Send + Sync + 'static,
    {
        let listener = self.listener.try_clone().expect("clone listener");
        let magic = self.magic;
        let shutdown = self.shutdown.clone();
        let on_connected = Arc::new(on_peer_connected);

        let handle = thread::spawn(move || {
            for stream_result in listener.incoming() {
                // Check shutdown flag
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                let mut stream = match stream_result {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "accept error");
                        continue;
                    }
                };

                let peer_addr = match stream.peer_addr() {
                    Ok(addr) => addr.to_string(),
                    Err(_) => continue,
                };

                // Check connection limits
                if let Err(denied) = peer_manager.can_accept_inbound(&peer_addr) {
                    debug!(%peer_addr, reason = %denied, "rejecting inbound connection");
                    continue;
                }

                // Get current height for handshake
                let our_height = {
                    let node = node.lock().unwrap();
                    node.height() as i32
                };

                // Perform handshake
                let peer_version = match handle_inbound_handshake(&mut stream, magic, our_height) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(%peer_addr, error = %e, "handshake failed");
                        continue;
                    }
                };

                // Register peer
                let peer_id = peer_manager.add_peer(
                    peer_addr.clone(),
                    PeerDirection::Inbound,
                    peer_version.version,
                    peer_version.services,
                    peer_version.start_height,
                );

                info!(
                    %peer_addr,
                    peer_id,
                    version = peer_version.version,
                    height = peer_version.start_height,
                    "inbound peer connected"
                );

                // Notify callback
                on_connected(peer_id, peer_version.clone());

                // Spawn message handler thread
                let node_clone = node.clone();
                let peer_manager_clone = peer_manager.clone();
                let shutdown_clone = shutdown.clone();

                thread::spawn(move || {
                    if let Err(e) = handle_inbound_messages(
                        stream,
                        magic,
                        peer_id,
                        node_clone,
                        peer_manager_clone.clone(),
                        shutdown_clone,
                    ) {
                        debug!(peer_id, error = %e, "peer disconnected");
                    }
                    peer_manager_clone.remove_peer(peer_id);
                });
            }
        });

        self.thread_handle = Some(handle);
    }

    /// Signal the listener to stop accepting connections.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Connect to ourselves to unblock accept()
        let _ = TcpStream::connect(self.listener.local_addr().unwrap());
    }

    /// Wait for the listener thread to finish.
    pub fn join(self) {
        if let Some(handle) = self.thread_handle {
            let _ = handle.join();
        }
    }
}

/// Handle messages from an inbound peer.
fn handle_inbound_messages(
    mut stream: TcpStream,
    magic: [u8; 4],
    peer_id: u64,
    node: Arc<Mutex<Node>>,
    peer_manager: Arc<PeerManager>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let msg = match read_message(&mut stream, magic) {
            Ok(m) => m,
            Err(e) => {
                // Check if it's a timeout (normal) or actual error
                if e.to_string().contains("timed out") {
                    // On timeout, process any pending relay transactions
                    let to_relay = peer_manager.take_relay_for_peer(peer_id);
                    if !to_relay.is_empty() {
                        let payload = ser_inv_tx(&to_relay);
                        write_message(&mut stream, magic, CMD_INV, &payload)?;
                    }
                    continue;
                }
                return Err(e);
            }
        };

        // Rate limiting
        if let Some(peer_arc) = peer_manager.get_peer(peer_id) {
            let mut peer = peer_arc.lock().unwrap();
            if !peer.msg_limiter.try_consume(1) {
                let should_ban = peer.score.record(Misbehavior::RateLimitExceeded);
                if should_ban {
                    return Err(anyhow!("rate limit exceeded, banned"));
                }
                continue;
            }
        }

        match msg.command.as_str() {
            CMD_GETHEADERS => {
                handle_getheaders(&mut stream, magic, &msg.payload, &node)?;
            }
            CMD_GETDATA => {
                handle_getdata(&mut stream, magic, &msg.payload, &node)?;
            }
            CMD_PING => {
                handle_ping(&mut stream, magic, &msg.payload)?;
            }
            CMD_INV => {
                // Parse inventory announcements and request unknown transactions
                let entries = parse_inv(&msg.payload)?;
                let mut tx_requests: Vec<[u8; 32]> = Vec::new();

                // Check rate limit for tx processing
                if let Some(peer_arc) = peer_manager.get_peer(peer_id) {
                    let mut peer = peer_arc.lock().unwrap();
                    if !peer.tx_limiter.try_consume(entries.len() as u32) {
                        // Rate limited - skip processing but don't disconnect
                        continue;
                    }
                }

                let node_guard = node.lock().unwrap();
                for entry in entries {
                    if entry.inv_type == MSG_TX {
                        // Only request if not already in mempool
                        if !node_guard.mempool_contains(&entry.hash) {
                            tx_requests.push(entry.hash);
                        }
                    }
                }
                drop(node_guard);

                // Send GETDATA for unknown transactions
                if !tx_requests.is_empty() {
                    let payload = ser_getdata_tx(&tx_requests);
                    write_message(&mut stream, magic, CMD_GETDATA, &payload)?;
                }
            }
            CMD_TX => {
                // Parse and validate incoming transaction
                let tx = parse_transaction(&msg.payload)?;
                let txid = tx.txid();

                // Rate limit tx processing
                if let Some(peer_arc) = peer_manager.get_peer(peer_id) {
                    let mut peer = peer_arc.lock().unwrap();
                    if !peer.tx_limiter.try_consume(1) {
                        // Rate limited - skip but don't disconnect
                        continue;
                    }
                    // Track that we received this tx from this peer
                    peer.received_from.insert(txid);
                }

                // Add to mempool (or orphan pool if parents missing)
                let mut node_guard = node.lock().unwrap();
                match node_guard.add_transaction_or_orphan(tx, Some(peer_id)) {
                    AddTxResult::Accepted(txid) => {
                        drop(node_guard);
                        // Queue for relay to other peers
                        peer_manager.queue_relay(peer_id, txid);
                    }
                    AddTxResult::Orphaned {
                        txid: _,
                        missing: _,
                    } => {
                        // Orphaned - already buffered, no relay needed yet
                    }
                    AddTxResult::Rejected(_reason) => {
                        // Could penalize peer for bad tx, but skip for now
                    }
                }
            }
            CMD_GETADDR => {
                // Peer is requesting known addresses
                // For now, send empty response (no address manager integration yet)
                let payload = ser_addr(&[]);
                write_message(&mut stream, magic, CMD_ADDR, &payload)?;
            }
            CMD_ADDR => {
                // Peer is sharing addresses - parse and log for now
                match parse_addr(&msg.payload) {
                    Ok(addrs) => {
                        if !addrs.is_empty() {
                            debug!(peer_id, count = addrs.len(), "peer shared addresses");
                        }
                    }
                    Err(e) => {
                        warn!(peer_id, error = %e, "failed to parse ADDR message");
                    }
                }
            }
            _ => {
                // Ignore unknown messages
            }
        }
    }

    Ok(())
}

/// Handle a GETHEADERS request.
fn handle_getheaders(
    stream: &mut TcpStream,
    magic: [u8; 4],
    payload: &[u8],
    node: &Arc<Mutex<Node>>,
) -> Result<()> {
    let (locator, _stop) = parse_getheaders(payload)?;

    let node_guard = node.lock().unwrap();

    // Find the first locator hash we have by checking heights
    let mut start_height: u64 = 0;
    for hash in &locator {
        let hash_hex = hex::encode(hash);
        // Check if we have this block by trying to get its bytes
        if node_guard.get_block_bytes(&hash_hex).is_some() {
            // Found a known block, start from the next one
            // We need to find its height - scan from tip down
            for h in (0..=node_guard.height()).rev() {
                if let Some(h_hex) = node_guard.get_blockhash(h)
                    && h_hex == hash_hex
                {
                    start_height = h + 1;
                    break;
                }
            }
            break;
        }
    }

    // Gather up to 2000 headers
    let mut headers = Vec::new();
    let max_headers = 2000;
    let tip = node_guard.height();

    for h in start_height..=tip {
        if headers.len() >= max_headers {
            break;
        }
        if let Some(hash_hex) = node_guard.get_blockhash(h)
            && let Some(block_bytes) = node_guard.get_block_bytes(&hash_hex)
            && block_bytes.len() >= 80
            && let Ok(header) = parse_header_bytes(block_bytes[..80].try_into().unwrap())
        {
            headers.push(header);
        }
    }

    drop(node_guard); // Release lock before I/O

    let response = ser_headers(&headers);
    write_message(stream, magic, CMD_HEADERS, &response)?;

    Ok(())
}

/// Handle a GETDATA request.
fn handle_getdata(
    stream: &mut TcpStream,
    magic: [u8; 4],
    payload: &[u8],
    node: &Arc<Mutex<Node>>,
) -> Result<()> {
    let entries = parse_getdata(payload)?;

    for entry in entries {
        match entry.inv_type {
            MSG_BLOCK => {
                let hash_hex = hex::encode(entry.hash);
                let node_guard = node.lock().unwrap();
                if let Some(block_bytes) = node_guard.get_block_bytes(&hash_hex) {
                    drop(node_guard);
                    write_message(stream, magic, CMD_BLOCK, &block_bytes)?;
                }
            }
            MSG_TX => {
                let node_guard = node.lock().unwrap();
                if let Some(tx) = node_guard.mempool_get(&entry.hash) {
                    let tx_bytes = tx.serialize(true);
                    drop(node_guard);
                    write_message(stream, magic, CMD_TX, &tx_bytes)?;
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Handle a PING request with PONG response.
fn handle_ping(stream: &mut TcpStream, magic: [u8; 4], payload: &[u8]) -> Result<()> {
    // PING payload is 8-byte nonce, reply with same nonce
    if payload.len() >= 8 {
        let nonce = u64::from_le_bytes(payload[0..8].try_into().unwrap());
        let pong = ser_pong(nonce);
        write_message(stream, magic, CMD_PONG, &pong)?;
    }
    Ok(())
}

/// Get default port for a chain.
pub fn default_port_for_chain(chain: &str) -> u16 {
    match chain {
        "mainnet" => crate::constants::DEFAULT_MAINNET_PORT,
        "testnet" => DEFAULT_TESTNET_PORT,
        _ => DEFAULT_DEVNET_PORT,
    }
}
