use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};

use crate::node::chainparams::NetworkParams;
use crate::node::node::Node;
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
