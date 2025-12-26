use std::io::{Read, Write};
use std::net::TcpStream;

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

fn read_exact(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_message(stream: &mut TcpStream, magic: [u8; 4]) -> Result<Message> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header)?;
    if header[..4] != magic {
        return Err(anyhow!("magic mismatch"));
    }
    let cmd = String::from_utf8_lossy(&header[4..16])
        .trim_end_matches('\0')
        .to_string();
    let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
    let cksum = &header[20..24];
    let payload = read_exact(stream, len)?;
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
    p.extend_from_slice(&2u32.to_le_bytes()); // MSG_BLOCK
    let mut le = hash;
    le.reverse();
    p.extend_from_slice(&le);
    p
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
