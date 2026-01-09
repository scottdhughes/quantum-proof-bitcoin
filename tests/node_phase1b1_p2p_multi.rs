use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::thread;

use hex::FromHex;
use tempfile::tempdir;

use qpb_consensus::node::chainparams::{load_chainparams, select_network};
use qpb_consensus::node::node::Node;
use qpb_consensus::node::p2p::{
    CMD_BLOCK, CMD_GETDATA, CMD_GETHEADERS, CMD_HEADERS, CMD_VERACK, CMD_VERSION,
    MAX_MESSAGE_BYTES, SyncOpts, read_message, ser_version, sync_with_retries,
    write_headers_payload, write_message,
};
use qpb_consensus::pow::pow_hash;
use qpb_consensus::script::build_p2qpkh;
use qpb_consensus::types::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};

fn coinbase_tx(message: &[u8], value: u64, spk: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0xffff_ffff,
            },
            script_sig: message.to_vec(),
            sequence: 0xffff_ffff,
            witness: Vec::new(),
        }],
        vout: vec![TxOut {
            value,
            script_pubkey: spk,
        }],
        lock_time: 0,
    }
}

fn build_block(prev_hash: [u8; 32], height: u32, coin_value: u64) -> Block {
    let pkhash = [0x11u8; 32];
    let spk = build_p2qpkh(pkhash);
    let cb = coinbase_tx(b"phase1b1 p2p", coin_value, spk);
    let merkle = cb.txid();
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_766_620_800 + height,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txdata: vec![cb],
    }
}

fn serialize_block(block: &Block) -> Vec<u8> {
    block.serialize(true)
}

/// Get block hash using Argon2id PoW hash (same as node uses).
fn block_hash(block: &Block) -> [u8; 32] {
    pow_hash(&block.header).unwrap()
}

/// Build a block with specific nonce (for creating different chains).
fn build_block_with_nonce(prev_hash: [u8; 32], height: u32, coin_value: u64, nonce: u32) -> Block {
    let pkhash = [0x11u8; 32];
    let spk = build_p2qpkh(pkhash);
    let cb = coinbase_tx(
        format!("chain h={} n={}", height, nonce).as_bytes(),
        coin_value,
        spk,
    );
    let merkle = cb.txid();
    Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: prev_hash,
            merkle_root: merkle,
            time: 1_766_620_800 + height,
            bits: 0x207f_ffff,
            nonce,
        },
        txdata: vec![cb],
    }
}

fn start_bad_peer(magic: [u8; 4]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Immediately send oversized message to trigger max size guard
        let payload = vec![0u8; (MAX_MESSAGE_BYTES + 1) as usize];
        let mut header = Vec::new();
        header.extend_from_slice(&magic);
        header.extend_from_slice(b"junk\0\0\0\0\0\0\0\0");
        header.extend_from_slice(&(MAX_MESSAGE_BYTES + 1).to_le_bytes());
        header.extend_from_slice(&[0u8; 4]);
        header.extend_from_slice(&payload[..16]); // send partial to exercise read logic
        let _ = stream.write_all(&header);
    });
    addr
}

fn start_good_peer(magic: [u8; 4], genesis_hash: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();

        // expect version, reply version+verack
        let _ = read_message(&mut stream, magic).unwrap();
        let ver = ser_version(0);
        write_message(&mut stream, magic, CMD_VERSION, &ver).unwrap();
        write_message(&mut stream, magic, CMD_VERACK, &[]).unwrap();
        let _ = read_message(&mut stream, magic).unwrap(); // verack

        // wait getheaders
        let gh = read_message(&mut stream, magic).unwrap();
        assert_eq!(gh.command, CMD_GETHEADERS);

        let mut prev = [0u8; 32];
        prev.copy_from_slice(&Vec::from_hex(&genesis_hash).unwrap());
        let block = build_block(prev, 1, qpb_consensus::reward::block_subsidy(1));
        let header = block.header.clone();
        let mut payload = Vec::new();
        write_headers_payload(&mut payload, &[header]);
        write_message(&mut stream, magic, CMD_HEADERS, &payload).unwrap();

        // expect getdata
        let gd = read_message(&mut stream, magic).unwrap();
        assert_eq!(gd.command, CMD_GETDATA);
        // reply block
        let block_bytes = serialize_block(&block);
        write_message(&mut stream, magic, CMD_BLOCK, &block_bytes).unwrap();
    });
    addr
}

#[test]
#[cfg_attr(miri, ignore)] // Network test uses sockets
fn p2p_multi_peer_fallback_succeeds() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let params = load_chainparams(std::path::Path::new("docs/chain/chainparams.json")).unwrap();
    let net = select_network(&params, "devnet").unwrap();
    let magic = hex::decode(&net.p2p_magic).unwrap().try_into().unwrap();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();
    let bad = start_bad_peer(magic);
    let good = start_good_peer(magic, node.best_hash_hex().to_string());

    let peers = vec![bad.parse().unwrap(), good.parse().unwrap()];
    let opts = SyncOpts {
        max_attempts_per_peer: 2,
        initial_backoff_ms: 50,
        max_backoff_ms: 200,
        total_deadline_ms: 2_000,
    };
    sync_with_retries(&mut node, net, &peers, &opts).expect("sync should succeed");
    assert_eq!(node.height(), 1);
}

/// Start a mock peer that serves a divergent chain from genesis.
///
/// This simulates the scenario where:
/// 1. Local node has chain A: genesis -> A1 -> A2 -> A3
/// 2. Peer has chain B: genesis -> B1 -> B2 -> B3 -> B4 -> B5 (longer, different)
/// 3. When local node requests GETHEADERS, peer returns B chain
/// 4. Since chains diverged at genesis, headers start from genesis's successor
fn start_divergent_chain_peer(
    magic: [u8; 4],
    genesis_hash: [u8; 32],
    chain_length: u32,
    nonce_seed: u32,
) -> (String, Vec<Block>) {
    use std::time::Duration;

    // Pre-build the divergent chain (different nonces = different hashes than local)
    let mut blocks = Vec::new();
    let mut prev_hash = genesis_hash;
    eprintln!(
        "[MOCK-MAIN] building chain with {} blocks, genesis={}",
        chain_length,
        hex::encode(genesis_hash)
    );
    for h in 1..=chain_length {
        let block = build_block_with_nonce(
            prev_hash,
            h,
            qpb_consensus::reward::block_subsidy(h),
            nonce_seed + h,
        );
        let bh = block_hash(&block);
        eprintln!(
            "[MOCK-MAIN] block[{}] hash={} prev={}",
            h,
            hex::encode(bh),
            hex::encode(prev_hash)
        );
        prev_hash = bh;
        blocks.push(block);
    }
    let blocks_for_thread = blocks.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        eprintln!("[MOCK] peer thread started");
        let (mut stream, _) = listener.accept().unwrap();
        eprintln!("[MOCK] connection accepted");
        // Set read/write timeouts for the mock peer
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        // Handshake: expect VERSION, reply VERSION+VERACK
        let msg = read_message(&mut stream, magic).unwrap();
        eprintln!("[MOCK] received: {}", msg.command);
        let ver = ser_version(chain_length as i32);
        write_message(&mut stream, magic, CMD_VERSION, &ver).unwrap();
        write_message(&mut stream, magic, CMD_VERACK, &[]).unwrap();
        eprintln!("[MOCK] sent VERSION+VERACK");
        let msg = read_message(&mut stream, magic).unwrap(); // VERACK
        eprintln!("[MOCK] received: {}", msg.command);

        // Wait for GETHEADERS
        let gh = read_message(&mut stream, magic).unwrap();
        eprintln!("[MOCK] received: {} (expecting getheaders)", gh.command);
        assert_eq!(gh.command, CMD_GETHEADERS);

        // Send all headers from our chain B
        let headers: Vec<_> = blocks_for_thread.iter().map(|b| b.header.clone()).collect();
        eprintln!("[MOCK] our block hashes:");
        for (i, block) in blocks_for_thread.iter().enumerate() {
            eprintln!("  [{}] {}", i, hex::encode(block_hash(block)));
        }
        let mut payload = Vec::new();
        write_headers_payload(&mut payload, &headers);
        write_message(&mut stream, magic, CMD_HEADERS, &payload).unwrap();
        eprintln!("[MOCK] sent {} headers", headers.len());

        // Serve blocks in order as GETDATA requests come in
        // (client requests them in header order, so we track index)
        let mut next_block_idx = 0;
        loop {
            let msg = match read_message(&mut stream, magic) {
                Ok(m) => m,
                Err(_) => break, // Connection closed or timeout
            };

            match msg.command.as_str() {
                CMD_GETDATA => {
                    // Send the next block in sequence
                    if next_block_idx < blocks_for_thread.len() {
                        let block_bytes = serialize_block(&blocks_for_thread[next_block_idx]);
                        let _ = write_message(&mut stream, magic, CMD_BLOCK, &block_bytes);
                        next_block_idx += 1;
                    }
                }
                CMD_GETHEADERS => {
                    // After syncing all blocks, client asks for more headers
                    // Send empty headers to indicate sync complete
                    let mut empty_payload = Vec::new();
                    write_headers_payload(&mut empty_payload, &[]);
                    let _ = write_message(&mut stream, magic, CMD_HEADERS, &empty_payload);
                    // If we've served all blocks, we're done
                    if next_block_idx >= blocks_for_thread.len() {
                        break;
                    }
                }
                _ => {} // Ignore other messages
            }
        }
    });
    (addr, blocks)
}

/// Simple test: node at genesis syncs to peer's longer chain.
/// This verifies basic P2P sync works (no reorg complexity).
#[test]
#[cfg_attr(miri, ignore)] // Network test uses sockets
fn p2p_sync_from_genesis_to_longer_chain() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let params = load_chainparams(std::path::Path::new("docs/chain/chainparams.json")).unwrap();
    let net = select_network(&params, "devnet").unwrap();
    let magic: [u8; 4] = hex::decode(&net.p2p_magic).unwrap().try_into().unwrap();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Get genesis hash
    let genesis_hex = node.best_hash_hex().to_string();
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&Vec::from_hex(&genesis_hex).unwrap());
    assert_eq!(node.height(), 0, "should start at genesis");

    // Start mock peer with chain: genesis -> B1 -> B2 -> B3 -> B4 -> B5
    let (peer_addr, peer_blocks) = start_divergent_chain_peer(magic, genesis_hash, 5, 100);
    let expected_tip_hash = block_hash(&peer_blocks[4]); // B5

    // Sync from the peer
    let peers = vec![peer_addr.parse().unwrap()];
    let opts = SyncOpts {
        max_attempts_per_peer: 3,
        initial_backoff_ms: 50,
        max_backoff_ms: 200,
        total_deadline_ms: 10_000,
    };
    sync_with_retries(&mut node, net, &peers, &opts).expect("sync should succeed");

    // Verify: node should be at height 5
    assert_eq!(node.height(), 5, "should have synced to height 5");
    assert_eq!(
        node.best_hash_hex(),
        hex::encode(expected_tip_hash),
        "should be on peer's tip"
    );
}

/// Regression test for Issue #90: divergent chain sync after restart.
///
/// This test verifies that a node can sync to a peer's longer chain when:
/// 1. Local node has chain A (shorter)
/// 2. Peer has chain B (longer, divergent from genesis)
/// 3. Node correctly reorgs to chain B via P2P sync
///
/// This exercises the fix for the genesis parent hash edge case where
/// headers[0].prev_blockhash could be [0u8; 32] when chains diverge early.
#[test]
#[cfg_attr(miri, ignore)] // Network test uses sockets
fn p2p_divergent_chain_sync_reorgs_to_longer() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let params = load_chainparams(std::path::Path::new("docs/chain/chainparams.json")).unwrap();
    let net = select_network(&params, "devnet").unwrap();
    let magic: [u8; 4] = hex::decode(&net.p2p_magic).unwrap().try_into().unwrap();

    let mut node = Node::open_or_init(
        "devnet",
        datadir,
        Path::new("docs/chain/chainparams.json"),
        true,
        false,
    )
    .unwrap();

    // Get genesis hash
    let genesis_hex = node.best_hash_hex().to_string();
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(&Vec::from_hex(&genesis_hex).unwrap());
    assert_eq!(node.height(), 0, "should start at genesis");

    // Build local chain A: genesis -> A1 -> A2 -> A3 (nonce=1)
    let mut prev_hash = genesis_hash;
    for h in 1..=3 {
        let block = build_block_with_nonce(
            prev_hash,
            h,
            qpb_consensus::reward::block_subsidy(h),
            1, // nonce=1 for chain A
        );
        prev_hash = block_hash(&block);
        node.submit_block_bytes(&block.serialize(true)).unwrap();
    }
    assert_eq!(node.height(), 3, "local chain should be at height 3");
    let local_tip_before = node.best_hash_hex().to_string();

    // Start mock peer with divergent chain B: genesis -> B1 -> B2 -> B3 -> B4 -> B5 (nonce=100)
    let (peer_addr, peer_blocks) = start_divergent_chain_peer(magic, genesis_hash, 5, 100);
    let expected_tip_hash = block_hash(&peer_blocks[4]); // B5

    // Sync from the divergent peer
    let peers = vec![peer_addr.parse().unwrap()];
    let opts = SyncOpts {
        max_attempts_per_peer: 3,
        initial_backoff_ms: 50,
        max_backoff_ms: 200,
        total_deadline_ms: 10_000,
    };
    sync_with_retries(&mut node, net, &peers, &opts).expect("sync should succeed");

    // Verify: node should have reorged to chain B (longer)
    assert_eq!(node.height(), 5, "should have reorged to height 5");
    let final_tip = node.best_hash_hex().to_string();
    assert_ne!(
        final_tip, local_tip_before,
        "tip should have changed after reorg"
    );
    assert_eq!(
        final_tip,
        hex::encode(expected_tip_hash),
        "should be on chain B tip"
    );
}
