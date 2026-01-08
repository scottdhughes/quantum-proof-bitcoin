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
