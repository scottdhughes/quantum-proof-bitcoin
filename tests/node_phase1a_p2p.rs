use std::net::TcpListener;
use std::thread;

use hex::FromHex;
use tempfile::tempdir;

use qpb_consensus::node::chainparams::load_chainparams;
use qpb_consensus::node::chainparams::select_network;
use qpb_consensus::node::node::Node;
use qpb_consensus::node::p2p::{
    CMD_BLOCK, CMD_GETDATA, CMD_GETHEADERS, CMD_HEADERS, CMD_VERACK, CMD_VERSION, read_message,
    ser_version, sync_headers_and_blocks, write_message,
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
    let cb = coinbase_tx(b"phase1a p2p", coin_value, spk);
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

fn start_mock_peer(magic: [u8; 4], genesis_hash: String) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
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
        qpb_consensus::node::p2p::write_headers_payload(&mut payload, &[header]);
        write_message(&mut stream, magic, CMD_HEADERS, &payload).unwrap();

        // expect getdata
        let gd = read_message(&mut stream, magic).unwrap();
        assert_eq!(gd.command, CMD_GETDATA);
        // reply block
        let block_bytes = serialize_block(&block);
        write_message(&mut stream, magic, CMD_BLOCK, &block_bytes).unwrap();
    });
    (addr, handle)
}

#[test]
fn p2p_headers_first_sync_tip_only() {
    let dir = tempdir().unwrap();
    let datadir = dir.path();

    let params = load_chainparams(std::path::Path::new("docs/chain/chainparams.json")).unwrap();
    let net = select_network(&params, "devnet").unwrap();
    let magic = hex::decode(&net.p2p_magic).unwrap().try_into().unwrap();

    let mut node = Node::open_or_init("devnet", datadir, true).unwrap();
    assert_eq!(node.height(), 0);

    let (addr, handle) = start_mock_peer(magic, node.best_hash_hex().to_string());
    sync_headers_and_blocks(&mut node, net, &addr).unwrap();
    assert_eq!(node.height(), 1);

    handle.join().unwrap();
}
