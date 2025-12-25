use hex_literal::hex;
use qpb_consensus::{
    Block, BlockHeader, CHAIN_ID, OutPoint, Prevout, Transaction, TxIn, TxOut, bits_to_target,
    block_weight_wu, build_p2qtsh, penalty, qpb_sighash, validate_block_basic,
    validate_transaction_basic, validate_witness_commitment, witness_merkle_root,
};

fn genesis_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_blockhash: [0u8; 32],
        merkle_root: hex!("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
        time: 1735171200,
        bits: 0x1d00ffff,
        nonce: 2083236893,
    }
}

#[test]
fn chain_id_matches_genesis_header() {
    let h = genesis_header().hash();
    assert_eq!(h, CHAIN_ID);
}

#[test]
fn weight_and_penalty_math() {
    // 1 MB base, no witness -> 4,000,000 WU
    let wu = block_weight_wu(1_000_000, 0);
    assert_eq!(wu, 4_000_000);

    // Penalty example: W=6M, M=4M, subsidy=50 QPB (sat style: 5e9)
    let penalty_val = penalty(5_000_000_000, 6_000_000, 4_000_000);
    // ((6-4)/4)^2 = (0.5)^2 = 0.25 -> 25% of subsidy
    assert_eq!(penalty_val, 1_250_000_000);
}

#[test]
fn subsidy_halving_and_tail() {
    use qpb_consensus::block_subsidy;
    // height 0 -> 50 QPB
    assert_eq!(block_subsidy(0), 5_000_000_000);
    // after 1 halving
    assert_eq!(block_subsidy(210_000), 2_500_000_000);
    // way in the future, should floor at tail emission 0.1
    assert_eq!(block_subsidy(10_000_000), 10_000_000);
}

#[test]
fn bits_to_target_bitcoin_example() {
    let t = bits_to_target(0x1d00ffff).unwrap();
    assert_eq!(
        t,
        hex!("00000000ffff0000000000000000000000000000000000000000000000000000")
    );
}

#[test]
fn p2qpkh_sighash_and_validation() {
    // Minimal single-input, single-output tx.
    let prev_txid = [0u8; 32];
    let prevout = OutPoint {
        txid: prev_txid,
        vout: 0,
    };

    // pk_ser = alg_id || 64 zero bytes
    let mut pk_ser = Vec::with_capacity(65);
    pk_ser.push(0x30);
    pk_ser.extend_from_slice(&[0u8; 64]);

    // scriptPubKey = OP_3 PUSH32(qpkh)
    let qpkh = qpb_consensus::qpkh32(&pk_ser);
    let spk = qpb_consensus::build_p2qpkh(qpkh);

    let txin = TxIn {
        prevout,
        script_sig: Vec::new(),
        sequence: 0xffffffff,
        witness: vec![
            {
                // sig_ser = 324-byte sig + sighash byte
                let mut v = vec![0u8; 324];
                v.push(0x01); // SIGHASH_ALL
                v
            },
            pk_ser.clone(),
        ],
    };

    let txout = TxOut {
        value: 50_0000_0000, // 50 QPB (sat base)
        script_pubkey: spk.clone(),
    };

    let tx = Transaction {
        version: 1,
        vin: vec![txin],
        vout: vec![txout],
        lock_time: 0,
    };

    let prevouts = vec![Prevout {
        value: 50_0000_0000,
        script_pubkey: spk,
    }];

    // Ensure sighash is well-formed and 32 bytes.
    let msg = qpb_sighash(&tx, 0, &prevouts, 0x01, 0x00, None).unwrap();
    assert_eq!(msg.len(), 32);

    // Validate tx (stub PQ verify).
    let cost = validate_transaction_basic(&tx, &prevouts).unwrap();
    assert_eq!(cost, 1);
}

#[test]
fn p2qtsh_validation_simple_true_script() {
    // Leaf script: OP_1 (push true)
    let leaf_script = vec![0x51];

    // control block: [leaf_version|1] with empty merkle path
    let control_block = vec![0x01];

    let leaf_hash = qpb_consensus::qtap_leaf_hash(0x00, &leaf_script);
    let qroot = leaf_hash; // no branches
    let spk = build_p2qtsh(qroot);

    let prev_txid = [0u8; 32];
    let txin = TxIn {
        prevout: OutPoint {
            txid: prev_txid,
            vout: 0,
        },
        script_sig: Vec::new(),
        sequence: 0xffffffff,
        witness: vec![leaf_script.clone(), control_block.clone()],
    };
    let txout = TxOut {
        value: 1_0000,
        script_pubkey: spk.clone(),
    };
    let tx = Transaction {
        version: 1,
        vin: vec![txin],
        vout: vec![txout],
        lock_time: 0,
    };
    let prevouts = vec![Prevout {
        value: 1_0000,
        script_pubkey: spk,
    }];

    let cost = validate_transaction_basic(&tx, &prevouts).unwrap();
    assert_eq!(cost, 0);
}

#[test]
fn witness_commitment_validation() {
    // Build a block with coinbase + one witness-bearing tx (same as above)
    let leaf_script = vec![0x51];
    let control_block = vec![0x01];
    let leaf_hash = qpb_consensus::qtap_leaf_hash(0x00, &leaf_script);
    let qroot = leaf_hash;
    let spk = build_p2qtsh(qroot);

    let spend_tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: vec![leaf_script.clone(), control_block.clone()],
        }],
        vout: vec![TxOut {
            value: 1_0000,
            script_pubkey: spk.clone(),
        }],
        lock_time: 0,
    };

    // Coinbase with placeholder commitment; witness reserved value 32 bytes zero
    let mut coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0xffffffff,
            },
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: vec![vec![0u8; 32]],
        }],
        vout: vec![],
        lock_time: 0,
    };

    let mut block = Block {
        header: genesis_header(),
        txdata: vec![coinbase.clone(), spend_tx],
    };

    // Compute commitment and set coinbase output
    let wroot = witness_merkle_root(&block);
    let mut buf = Vec::new();
    buf.extend_from_slice(&wroot);
    buf.extend_from_slice(&coinbase.vin[0].witness[0]);
    let commitment_hash = qpb_consensus::hash256(&buf);

    coinbase.vout.push(TxOut {
        value: 0,
        script_pubkey: {
            let mut spk_c = Vec::with_capacity(38);
            spk_c.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
            spk_c.extend_from_slice(&commitment_hash);
            spk_c
        },
    });

    block.txdata[0] = coinbase;

    validate_witness_commitment(&block).unwrap();
}

#[test]
fn block_validation_without_pow_check() {
    // Reuse block from previous test but call validate_block_basic with pow disabled.
    let leaf_script = vec![0x51];
    let control_block = vec![0x01];
    let leaf_hash = qpb_consensus::qtap_leaf_hash(0x00, &leaf_script);
    let qroot = leaf_hash;
    let spk = build_p2qtsh(qroot);

    let spend_tx = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: vec![leaf_script.clone(), control_block.clone()],
        }],
        vout: vec![TxOut {
            value: 1_0000,
            script_pubkey: spk.clone(),
        }],
        lock_time: 0,
    };

    let mut coinbase = Transaction {
        version: 1,
        vin: vec![TxIn {
            prevout: OutPoint {
                txid: [0u8; 32],
                vout: 0xffffffff,
            },
            script_sig: Vec::new(),
            sequence: 0xffffffff,
            witness: vec![vec![0u8; 32]],
        }],
        vout: vec![],
        lock_time: 0,
    };

    let mut block = Block {
        header: genesis_header(),
        txdata: vec![coinbase.clone(), spend_tx],
    };

    // commitment
    let wroot = witness_merkle_root(&block);
    let mut buf = Vec::new();
    buf.extend_from_slice(&wroot);
    buf.extend_from_slice(&coinbase.vin[0].witness[0]);
    let commitment_hash = qpb_consensus::hash256(&buf);

    coinbase.vout.push(TxOut {
        value: 0,
        script_pubkey: {
            let mut spk_c = Vec::with_capacity(38);
            spk_c.extend_from_slice(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
            spk_c.extend_from_slice(&commitment_hash);
            spk_c
        },
    });

    block.txdata[0] = coinbase;

    // prevouts sets
    let prevouts = vec![
        vec![], // coinbase prevouts placeholder
        vec![Prevout {
            value: 1_0000,
            script_pubkey: spk,
        }],
    ];

    validate_block_basic(&block, &prevouts, 4_000_000, 4_000_000, false, 1).unwrap();
}
