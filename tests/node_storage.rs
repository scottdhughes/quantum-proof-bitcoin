use qpb_consensus::node::blockstore;
use qpb_consensus::node::utxo::UtxoSet;

#[test]
fn blockstore_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let bytes = b"deadbeef".to_vec();
    blockstore::put_block(tmp.path(), "abcd", &bytes).unwrap();
    let loaded = blockstore::get_block(tmp.path(), "abcd").unwrap().unwrap();
    assert_eq!(loaded, bytes);
    assert!(blockstore::get_block(tmp.path(), "ffff").unwrap().is_none());
}

#[test]
fn utxo_save_load_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let mut utxo = UtxoSet::load(tmp.path()).unwrap();
    let txid = [1u8; 32];
    // height=10, is_coinbase=true
    utxo.insert(&txid, 0, 42, vec![0x6a], 10, true);
    utxo.save(tmp.path()).unwrap();

    let utxo2 = UtxoSet::load(tmp.path()).unwrap();
    let prev = utxo2.get(&txid, 0).unwrap();
    assert_eq!(prev.value, 42);
    assert_eq!(prev.script_pubkey, vec![0x6a]);
    assert_eq!(prev.height, 10);
    assert!(prev.is_coinbase);
    assert!(utxo2.get(&txid, 1).is_none());
}
