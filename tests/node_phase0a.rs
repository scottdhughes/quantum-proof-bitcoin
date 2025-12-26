use qpb_consensus::node::chainparams::{compute_genesis_hash, load_chainparams, select_network};
use qpb_consensus::node::store::Store;

#[test]
fn genesis_init_and_persist() {
    let tmp = tempfile::tempdir().unwrap();
    let chainparams =
        load_chainparams(std::path::Path::new("docs/chain/chainparams.json")).unwrap();
    let net = select_network(&chainparams, "devnet").unwrap();
    let genesis = net.genesis.as_ref().expect("genesis present");
    let genesis_hash = compute_genesis_hash(&genesis.header).unwrap();
    let genesis_hex = hex::encode(genesis_hash);

    // first open initializes
    let store1 = Store::open_or_init(tmp.path(), "devnet", &genesis_hex).unwrap();
    assert_eq!(store1.height(), 0);
    assert_eq!(store1.tip_hash(), genesis.block_hash_hex);

    // second open loads existing state
    let store2 = Store::open_or_init(tmp.path(), "devnet", &genesis_hex).unwrap();
    assert_eq!(store2.height(), 0);
    assert_eq!(store2.tip_hash(), genesis.block_hash_hex);
}
