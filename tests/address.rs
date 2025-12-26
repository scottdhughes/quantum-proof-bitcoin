use qpb_consensus::address::{decode_address, encode_address};

#[test]
fn bech32m_roundtrip_v2() {
    let program = [0x11u8; 32];
    let addr = encode_address("qpb", 2, &program).expect("encode");
    let dec = decode_address(&addr).expect("decode");
    assert_eq!(dec.witness_version, 2);
    assert_eq!(dec.program, program);
    assert_eq!(dec.script_pubkey[0], 0x52);
    assert_eq!(dec.script_pubkey[1], 0x20);
    assert_eq!(&dec.script_pubkey[2..], &program);
}

#[test]
fn bech32m_roundtrip_v3() {
    let program = [0x22u8; 32];
    let addr = encode_address("qpb", 3, &program).expect("encode");
    let dec = decode_address(&addr).expect("decode");
    assert_eq!(dec.witness_version, 3);
    assert_eq!(dec.program, program);
    assert_eq!(dec.script_pubkey[0], 0x53);
    assert_eq!(dec.script_pubkey[1], 0x20);
}

#[test]
fn reject_wrong_version() {
    // witness version 1 encoded bech32m -> should fail because only v2/v3 allowed
    let addr = "qpb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqp6f7t7";
    assert!(decode_address(addr).is_err());
}
