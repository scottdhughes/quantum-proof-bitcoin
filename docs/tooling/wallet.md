# QPB Wallet / Tooling MVP (non-consensus)

Features (dev tooling only):
- Bech32m encode/decode for P2QTSH (v2) and P2QPKH (v3) with 32-byte programs.
- ML-DSA-65 (alg_id 0x11) keygen/sign for P2QPKH spends.
- Address derivation from pk_ser/qroot.
- Decode addresses to scriptPubKey.

## Addresses
- Witness v2 (P2QTSH): `OP_2 0x20 <32B>`
- Witness v3 (P2QPKH): `OP_3 0x20 <32B>`
- Bech32m only (BIP350), 32-byte program required, witness_version must be 2 or 3.
- HRP is loaded from `docs/chain/chainparams.json` (devnet/regtest/testnet); defaults to `qpb` if missing.

## CLI: `qpb-wallet`
```
# Keygen (prints pk/sk, pk_ser, address)
cargo run --bin qpb-wallet -- keygen --network devnet

# Derive P2QPKH address from pk_ser
cargo run --bin qpb-wallet -- addr p2qpkh --pk-ser-hex <hex> --network devnet

# Derive P2QTSH address from qroot
cargo run --bin qpb-wallet -- addr p2qtsh --qroot-hex <hex> --network devnet

# Decode address -> witness_version, program, scriptPubKey
cargo run --bin qpb-wallet -- decode --address <addr>

# Sign a P2QPKH input (ML-DSA-65)
cargo run --bin qpb-wallet -- sign-p2qpkh --tx-hex <hex> --in 0 \
  --prevouts-json prevouts.json --sk-hex <hex> --pk-hex <hex>
```
Notes:
- `prevouts.json` is an array of objects `{ "value": <u64>, "script_pubkey_hex": "..." }`, indexed to match tx inputs.
- Signing uses the consensus sighash (ext_flag=0x00 key path); output includes `msg32_hex`, `sig_hex`, `sig_ser_hex`, `pk_ser_hex`.
- Tooling only; consensus rules are unchanged.
