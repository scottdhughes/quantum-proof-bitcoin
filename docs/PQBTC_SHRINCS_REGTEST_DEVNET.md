# PQBTC SHRINCS-v0 regtest devnet

This branch removes the artificial test-only build gates and makes the frozen
SHRINCS-v0 verifier part of the node. The spend path is active **only** when the
chain's consensus parameters set `shrincs_v0=true`; currently that is private
`-regtest` only.

## Spend format

```text
scriptPubKey:
    OP_2 PUSH32 TaggedHash("PQBTC/SHRINCS/OUTPUT/v0", public_key_48)

witness:
    canonical_signature
    public_key_48
```

The accepted signatures are the frozen current-profile encodings:

- stateful: `538 + 16*d` bytes for `1 <= d <= 255`;
- stateless recovery: exactly `5,776` bytes.

The transaction digest is fixed `SIGHASH_ALL`, commits to every input prevout,
amount, script, and sequence, every output, the selected input, and the private
regtest chain identifier. There is no ECDSA, Schnorr, rc2, ML-DSA, or
unknown-algorithm fallback.

## Build and mine

```bash
cmake -S . -B build -G Ninja \
  -DBUILD_TESTS=ON \
  -DENABLE_WALLET=ON \
  -DENABLE_IPC=OFF
cmake --build build --parallel 2

build/bin/pqbtcd -regtest -daemon
build/bin/pqbtc-cli -regtest createwallet devnet
ADDR=$(build/bin/pqbtc-cli -regtest getnewaddress)
build/bin/pqbtc-cli -regtest generatetoaddress 101 "$ADDR"
```

The signed interpreter KAT is:

```bash
build/bin/test_pqbtc \
  --run_test=shrincs_tx_v0_signed_seam_tests \
  --catch_system_error=no
```

Coins mined on regtest have no value and the network can be reset at any time.
Mainnet, testnet, testnet4, and signet do not activate this witness version.
