# Quantum Proof Bitcoin (QPB)

[![CI](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ci.yml/badge.svg)](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ci.yml)

Hash-first, post-quantum Bitcoin-derived consensus prototype with SHRINCS (hash-based, stateful-fast + stateless fallback) from genesis. INTERNAL: not an audit, not production security guidance, not legal/compliance advice.

## Quick start
```bash
cargo test --all-features
```

## SHRINCS FFI quickstart (optional)
Build the prototype C stub and point the runtime loader at it:
```bash
# Linux
gcc -shared -fPIC -o libshrincs.so ffi/shrincs.c
# macOS
clang -dynamiclib -o libshrincs.dylib ffi/shrincs.c
# Windows (MSVC shell)
cl /LD ffi\\shrincs.c /Felibshrincs.dll

export SHRINCS_LIB_PATH=$PWD/libshrincs.so   # or .dylib / .dll
cargo test --all-features --features shrincs-ffi
```
Without the library, the Rust fallback stub is used automatically.

## Mining CLI (dev/regtest)
Examples with the `qpb-cli` binary:
```bash
# Mine blocks without spending the previous coinbase
cargo run --bin qpb-cli -- --blocks=3 --no-spend --bits=0x207fffff

# Mine with fresh key per block and spend prior coinbase
cargo run --bin qpb-cli -- --blocks=5 --fresh-key

# Claim fees in coinbase and allow parallel nonce search
cargo run --bin qpb-cli -- --blocks=5 --claim-fees --parallel
```
Flags of interest: `--no-spend`, `--fresh-key`, `--claim-fees`, `--parallel`, `--blocks=`, `--bits=`.

## Dev checks
```bash
scripts/check.sh
```
Runs `fmt`, `clippy`, and `test` with all features. Benches stay opt-in (not on push/PR).
