# Quantum Proof Bitcoin (QPB)

[![CI](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ci.yml/badge.svg)](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ci.yml)
[![Docker](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/docker.yml/badge.svg)](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/docker.yml)

A post-quantum Bitcoin-derived consensus prototype with hash-first security guarantees.

> **Status:** Testnet live. Devnet-ready. Not for production use.
> INTERNAL: not an audit, not production security guidance, not legal/compliance advice.

## Features

- **Post-Quantum Cryptography**: ML-DSA-65 (Dilithium3) signatures at genesis
- **Memory-Hard PoW**: Argon2id proof-of-work (non-SHA256)
- **QScript VM**: 7-opcode stack-based script execution
- **Full Node**: P2P networking, mempool, UTXO management, wallet
- **JSON-RPC API**: 40+ methods for blockchain, wallet, and network operations
- **Docker Support**: Multi-stage build for easy deployment

## Quick Start

### Using Docker

```bash
# Build and run (devnet)
docker compose up -d

# Check node status
curl http://localhost:38332/health

# View metrics
curl http://localhost:38332/metrics
```

### Pre-built Docker Images

Pre-built images are available on GitHub Container Registry:

```bash
# Pull latest image
docker pull ghcr.io/scottdhughes/qpb-node:latest

# Or pin to a specific commit SHA
docker pull ghcr.io/scottdhughes/qpb-node:c12f54e

# Run testnet node
docker run -d \
  --name qpb-testnet \
  -p 38334:38334 \
  -p 127.0.0.1:38335:38335 \
  -v qpb-data:/data \
  ghcr.io/scottdhughes/qpb-node:latest \
  /usr/local/bin/qpb-node --chain=testnet --datadir=/data --listen
```

See [Testnet Deployment](deploy/testnet/README.md) for production deployment guide.

### From Source

```bash
# Clone and build
git clone https://github.com/scottdhughes/quantum-proof-bitcoin.git
cd quantum-proof-bitcoin
cargo build --release

# Run devnet node
./target/release/qpb-node --chain=devnet --datadir=.qpb --listen

# Run tests
cargo test --all-features
```

## Documentation

| Document | Description |
|----------|-------------|
| [RPC Reference](docs/rpc/README.md) | JSON-RPC API methods and examples |
| [Running a Node](docs/operations/running-a-node.md) | Installation, configuration, monitoring |
| [Testnet Deployment](deploy/testnet/README.md) | Production testnet deployment on AWS |
| [Architecture](docs/architecture/reference-node.md) | Node implementation phases |
| [Whitepaper](docs/spec/QPB_Whitepaper_v1.1m.md) | Full consensus specification |
| [Cryptography](docs/crypto/README.md) | ML-DSA-65, SLH-DSA, SHRINCS specs |

## RPC Examples

```bash
# Get blockchain info (devnet default port)
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'

# Create wallet and get address
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"createwallet","params":[]}'
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnewaddress","params":[]}'

# Mine blocks to address
curl -X POST http://localhost:38332/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"generatetoaddress","params":[1,"qpb1..."]}'
```

See [RPC Reference](docs/rpc/README.md) for complete API documentation.

## Mining CLI

For development/testing with the `qpb-cli` binary:

```bash
# Mine 3 blocks without spending coinbase
cargo run --bin qpb-cli -- --blocks=3 --no-spend --bits=0x207fffff

# Mine with fresh key per block
cargo run --bin qpb-cli -- --blocks=5 --fresh-key

# Mine with fee claiming and parallel nonce search
cargo run --bin qpb-cli -- --blocks=5 --claim-fees --parallel
```

## SHRINCS Roadmap

SHRINCS (alg_id 0x30) is a hybrid stateful + stateless PQ signature scheme. Target: NIST Level 3, ~636 byte signatures.

| Phase | Status | Description |
|-------|--------|-------------|
| 1. Core Primitives | ✅ Complete | WOTS+C, PORS+FP |
| 2. Hypertree | ✅ Complete | XMSS^MT, state management |
| 3. Orchestrator | ✅ Complete | Full signing, SPHINCS+ fallback |
| 4. Consensus Wiring | ✅ Complete | Height/network activation context |
| 5. Wallet Integration | ✅ Complete | SHRINCS key generation + signing |
| 6. Mainnet Activation | Pending | Algorithm ID 0x30 soft-fork |

**Current Status**: SHRINCS is fully implemented and testable with `--features shrincs-dev`.
Activation heights: Devnet (0), Testnet (100), Mainnet (TBD after audit).

See [SHRINCS Spec](docs/crypto/SHRINCS.md) for details.

## Development

```bash
# Run all checks (fmt, clippy, test)
scripts/check.sh

# Regenerate test vectors
cargo run --bin gen_vectors

# Build with SHRINCS dev stub (research only)
cargo test --features "shrincs-dev,shrincs-ffi"
```

### Miri (Undefined Behavior Detection)

[Miri](https://github.com/rust-lang/miri) is a Rust interpreter that detects undefined behavior, memory leaks, and data races in pure Rust code.

```bash
# Install Miri (requires nightly)
rustup +nightly component add miri

# Run Miri tests (FFI tests auto-skipped)
cargo +nightly miri test --lib

# Verify no UB in consensus-critical code
cargo +nightly miri test --lib consensus
```

> **Note:** Tests using FFI (Dilithium/SPHINCS+ C libraries) are annotated with `#[cfg_attr(miri, ignore)]` since Miri cannot interpret foreign code. This enables Miri verification of all pure-Rust logic including SHRINCS, script execution, and transaction validation.

## Project Structure

```
src/
  bin/           # qpb-node, qpb-cli, qpb-wallet binaries
  node/          # Node implementation (rpc, mempool, p2p, wallet)
  crypto/        # ML-DSA-65, hashing, signatures
docs/
  rpc/           # RPC API reference
  operations/    # Node operator guides
  crypto/        # Cryptography specifications
  spec/          # Consensus whitepaper
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `scripts/check.sh` before committing
4. Submit a pull request

## License

See LICENSE file for details.
