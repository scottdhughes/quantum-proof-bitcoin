# Quantum Proof Bitcoin (QPB)

[![CI](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ci.yml/badge.svg)](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/workflows/ci.yml)

A post-quantum Bitcoin-derived consensus prototype with hash-first security guarantees.

> **Status:** Devnet-ready. Not for production use.
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
# Build and run
docker compose up -d

# Check node status
curl http://localhost:28332/health

# View metrics
curl http://localhost:28332/metrics
```

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
| [Architecture](docs/architecture/reference-node.md) | Node implementation phases |
| [Whitepaper](docs/spec/QPB_Whitepaper_v1.1m.md) | Full consensus specification |
| [Cryptography](docs/crypto/README.md) | ML-DSA-65, SLH-DSA, SHRINCS specs |

## RPC Examples

```bash
# Get blockchain info
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'

# Create wallet and get address
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"createwallet","params":[]}'
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnewaddress","params":[]}'

# Mine blocks to address
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"generatetoaddress","params":[1,"qpbdev1q..."]}'
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
| 1. Core Primitives | Complete | WOTS+C, PORS+FP |
| 2. Hypertree | Complete | XMSS^MT, state management |
| 3. Orchestrator | Complete | Full signing, SPHINCS+ fallback |
| 4. Consensus | Pending | Algorithm ID 0x30 activation |

**Strategy**: Consensus currently rejects alg_id 0x30. Integration pending security audit.

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
