# Running a QPB Node

This guide covers installation, configuration, and operation of a Quantum-Proof Bitcoin node.

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 2 GB | 4+ GB |
| Storage | 10 GB | 50+ GB SSD |
| Network | 1 Mbps | 10+ Mbps |

## Installation

### From Source

```bash
# Prerequisites: Rust 1.83+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/scottdhughes/quantum-proof-bitcoin.git
cd quantum-proof-bitcoin
cargo build --release

# Verify installation
./target/release/qpb-node --help
```

### Using Docker

```bash
# Build image
docker build -t qpb-node .

# Run container
docker run -d \
  --name qpb-node \
  -p 28332:28332 \
  -p 28333:28333 \
  -v qpb-data:/data \
  qpb-node

# Or use docker-compose
docker compose up -d
```

## Configuration

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--chain` | `devnet` | Network: `mainnet`, `testnet`, or `devnet` |
| `--datadir` | `.qpb` | Data directory path |
| `--chainparams` | `docs/chain/chainparams.json` | Chain parameters file |
| `--rpc-addr` | `127.0.0.1:PORT` | RPC bind address |
| `--listen` | `false` | Accept inbound P2P connections |
| `--bind` | `0.0.0.0` | P2P bind address |
| `--port` | Network default | P2P port |
| `--maxinbound` | Unlimited | Maximum inbound connections |
| `--p2p-connect` | None | Peer addresses to connect to |
| `--rpcuser` | None | RPC authentication username |
| `--rpcpassword` | None | RPC authentication password |
| `--rpc-rate-limit` | `100` | Max RPC requests/second/client |
| `--no-pow` | `false` | Skip PoW verification (dev only) |
| `--config`, `-c` | `{datadir}/qpb.toml` | Path to configuration file |

### Configuration File

Instead of command-line flags, you can use a TOML configuration file. By default, the node looks for `qpb.toml` in the data directory.

**Priority:** CLI flags override config file values.

**Example `qpb.toml`:**

```toml
# Network configuration
chain = "testnet"
datadir = "/var/lib/qpb"

# RPC server
[rpc]
bind = "127.0.0.1:18332"
user = "admin"
password = "secretpassword"
rate_limit = 100

# P2P network
[p2p]
listen = true
bind = "0.0.0.0"
port = 18333
max_inbound = 125
connect = ["seed1.example.com:18333", "seed2.example.com:18333"]

# Mining (development only)
[mining]
no_pow = false

# Logging
[log]
level = "info"
```

**Configuration Options:**

| Section | Key | Type | Description |
|---------|-----|------|-------------|
| (root) | `chain` | string | Network: "mainnet", "testnet", "devnet" |
| (root) | `datadir` | string | Data directory path |
| `[rpc]` | `bind` | string | RPC bind address (e.g., "127.0.0.1:28332") |
| `[rpc]` | `user` | string | RPC authentication username |
| `[rpc]` | `password` | string | RPC authentication password |
| `[rpc]` | `rate_limit` | number | Max requests/second/client |
| `[p2p]` | `listen` | boolean | Accept inbound connections |
| `[p2p]` | `bind` | string | P2P bind address |
| `[p2p]` | `port` | number | P2P port |
| `[p2p]` | `max_inbound` | number | Maximum inbound connections |
| `[p2p]` | `connect` | array | Peer addresses to connect to |
| `[mining]` | `no_pow` | boolean | Skip PoW verification |
| `[log]` | `level` | string | Log level ("error", "warn", "info", "debug", "trace") |

### Network Ports

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| mainnet | 8333 | 8332 |
| testnet | 18333 | 18332 |
| devnet | 28333 | 28332 |

### Example Configurations

**Development Node (single node, no network):**
```bash
./target/release/qpb-node \
  --chain=devnet \
  --datadir=.qpb \
  --no-pow
```

**Testnet Node (with P2P):**
```bash
./target/release/qpb-node \
  --chain=testnet \
  --datadir=/var/lib/qpb \
  --listen \
  --port=18333 \
  --p2p-connect=seed1.example.com:18333 \
  --p2p-connect=seed2.example.com:18333
```

**Secured RPC:**
```bash
./target/release/qpb-node \
  --chain=devnet \
  --rpcuser=admin \
  --rpcpassword=secretpassword \
  --rpc-rate-limit=50
```

## Monitoring

### Health Endpoint

```bash
curl http://localhost:28332/health
```

Response:
```json
{
  "status": "healthy",
  "chain": "devnet",
  "height": 150,
  "peers": 3
}
```

### Prometheus Metrics

```bash
curl http://localhost:28332/metrics
```

Available metrics:
- `qpb_block_height` - Current block height
- `qpb_peers_inbound` - Inbound peer count
- `qpb_peers_outbound` - Outbound peer count
- `qpb_mempool_size` - Mempool transaction count
- `qpb_mempool_bytes` - Mempool size in bytes
- `qpb_utxo_count` - UTXO set size

### RPC Status Checks

```bash
# Block height
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'

# Network info
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getnetworkinfo","params":[]}'

# Mempool info
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"getmempoolinfo","params":[]}'
```

## Data Directory Structure

```
.qpb/
  blocks/           # Block data files
  utxo.json         # UTXO set
  mempool.json      # Mempool state
  wallet.json       # Wallet data (if created)
  peers.json        # Known peers
  bans.json         # Banned peers
```

## Troubleshooting

### Node Won't Start

1. **Check port availability:**
   ```bash
   lsof -i :28332
   lsof -i :28333
   ```

2. **Verify chainparams file exists:**
   ```bash
   ls -la docs/chain/chainparams.json
   ```

3. **Check data directory permissions:**
   ```bash
   ls -la .qpb/
   ```

### Peer Connection Issues

1. **Check firewall rules:**
   ```bash
   # Allow P2P port
   sudo ufw allow 28333/tcp
   ```

2. **Verify DNS resolution:**
   ```bash
   nslookup seed1.example.com
   ```

3. **Check peer info:**
   ```bash
   curl -X POST http://localhost:28332 \
     -d '{"jsonrpc":"2.0","id":1,"method":"getpeerinfo","params":[]}'
   ```

### High Memory Usage

- Reduce mempool size limits
- Consider using swap space
- Monitor with `/metrics` endpoint

### RPC Authentication Failures

1. **Verify credentials:**
   ```bash
   curl -X POST http://localhost:28332 \
     -H "Authorization: Basic $(echo -n 'user:pass' | base64)" \
     -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
   ```

2. **Check rate limiting:**
   - Default: 100 requests/second
   - Increase with `--rpc-rate-limit`

## Graceful Shutdown

```bash
# Via RPC
curl -X POST http://localhost:28332 \
  -d '{"jsonrpc":"2.0","id":1,"method":"stop","params":[]}'

# Via signal
kill -SIGTERM $(pgrep qpb-node)
```

The node will:
1. Stop accepting new connections
2. Flush mempool to disk
3. Save UTXO state
4. Close peer connections
5. Exit cleanly

## Systemd Service

Create `/etc/systemd/system/qpb-node.service`:

```ini
[Unit]
Description=Quantum-Proof Bitcoin Node
After=network.target

[Service]
Type=simple
User=qpb
Group=qpb
ExecStart=/usr/local/bin/qpb-node \
  --chain=devnet \
  --datadir=/var/lib/qpb \
  --listen \
  --rpc-addr=127.0.0.1:28332
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable qpb-node
sudo systemctl start qpb-node
sudo systemctl status qpb-node
```

## See Also

- [RPC Reference](../rpc/README.md) - Complete API documentation
- [Architecture](../architecture/reference-node.md) - Node implementation details
- [Cryptography](../crypto/README.md) - Post-quantum signature schemes
