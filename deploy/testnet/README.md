# QPB Testnet Deployment (AWS Lightsail)

This deploy package runs a single QPB node on **testnet** in Docker, with:
- **P2P exposed publicly** (38334/tcp)
- **RPC bound to localhost only** (38335/tcp - access via SSH tunnel)

> **Security:** Do NOT expose RPC to the public internet.

---

## Prerequisites (on the Lightsail instance)

- Docker installed and running
- Docker Compose plugin available (`docker compose`)
- Lightsail firewall configured:
  - **Open:** 38334/tcp (P2P)
  - **Keep closed:** 38335/tcp (RPC)

Quick checks:

```bash
docker --version
docker compose version
sudo systemctl status docker --no-pager
sudo apt-get install -y curl jq  # for status.sh
```

---

## Initial Setup

### 1) Create deployment directory (on server)

```bash
sudo mkdir -p /opt/qpb-testnet/{data,scripts}
sudo chown -R ubuntu:ubuntu /opt/qpb-testnet
```

### 2) Copy deployment files (from your laptop)

```bash
scp -r deploy/testnet/* ubuntu@34.237.78.113:/opt/qpb-testnet/
```

### 3) Configure environment (on server)

```bash
cd /opt/qpb-testnet
cp .env.example .env
nano .env   # Set QPB_IMAGE tag
chmod 600 .env
chmod +x scripts/*.sh
```

### 4) Install systemd unit

```bash
sudo cp qpb-testnet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable qpb-testnet
```

### 5) Pull image and start

```bash
docker pull "$(grep '^QPB_IMAGE=' .env | cut -d= -f2-)"
sudo systemctl start qpb-testnet
```

---

## Operations

```bash
# Status / logs / chain info
/opt/qpb-testnet/scripts/status.sh

# Upgrade to new image
/opt/qpb-testnet/scripts/upgrade.sh ghcr.io/scottdhughes/qpb-node:NEW_SHA

# Rollback to previous image
/opt/qpb-testnet/scripts/rollback.sh ghcr.io/scottdhughes/qpb-node:OLD_SHA
```

---

## RPC Access (SSH tunnel)

RPC listens only on localhost. To access from your laptop:

```bash
# Open tunnel
ssh -L 38335:127.0.0.1:38335 ubuntu@34.237.78.113

# Then call RPC (in another terminal)
curl -s http://127.0.0.1:38335/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}'
```

---

## Troubleshooting

**Permission denied on /data:**
```bash
sudo chown -R 1000:1000 /opt/qpb-testnet/data
```
Or remove `user: "1000:1000"` from docker-compose.testnet.yml.

**Container unhealthy:**
```bash
docker logs qpb-testnet --tail=100
```

---

## File Structure

```
deploy/
  testnet/
    docker-compose.testnet.yml
    .env.example
    qpb-testnet.service
    chainparams.json          (copy from docs/chain/)
    README.md
    scripts/
      status.sh
      upgrade.sh
      rollback.sh
    data/                     (created on server, gitignored)
```

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| RPC on localhost only | Security - requires SSH tunnel for remote access |
| Ports 38334/38335 | Match chainparams.json testnet config |
| systemd manages compose | Clean start/stop, survives reboots |
| .env pins image tag | Deterministic upgrades/rollbacks |
| `/health` for healthcheck | No auth needed, returns chain status |
