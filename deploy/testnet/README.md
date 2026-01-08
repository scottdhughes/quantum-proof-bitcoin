# QPB Testnet Deployment (AWS Lightsail)

This deploy package runs a single QPB node on **testnet** in Docker, with:
- **P2P exposed publicly** (38334/tcp, IPv4 only)
- **RPC bound to localhost only** (38335/tcp) with **authentication required**

> **Security:** RPC requires Basic Auth. Do NOT expose RPC to the public internet.

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

# Generate random RPC password and set image tag
RPC_PASS=$(openssl rand -base64 24 | tr -d '/+=')
sed -i "s/CHANGE_ME_RANDOM_PASSWORD/$RPC_PASS/" .env
nano .env   # Verify QPB_IMAGE tag

chmod 600 .env
chmod +x scripts/*.sh
sudo chown -R 1000:1000 data/
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

## RPC Access (SSH tunnel + auth)

RPC listens only on localhost and requires Basic Auth. To access from your laptop:

```bash
# Open tunnel
ssh -L 38335:127.0.0.1:38335 ubuntu@34.237.78.113

# Get credentials (on server)
source /opt/qpb-testnet/.env
echo "User: $RPC_USER  Pass: $RPC_PASS"

# Then call RPC with auth (in another terminal)
curl -s -u qpb:YOUR_PASSWORD http://127.0.0.1:38335/rpc \
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
| RPC on localhost + auth | Defense in depth - requires SSH tunnel AND credentials |
| P2P IPv4-only binding | Avoids unintended IPv6 exposure (cloud firewalls may not cover IPv6) |
| Ports 38334/38335 | Match chainparams.json testnet config |
| systemd manages compose | Clean start/stop, survives reboots |
| .env pins image + secrets | Deterministic upgrades, secrets out of compose file |
| `/health` for healthcheck | No auth needed, returns chain status |
