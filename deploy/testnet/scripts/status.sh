#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Container Status ==="
docker compose -f docker-compose.testnet.yml ps

echo -e "\n=== Recent Logs ==="
docker logs --tail=50 qpb-testnet 2>&1 || true

echo -e "\n=== Chain Info ==="
source /opt/qpb-testnet/.env
curl -sf -u "$RPC_USER:$RPC_PASS" http://127.0.0.1:38335/rpc \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}' 2>/dev/null \
  | jq '{chain: .result.chain, blocks: .result.blocks, bestblockhash: .result.bestblockhash}' \
  || echo "RPC unavailable"
