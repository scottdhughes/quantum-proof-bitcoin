#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Container Status ==="
docker compose -f docker-compose.testnet.yml ps

echo -e "\n=== Recent Logs ==="
docker logs --tail=50 qpb-testnet 2>&1 || true

echo -e "\n=== Health (authoritative) ==="
curl -sf http://127.0.0.1:38335/health 2>/dev/null | jq '{status, chain, height, tip, peers, auth_enabled}' \
  || echo "Health unavailable"
