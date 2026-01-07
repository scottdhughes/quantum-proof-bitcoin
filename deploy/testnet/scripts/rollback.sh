#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <full-image-ref>"
  echo "Example: $0 ghcr.io/scottdhughes/qpb-node:previous-sha"
  exit 1
fi

OLD_IMAGE="$1"

echo "=== Rolling back to: $OLD_IMAGE ==="
sed -i.tmp "s|^QPB_IMAGE=.*|QPB_IMAGE=$OLD_IMAGE|" .env && rm -f .env.tmp

docker pull "$OLD_IMAGE"
sudo systemctl restart qpb-testnet

sleep 10
./scripts/status.sh
