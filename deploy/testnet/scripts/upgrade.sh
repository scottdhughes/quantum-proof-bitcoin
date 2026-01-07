#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <full-image-ref>"
  echo "Example: $0 ghcr.io/scottdhughes/qpb-node:abcd1234"
  exit 1
fi

NEW_IMAGE="$1"
BACKUP=".env.bak.$(date +%Y%m%d%H%M%S)"

echo "=== Pre-upgrade chain state ==="
./scripts/status.sh || true

echo -e "\n=== Backing up .env to $BACKUP ==="
cp -a .env "$BACKUP"

echo "=== Updating image to: $NEW_IMAGE ==="
sed -i.tmp "s|^QPB_IMAGE=.*|QPB_IMAGE=$NEW_IMAGE|" .env && rm -f .env.tmp

echo "=== Pulling new image ==="
docker pull "$NEW_IMAGE"

echo "=== Restarting service ==="
sudo systemctl restart qpb-testnet

sleep 10

echo -e "\n=== Post-upgrade status ==="
./scripts/status.sh
