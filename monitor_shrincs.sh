#!/bin/bash
# SHRINCS Monitoring Script (daily checks for public code or updates)

set -euo pipefail

LOG_DIR="./monitor_logs"
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/monitor_$(date -u +%Y%m%d).log"

# Append all output to log (and stdout)
exec > >(tee -a "${LOG_FILE}") 2>&1

# Rotate logs older than 30 days
find "${LOG_DIR}" -type f -mtime +30 -delete

echo "=== SHRINCS monitor run at $(date -u) ==="

echo "[1/3] Delving thread updates:"
curl -s https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158 |
  grep -i -E "reply|code|github|impl|vector|update since Dec 11" || echo "No thread updates"

echo "[2/3] GitHub repository search (created after 2025-12-11):"
curl -s "https://api.github.com/search/repositories?q=SHRINCS+signature+post-quantum+language:rust+created:>2025-12-11" |
  jq '.items[] | {name: .full_name, url: .html_url, updated: .updated_at}' || echo "No new GitHub repos"

echo "[3/3] BlockstreamResearch SPHINCS-Parameters repo commits since 2025-12-10:"
tmpdir=$(mktemp -d)
git clone --depth=20 https://github.com/BlockstreamResearch/SPHINCS-Parameters.git "$tmpdir" >/dev/null 2>&1 || { echo "clone failed"; exit 0; }
cd "$tmpdir"
git log --since="2025-12-10" --oneline | grep -i -E "shrincs|hybrid|impl|vector" || echo "No SHRINCS commits"
cd - >/dev/null
rm -rf "$tmpdir"

echo "=== Done ==="
