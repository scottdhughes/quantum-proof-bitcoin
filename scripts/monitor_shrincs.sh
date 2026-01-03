#!/usr/bin/env bash
# Monitor SHRINCS reference implementation progress
# Run periodically to check for updates from Jonas Nick / Blockstream Research
set -euo pipefail

echo "=== SHRINCS Implementation Monitor ==="
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# Colors (if terminal supports)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_url() {
    local name="$1"
    local url="$2"
    if curl -sf --max-time 10 "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}[OK]${NC} $name"
        return 0
    else
        echo -e "${YELLOW}[--]${NC} $name (not found or unreachable)"
        return 1
    fi
}

echo "--- Checking Known Resources ---"
echo ""

# Delving Bitcoin thread
echo "Delving Bitcoin SHRINCS Thread:"
echo "  https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158"
echo ""

# ePrint paper
echo "ePrint Paper (Hash-based Signatures for Bitcoin):"
echo "  https://eprint.iacr.org/2025/2203"
echo ""

# Jonas Nick's GitHub
echo "--- Checking GitHub for SHRINCS Repos ---"
echo ""

# Search for SHRINCS repos (case-insensitive)
echo "Searching GitHub for 'shrincs' repositories..."
if command -v gh &> /dev/null; then
    REPOS=$(gh search repos shrincs --limit 10 --json fullName,description,updatedAt 2>/dev/null || echo "[]")
    if [ "$REPOS" != "[]" ] && [ -n "$REPOS" ]; then
        echo -e "${GREEN}Found SHRINCS repositories:${NC}"
        echo "$REPOS" | jq -r '.[] | "  \(.fullName) - \(.description // "No description") (updated: \(.updatedAt))"' 2>/dev/null || echo "  (parse error)"
    else
        echo -e "${YELLOW}No public SHRINCS repositories found yet${NC}"
    fi
else
    echo "  (gh CLI not installed - install with: brew install gh)"
fi
echo ""

# Check Jonas Nick's repos for anything new
echo "Checking jonasnick's recent repositories..."
if command -v gh &> /dev/null; then
    NICK_REPOS=$(gh api users/jonasnick/repos --jq 'sort_by(.pushed_at) | reverse | .[0:5] | .[] | "\(.name) (pushed: \(.pushed_at))"' 2>/dev/null || echo "")
    if [ -n "$NICK_REPOS" ]; then
        echo "  Recent activity from jonasnick:"
        echo "$NICK_REPOS" | sed 's/^/    /'
    else
        echo "  Could not fetch jonasnick repos"
    fi
else
    echo "  (gh CLI not installed)"
fi
echo ""

# Check Blockstream Research
echo "Checking BlockstreamResearch organization..."
if command -v gh &> /dev/null; then
    BS_REPOS=$(gh search repos "org:BlockstreamResearch" --limit 5 --sort updated --json fullName,updatedAt 2>/dev/null || echo "[]")
    if [ "$BS_REPOS" != "[]" ] && [ -n "$BS_REPOS" ]; then
        echo "  Recent BlockstreamResearch repos:"
        echo "$BS_REPOS" | jq -r '.[] | "    \(.fullName) (updated: \(.updatedAt))"' 2>/dev/null || echo "    (parse error)"
    fi
else
    echo "  (gh CLI not installed)"
fi
echo ""

# Known reference locations to watch
echo "--- Key URLs to Watch ---"
echo ""
echo "1. Jonas Nick GitHub:     https://github.com/jonasnick"
echo "2. Blockstream Research:  https://github.com/BlockstreamResearch"
echo "3. Delving Bitcoin:       https://delvingbitcoin.org/t/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/2158"
echo "4. Bitcoin-dev mailing:   https://groups.google.com/g/bitcoindev"
echo "5. ePrint crypto:         https://eprint.iacr.org/2025/2203"
echo ""

echo "--- QPB Integration Status ---"
echo ""
echo "Current SHRINCS module:   src/shrincs/"
echo "Target security level:    NIST Level 3 (192-bit)"
echo "Target signature size:    636 bytes (first sig)"
echo "Consensus status:         RESERVED (alg_id 0x30, inactive)"
echo ""
echo "When reference impl is available:"
echo "  1. Evaluate: Rust native vs C FFI"
echo "  2. Implement: ShrincsSign + ShrincsVerify traits"
echo "  3. Test: Validate against official test vectors"
echo "  4. Activate: Hard fork coordination"
echo ""
echo "=== Monitor Complete ==="
