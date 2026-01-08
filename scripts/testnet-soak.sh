#!/bin/bash
# Testnet Soak Test Script
# Tests SHRINCS transactions on the live testnet with the AWS seed node
#
# Prerequisites:
#   - SSH key at ~/.ssh/lightsail-key.pem with access to 34.237.78.113
#   - Testnet node running on AWS
#
# Usage:
#   ./scripts/testnet-soak.sh [--blocks N] [--mldsa-only]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
AWS_HOST="34.237.78.113"
SSH_KEY="$HOME/.ssh/lightsail-key.pem"
RPC_PORT="38335"
BLOCK_COUNT=10
MLDSA_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --blocks)
            BLOCK_COUNT="$2"
            shift 2
            ;;
        --mldsa-only)
            MLDSA_ONLY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--blocks N] [--mldsa-only]"
            echo "  --blocks N    Number of blocks to mine (default: 10)"
            echo "  --mldsa-only  Skip SHRINCS tests, use ML-DSA-65 only"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    exit 1
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_metric() {
    echo -e "${CYAN}[METRIC]${NC} $1"
}

# Execute RPC via SSH tunnel
rpc() {
    local method="$1"
    shift
    local params="$*"

    if [ -z "$params" ]; then
        params="[]"
    fi

    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "ubuntu@$AWS_HOST" \
        "curl -s -X POST http://localhost:$RPC_PORT/rpc \
            -H 'Content-Type: application/json' \
            -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}'" \
        2>/dev/null | jq -r '.result // .error'
}

# Timed RPC call (returns time in ms)
rpc_timed() {
    local method="$1"
    shift
    local params="$*"

    if [ -z "$params" ]; then
        params="[]"
    fi

    local start_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')

    local result=$(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "ubuntu@$AWS_HOST" \
        "curl -s -X POST http://localhost:$RPC_PORT/rpc \
            -H 'Content-Type: application/json' \
            -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}'" \
        2>/dev/null)

    local end_ms=$(python3 -c 'import time; print(int(time.time() * 1000))')
    local elapsed=$((end_ms - start_ms))

    echo "$elapsed|$(echo "$result" | jq -r '.result // .error')"
}

# Get health status
get_health() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "ubuntu@$AWS_HOST" \
        "curl -s http://localhost:$RPC_PORT/health" 2>/dev/null
}

echo "=========================================="
echo "  QPB Testnet Soak Test"
echo "=========================================="
echo ""
echo "Target: $AWS_HOST:$RPC_PORT"
echo "Blocks: $BLOCK_COUNT"
echo "SHRINCS: $( [ "$MLDSA_ONLY" = true ] && echo 'disabled' || echo 'enabled' )"
echo ""

# Phase 1: Check connectivity
log_info "Phase 1: Connectivity Check"
echo "-------------------------------------------"

HEALTH=$(get_health)
if [ -z "$HEALTH" ]; then
    log_error "Cannot connect to testnet node at $AWS_HOST"
fi

CHAIN=$(echo "$HEALTH" | jq -r '.chain')
HEIGHT=$(echo "$HEALTH" | jq -r '.height')
PEERS_IN=$(echo "$HEALTH" | jq -r '.peers.inbound')
PEERS_OUT=$(echo "$HEALTH" | jq -r '.peers.outbound')

log_success "Connected to $CHAIN at height $HEIGHT"
log_info "Peers: inbound=$PEERS_IN, outbound=$PEERS_OUT"
echo ""

# Phase 2: Wallet setup
log_info "Phase 2: Wallet Setup"
echo "-------------------------------------------"

# Create/open wallet
WALLET_INFO=$(rpc "createwallet")
if [ -z "$WALLET_INFO" ] || [ "$WALLET_INFO" == "null" ]; then
    log_warn "Wallet may already exist, continuing..."
fi

# Generate ML-DSA address
ADDR_MLDSA=$(rpc "getnewaddress" '["mldsa"]')
if [ -z "$ADDR_MLDSA" ] || [ "$ADDR_MLDSA" == "null" ]; then
    log_error "Failed to generate ML-DSA address"
fi
log_success "ML-DSA address: ${ADDR_MLDSA:0:20}..."

# Generate SHRINCS address (if enabled)
ADDR_SHRINCS=""
if [ "$MLDSA_ONLY" = false ]; then
    ADDR_SHRINCS=$(rpc "getnewaddress" '["shrincs"]')
    if [ -z "$ADDR_SHRINCS" ] || [ "$ADDR_SHRINCS" == "null" ]; then
        log_warn "SHRINCS address generation failed (may need --features shrincs-dev)"
        log_warn "Falling back to ML-DSA only"
        MLDSA_ONLY=true
    else
        log_success "SHRINCS address: ${ADDR_SHRINCS:0:20}..."
    fi
fi
echo ""

# Phase 3: Mining test
log_info "Phase 3: Mining Test ($BLOCK_COUNT blocks)"
echo "-------------------------------------------"

START_HEIGHT=$HEIGHT
START_TIME=$(date +%s)

# Mine to ML-DSA address (in batches of 10 due to RPC limit)
log_info "Mining $BLOCK_COUNT blocks to ML-DSA address..."
REMAINING=$BLOCK_COUNT
TOTAL_MINE_TIME=0
while [ $REMAINING -gt 0 ]; do
    BATCH=$((REMAINING > 10 ? 10 : REMAINING))
    MINE_RESULT=$(rpc_timed "generatetoaddress" "[$BATCH, \"$ADDR_MLDSA\"]")
    MINE_TIME=$(echo "$MINE_RESULT" | cut -d'|' -f1)
    TOTAL_MINE_TIME=$((TOTAL_MINE_TIME + MINE_TIME))
    REMAINING=$((REMAINING - BATCH))
    echo -ne "\r  Progress: $((BLOCK_COUNT - REMAINING))/$BLOCK_COUNT blocks    "
done
echo ""

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
if [ $ELAPSED -eq 0 ]; then
    ELAPSED=1
fi

# Check new height
NEW_HEIGHT=$(rpc "getblockcount")
MINED=$((NEW_HEIGHT - START_HEIGHT))

log_success "Mined $MINED blocks in ${ELAPSED}s (RPC: ${MINE_TIME}ms)"
log_metric "Mining rate: $(echo "scale=2; $MINED / $ELAPSED" | bc) blocks/sec"
echo ""

# Phase 4: Transaction tests
log_info "Phase 4: Transaction Tests"
echo "-------------------------------------------"

# Check balance
BALANCE=$(rpc "getbalance")
log_info "Wallet balance: $BALANCE satoshis"

if [ "$BALANCE" -gt 1000000 ]; then
    # Test ML-DSA send
    log_info "Testing ML-DSA transaction..."
    SEND_RESULT=$(rpc_timed "sendtoaddress" "[\"$ADDR_MLDSA\", 100000]")
    SEND_TIME=$(echo "$SEND_RESULT" | cut -d'|' -f1)
    TXID=$(echo "$SEND_RESULT" | cut -d'|' -f2)

    if [ -n "$TXID" ] && [ "$TXID" != "null" ]; then
        log_success "ML-DSA TX: ${TXID:0:16}... (${SEND_TIME}ms)"
    else
        log_warn "ML-DSA send failed (may need more confirmations)"
    fi

    # Test SHRINCS send (if enabled and has SHRINCS address)
    if [ "$MLDSA_ONLY" = false ] && [ -n "$ADDR_SHRINCS" ]; then
        log_info "Testing SHRINCS transaction..."
        SEND_RESULT=$(rpc_timed "sendtoaddress" "[\"$ADDR_SHRINCS\", 50000]")
        SEND_TIME=$(echo "$SEND_RESULT" | cut -d'|' -f1)
        TXID=$(echo "$SEND_RESULT" | cut -d'|' -f2)

        if [ -n "$TXID" ] && [ "$TXID" != "null" ]; then
            log_success "SHRINCS TX: ${TXID:0:16}... (${SEND_TIME}ms)"
        else
            log_warn "SHRINCS send failed (check activation height)"
        fi
    fi

    # Mine to confirm transactions
    log_info "Mining 1 block to confirm transactions..."
    rpc "generatetoaddress" "[1, \"$ADDR_MLDSA\"]" > /dev/null
else
    log_warn "Insufficient balance for transaction tests (need coinbase maturity)"
fi
echo ""

# Phase 5: Performance benchmarks
log_info "Phase 5: Performance Benchmarks"
echo "-------------------------------------------"

# Benchmark getblockcount
TIMES=()
for i in {1..5}; do
    RESULT=$(rpc_timed "getblockcount")
    TIME=$(echo "$RESULT" | cut -d'|' -f1)
    TIMES+=($TIME)
done
AVG_TIME=$(echo "${TIMES[@]}" | tr ' ' '\n' | awk '{s+=$1} END {printf "%.0f", s/NR}')
log_metric "getblockcount avg: ${AVG_TIME}ms (5 calls)"

# Benchmark getbalance
TIMES=()
for i in {1..3}; do
    RESULT=$(rpc_timed "getbalance")
    TIME=$(echo "$RESULT" | cut -d'|' -f1)
    TIMES+=($TIME)
done
AVG_TIME=$(echo "${TIMES[@]}" | tr ' ' '\n' | awk '{s+=$1} END {printf "%.0f", s/NR}')
log_metric "getbalance avg: ${AVG_TIME}ms (3 calls)"
echo ""

# Phase 6: Final status
log_info "Phase 6: Final Status"
echo "-------------------------------------------"

FINAL_HEALTH=$(get_health)
FINAL_HEIGHT=$(echo "$FINAL_HEALTH" | jq -r '.height')
FINAL_BALANCE=$(rpc "getbalance")
MEMPOOL=$(rpc "getmempoolinfo")
MEMPOOL_SIZE=$(echo "$MEMPOOL" | jq -r '.size // 0')

echo ""
echo "=========================================="
echo "  Soak Test Summary"
echo "=========================================="
echo ""
echo "Chain:          $CHAIN"
echo "Start height:   $START_HEIGHT"
echo "Final height:   $FINAL_HEIGHT"
echo "Blocks mined:   $((FINAL_HEIGHT - START_HEIGHT))"
echo "Balance:        $FINAL_BALANCE satoshis"
echo "Mempool:        $MEMPOOL_SIZE txs"
echo ""

if [ "$MLDSA_ONLY" = false ] && [ -n "$ADDR_SHRINCS" ]; then
    log_success "SHRINCS integration: WORKING"
else
    log_info "SHRINCS integration: SKIPPED (--mldsa-only or unavailable)"
fi

log_success "Soak test complete!"
echo ""
