# Multi-stage Dockerfile for QPB Node
# Stage 1: Build the binary
FROM rust:slim-bookworm AS builder

# Install build dependencies and nightly toolchain
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rustup toolchain install nightly \
    && rustup default nightly

WORKDIR /build

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/bin/qpb-node.rs && \
    echo 'pub fn dummy() {}' > src/lib.rs

# Build arg to enable SHRINCS (default: enabled for testing)
ARG ENABLE_SHRINCS=true

# Build dependencies only (cached unless Cargo.toml changes)
RUN cargo build --release --bin qpb-node || true

# Now copy the real source code
COPY src/ src/
COPY docs/ docs/
COPY benches/ benches/

# Touch to invalidate cached dummy files
RUN touch src/bin/qpb-node.rs src/lib.rs

# Build the actual binary (with SHRINCS if enabled)
RUN if [ "$ENABLE_SHRINCS" = "true" ]; then \
        cargo build --release --features shrincs-dev --bin qpb-node; \
    else \
        cargo build --release --bin qpb-node; \
    fi

# Stage 2: Runtime image
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 qpb

# Create data directory
RUN mkdir -p /data && chown qpb:qpb /data

# Copy binary from builder
COPY --from=builder /build/target/release/qpb-node /usr/local/bin/qpb-node

# Copy chainparams to expected location (node has hardcoded path)
COPY --from=builder /build/docs/chain/chainparams.json /etc/qpb/chainparams.json

# Create symlink at hardcoded path for compatibility
RUN mkdir -p /data/docs/chain && \
    ln -s /etc/qpb/chainparams.json /data/docs/chain/chainparams.json

# Switch to non-root user
USER qpb

# Set working directory
WORKDIR /data

# Expose ports
# P2P: 8333 (mainnet), 18333 (testnet), 28333 (devnet)
# RPC: 8332 (mainnet), 18332 (testnet), 28332 (devnet)
EXPOSE 8333 18333 28333
EXPOSE 8332 18332 28332

# Default to devnet for safety
ENV QPB_CHAIN=devnet
ENV QPB_DATADIR=/data
ENV QPB_RPC_ADDR=0.0.0.0:28332

# Health check using the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${QPB_RPC_ADDR#*:}/health || exit 1

# Default command (shell form for env var expansion)
CMD /usr/local/bin/qpb-node \
    --chain=${QPB_CHAIN} \
    --datadir=${QPB_DATADIR} \
    --rpc-addr=${QPB_RPC_ADDR} \
    --chainparams=/etc/qpb/chainparams.json \
    --listen
