# Build stage
FROM rust:1.87-bookworm AS builder

WORKDIR /build

# Copy workspace configuration
COPY Cargo.toml Cargo.lock ./

# Copy only what's needed for faucet
COPY tools/faucet tools/faucet

# Create dummy src for the main crate to satisfy workspace
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/bin/qpb-cli.rs && \
    echo "fn main() {}" > src/bin/gen_vectors.rs && \
    echo "fn main() {}" > src/bin/gen_chainparams.rs && \
    echo "fn main() {}" > src/bin/qpb-wallet.rs && \
    echo "fn main() {}" > src/bin/bench_perf.rs && \
    echo "" > src/lib.rs

# Build faucet in release mode
RUN cargo build --release -p qpb-faucet

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/qpb-faucet /usr/local/bin/

ENV QPB_RPC_URL=http://qpb-testnet:38335/rpc
ENV QPB_RPC_USER=rpcuser
ENV QPB_RPC_PASS=rpcpass
ENV FAUCET_PAYOUT_SATS=100000000
ENV FAUCET_RATE_LIMIT_SECS=3600
ENV FAUCET_PORT=8080

EXPOSE 8080

CMD ["qpb-faucet"]
