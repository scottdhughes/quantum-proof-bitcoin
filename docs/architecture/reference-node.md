# QPB Reference Node Architecture

**Decision:** Route A (Rust-native minimal node) is the reference implementation for devnet/testnet. Route B (Bitcoin Core fork) is deferred until after testnet stabilizes.

> **See Also:**
> - [RPC Reference](../rpc/README.md) - Complete API documentation
> - [Running a Node](../operations/running-a-node.md) - Installation and configuration guide

## Why Route A
- Faster iteration on consensus and tooling using the existing Rust consensus crate.
- Keeps PoW, PQ validation, and vector determinism unified in one codebase.
- A future Core port remains possible once testnet parameters and wire behavior are stable.

## Phased plan

### Phase 0 — Core validation spine
**Deliverables**
- Persistent storage for headers, blocks, and UTXO set.
- Full block/tx validation wired to the consensus crate (no policy/mempool needed).
- Minimal RPC: `getblock`, `getblockhash`, `getblockheader`, `submitblock`, `getchaintips`, `getbestblockhash`.
- Deterministic CHAIN_ID and genesis wiring from `docs/chain/chainparams.json`.

**Non-goals**
- P2P networking.
- Fee policy, mempool, or relay rules.
- Wallet/key management.

**Phase 0A status:** Implemented genesis init + persistent tip/index only (no RPC/submitblock yet). Run `qpb-node --chain devnet|regtest --datadir <path>` to bootstrap from `docs/chain/chainparams.json` and persist height/tip/index on disk.

**Phase 0B status:** Complete. Blockstore + UTXO persistence with tip-only submitblock. Full JSON-RPC API with 40+ methods. See [RPC Reference](../rpc/README.md).

### Phase 1 — Minimal P2P sync
**Phase 1A status:** Outbound headers-first sync (getheaders/headers/getdata/blocks) to a single peer, tip-only (no reorgs yet). No mempool/tx relay.

**Phase 1B1 status:** Outbound sync with multiple peers (try in order until one succeeds), read/write timeouts, max message size guard (8MB), safer partial reads. Still tip-only; no reorgs or inbound/mempool.

**Phase 1B2 status (current):** Outbound sync now retries peers with backoff/deadline; recovers from dropped connections mid-handshake or mid-block. Still tip-only; no forks/reorgs/mempool.

**Deliverables (overall Phase 1)**
- Headers-first sync with basic DoS limits.
- Block download + validation pipeline feeding Phase 0 storage/UTXO.
- Peer management basics: outbound connections, addr seeds (static/manual).

**Non-goals**
- Transaction relay.
- Compact blocks, BIP324, or encryption.
- Address relay, addrman heuristics.

Run example: `cargo run --bin qpb-node -- --chain devnet --datadir /tmp/qpb-dev --rpc-addr 127.0.0.1:38332 --p2p-connect 127.0.0.1:18444 --no-pow`
Multi-peer example: `... --p2p-connect 127.0.0.1:18444 --p2p-connect 127.0.0.1:18445`

### Phase 2 — Mempool + mining
**Status:** Complete.

**Implemented:**
- Mempool with fee/ancestor limits
- `getblocktemplate` for external miners
- Local mining via `generatenextblock`, `generateblock`, `generatetoaddress`
- RBF support with `bumpfee` RPC
- Fee estimation via `estimatesmartfee`
- Full wallet with encryption, backup/restore
- Transaction relay between nodes
- Inbound P2P connections
- Peer scoring and ban management
- RPC authentication and rate limiting
- Health and metrics endpoints

**Non-goals (Phase 2)**
- Package relay or CPFP
- Compact blocks (BIP152)
- Difficulty adjustment (uses static bits)

Run mining example:
`curl -s -X POST http://127.0.0.1:38332/rpc -d '{"jsonrpc":"2.0","id":1,"method":"generatenextblock","params":[]}'`

Stop example:
`curl -s -X POST http://127.0.0.1:38332/rpc -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"stop","params":[]}'`

## Deferred Route B (Bitcoin Core fork)
- Consider after testnet stabilization to achieve protocol parity and broader ecosystem tooling.
- Would reuse the stabilized consensus rules, chainparams, and vectors from this repo.
