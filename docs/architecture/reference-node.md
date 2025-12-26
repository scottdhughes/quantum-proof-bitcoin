# QPB Reference Node Route Decision

**Decision:** Route A (Rust-native minimal node) is the reference node for devnet/testnet now. Route B (a Bitcoin Core fork) is deferred until after testnet stabilizes.

## Why this decision
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

**Phase 0B status (current):** Blockstore + UTXO persistence and tip-only submitblock wired in-process. Minimal JSON-RPC (HTTP POST /rpc) is available for getblockcount/getbestblockhash/getblockhash/getblock/submitblock/getutxo. No P2P/mempool yet.

### Phase 1 — Minimal P2P sync
**Phase 1A status (current):** Outbound headers-first sync (getheaders/headers/getdata/blocks) to a single peer, tip-only (no reorgs yet). No mempool/tx relay.

**Deliverables (overall Phase 1)**
- Headers-first sync with basic DoS limits.
- Block download + validation pipeline feeding Phase 0 storage/UTXO.
- Peer management basics: outbound connections, addr seeds (static/manual).

**Non-goals**
- Transaction relay.
- Compact blocks, BIP324, or encryption.
- Address relay, addrman heuristics.

Run example: `cargo run --bin qpb-node -- --chain devnet --datadir /tmp/qpb-dev --rpc-addr 127.0.0.1:38332 --p2p-connect 127.0.0.1:18444 --no-pow`

### Phase 2 — Mempool + mining (optional)
**Deliverables**
- Minimal mempool with fee/ancestor limits suitable for dev/testnet.
- `getblocktemplate` for external miners; ability to assemble candidate blocks.
- Optional local CPU miner reuse of existing PoW module.

**Non-goals**
- RBF policy, package relay, or advanced fee estimation.
- P2P tx relay robustness (ok if absent; focus stays on validation + template).
- Wallet/key UX.

## Deferred Route B (Bitcoin Core fork)
- Consider after testnet stabilization to achieve protocol parity and broader ecosystem tooling.
- Would reuse the stabilized consensus rules, chainparams, and vectors from this repo.
