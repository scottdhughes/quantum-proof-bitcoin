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

**Phase 0B status (current):** Blockstore + UTXO persistence and tip-only submitblock wired in-process (no RPC/P2P/mempool yet). Next step: expose JSON-RPC over HTTP in a later Phase 0B step.

### Phase 1 — Minimal P2P sync
**Deliverables**
- Headers-first sync (inv/getheaders/headers/getdata/blocks) with basic DoS limits.
- Block download + validation pipeline feeding Phase 0 storage/UTXO.
- Peer management basics: outbound connections, addr seeds (static/manual).

**Non-goals**
- Transaction relay.
- Compact blocks, BIP324, or encryption.
- Address relay, addrman heuristics.

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
