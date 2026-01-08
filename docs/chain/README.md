# QPB chain parameters pack

This directory carries a deterministic `chainparams.json` describing network IDs, ports, genesis blocks, and CHAIN_ID derivation for QPB networks.

## Schema (summary)
- `schema_version`: 1
- `chain_id_derivation`: `"CHAIN_ID = HASH256(SerializeBlockHeader(genesis_header))"`
- `networks`: map of network name -> params:
  - `name`, `hrp`, `p2p_magic` (4-byte hex), `p2p_port`, `rpc_port`
  - `genesis`: genesis data or `null` if not finalized
    - `coinbase_tx_hex`
    - `header` (version, prev_blockhash_hex, merkle_root_hex, time, bits, nonce)
    - `block_hash_hex` (Argon2 PoW hash)
    - `chain_id_hex`  (double-SHA256 of header)

## Current status (v1.2)
- Genesis-active PQ algorithm: alg_id **0x30 (SHRINCS)** — sole active algorithm.
- Deprecated (rejected by consensus): alg_id **0x11 (ML-DSA-65)** — removed.
- Reserved/inactive (rejected by consensus): alg_id **0x21 (SLH-DSA)**.
- Devnet and regtest genesis blocks are fully specified here with easy PoW (`bits=0x207fffff`).
- Testnet genesis is TBD; entry is present with `genesis: null` to keep the schema stable.

## CHAIN_ID derivation
```
CHAIN_ID = HASH256(SerializeBlockHeader(genesis_header))
```
where `SerializeBlockHeader` is the consensus (Bitcoin-style) 80-byte serialization and `HASH256` is double SHA256.

## p2p magic derivation
```
p2p_magic = first4bytes( HASH256("QPB:" + network_name) )
```
This keeps magic values deterministic and collision-resistant across networks.

## Regenerating chainparams.json
The generator is optional and not run in CI by default.
```
cargo run --bin gen_chainparams
```
This deterministically rebuilds `docs/chain/chainparams.json` for devnet/regtest (and leaves testnet as `null`). The file is pretty-printed and stable; rerunning should produce no diff.

