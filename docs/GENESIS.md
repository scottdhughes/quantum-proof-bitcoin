# GENESIS Specification

## Status: FROZEN
## Spec-ID: GENESIS-v1
## Frozen-By: gate-v1-bootstrap-20260222
## Consensus-Relevant: YES

## Purpose
Defines deterministic generation and committed values for PQBTC network identity and genesis blocks.

## Deterministic Inputs
- Seed phrase: `PqbtcGenesis/v1/2026-02-22`
- Hash primitive for derivations: SHA-256
- Networks: `main`, `test`, `regtest`

## Deterministic Derivation Rules
1. Compute `D = SHA256("<seed>|<network>|identity")`.
2. Message start bytes are `D[0..3]` with high-bit forcing (`byte | 0x80`).
3. Bech32 HRP is fixed by network: `pq` (main), `tq` (test), `rq` (regtest).
4. Compute `B = SHA256("<seed>|<network>|base58")`:
`PUBKEY_ADDRESS=B[0]`, `SCRIPT_ADDRESS=B[1]`, `SECRET_KEY=B[2]`,
`EXT_PUBLIC_KEY=B[3..6]`, `EXT_SECRET_KEY=B[7..10]`.
5. Genesis timestamp text is exactly:
`The Times 22/Feb/2026 PQBTC <network> genesis`.
6. Genesis output script is:
`OP_PUSHBYTES_65 || 04678a...11d5f || OP_CHECKSIG`.
7. Header fields are:
`version=1`, `bits=0x207fffff`, `time=1772057600 + le16(SHA256("<seed>|<network>|time")[0..1])`.
8. Start nonce is `le32(SHA256("<seed>|<network>|nonce")[0..3])`; increment until `hash <= target(bits)`.
9. Ports are fixed by network: main `22833/22832`, test `23833/23832`, regtest `24833/24832` (p2p/rpc).

## Committed Artifacts
- Generator tool path: `contrib/genesis/generate_constants.py`
- Output artifact path: `contrib/genesis/generated_constants.json`

## Frozen Constants
- `main`
`message_start=[0x85,0x92,0xa7,0xad]`, `p2p=22833`, `rpc=22832`, `hrp=pq`
`base58={188,112,227}`, `xpub=[70,238,60,233]`, `xprv=[232,156,209,5]`
`time=1772116563`, `nonce=4185130280`, `bits=0x207fffff`
`merkle=f586d6aae001c2f2fc69588582695650a8247bf628a2c21c40c334d527398838`
`genesis=2af71da20e6e03bfdfc2347edffbbb4087796678c8d57cacbccbd10eee7b31e4`
- `test`
`message_start=[0xa7,0xe2,0x9c,0xf7]`, `p2p=23833`, `rpc=23832`, `hrp=tq`
`base58={191,187,64}`, `xpub=[149,138,123,144]`, `xprv=[146,100,134,147]`
`time=1772119544`, `nonce=2499947721`, `bits=0x207fffff`
`merkle=d3bf22ef43098736f11406c5bff808e933df335705f4c8c022dcffaa0d26164a`
`genesis=2b6939c6a048aa840a962d19ee680879c0bcbbeeff6e258fd049b5a6a947a979`
- `regtest`
`message_start=[0x96,0xbd,0x87,0x9e]`, `p2p=24833`, `rpc=24832`, `hrp=rq`
`base58={121,197,115}`, `xpub=[153,13,180,18]`, `xprv=[61,100,33,230]`
`time=1772086429`, `nonce=17489643`, `bits=0x207fffff`
`merkle=eff22c74638125519d38bab3d58d460f93ff0d5ef57dfbabc9514353bdb458cb`
`genesis=36cc1172b59a75d055126cfb7a1d3b5d37eebc57bec9791fccfa48af6bbd15e2`

## Validation Requirements
- Chainparams must assert generated genesis hash and merkle root per network.
- No runtime randomization of identity constants is allowed.
- Any semantic change requires a new Spec-ID version.
