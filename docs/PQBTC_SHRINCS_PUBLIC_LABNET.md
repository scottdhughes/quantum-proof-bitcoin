# PQBTC SHRINCS public zero-value labnet

This profile is the first network-distinct PQBTC chain that exercises the frozen
SHRINCS-v0 transaction authorization path.  It is selected with:

```bash
pqbtcd -regtest -shrincslab
```

It deliberately reuses mature **regtest machinery** (instant mining and no
retargeting) while replacing every network-facing identity that could collide
with Bitcoin regtest:

| Field | SHRINCS labnet |
|---|---|
| Genesis | `122201a7b5dc205ec063486e4080760ab8f73c3f07804d69351da96bd6c2ab69` |
| Merkle root | `2dec88624f3bbd6308ed55b83d9cb01933bbc76759498e52d21130c4e6ccd672` |
| Message magic | `91e1cac8` |
| Default P2P port | `29333` |
| Recommended RPC port | `29332` |
| Bech32 HRP | `pqsl` |
| DNS/fixed seeds | none |

Ordinary `-regtest` does **not** activate SHRINCS on this branch.  Mainnet,
testnet3, testnet4, and signet remain unchanged.

## Start a two-node network and mine

```bash
python3 contrib/shrincs-labnet/labnet.py quickstart --fresh --mode both
python3 contrib/shrincs-labnet/labnet.py mine 10
python3 contrib/shrincs-labnet/labnet.py status
```

The quickstart builds the node, starts two peers, mines mature funds, creates a
crash-safe stateful signer, rejects a mutated signature, broadcasts one
stateful and one stateless SHRINCS spend, and mines both.

## Public node

Use `contrib/shrincs-labnet/shrincslab.conf.example` as a starting point.  Expose
only P2P port `29333`.  Keep RPC firewalled and use cookie authentication.
Until seed operators exist, peers join with `-addnode=<host>:29333`.

The supplied Docker Compose file starts a seed, miner, and observer on one
machine for deployment rehearsal.  It does not create economic security.

## Security scope

At compact target `0x207fffff`, a block requires about two SHA-256d attempts on
average.  This is ideal for testing and worthless as adversarial hash security.
Coins on this network must never be sold, custodied as value, or represented as
production-ready.  The current SHRINCS draft and signer remain research code.

## Genesis-bound signature domain

Every SHRINCS transaction signature commits to:

```text
PQBTC-SHRINCSLAB-v0|genesis=122201a7b5dc205ec063486e4080760ab8f73c3f07804d69351da96bd6c2ab69
SHA256 = db0e425cda8dcebc9e64203d2a5dfde2e954954f3dc95b8b9807590103d07652
```

This is intentionally incompatible with the earlier private-regtest fixture.
A signature from that fixture cannot authorize an otherwise identical labnet
transaction, and changing the labnet genesis requires a new signature domain.

## Filesystem and RPC isolation

`-regtest -shrincslab` selects base data directory `shrincslab/` and default
RPC port `29332`. Ordinary regtest keeps `regtest/` and `18443`. The two chains
therefore cannot share block databases, wallets, cookies, settings, or RPC
endpoints by default. The inherited `[regtest]` configuration section remains
intact so mature Bitcoin Core test and port-assignment tooling keeps working.
