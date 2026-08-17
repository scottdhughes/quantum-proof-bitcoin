# PQBTC SHRINCS-v0 private mineable labnet

This directory turns the repository's regtest-only SHRINCS-v0 consensus path into a persistent local development network that can be built, mined, funded, signed, broadcast, and inspected from one controller.

It is deliberately a **zero-value private labnet**. It does not enable SHRINCS-v0 on mainnet, testnet, testnet4, or signet, and it does not make the current draft implementation production-safe.

## One-command end-to-end run

Install the native build dependencies on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
  build-essential cmake ninja-build libboost-dev libevent-dev \
  libsqlite3-dev pkg-config
```

On macOS with Homebrew:

```bash
brew install cmake ninja boost libevent sqlite pkg-config
```

Then run:

```bash
python3 contrib/shrincs-labnet/labnet.py quickstart --fresh --mode both
```

That command:

1. configures and builds `pqbtcd`, `pqbtc-cli`, the wallet, the verifier, and tests;
2. starts two persistent local regtest nodes on isolated ports;
3. connects and synchronizes them;
4. creates local wallets and mines enough blocks to mature coinbase funds;
5. fetches and verifies the exact executable signer model at commit
   `acc6bda51dc3b94848d118967247ad0f3cd7a80e`;
6. creates a local SHRINCS key and crash-safe SQLite state database;
7. funds genuine witness-v2 SHRINCS outputs;
8. creates one stateful and one stateless signed spend;
9. proves a one-bit signature mutation is rejected;
10. broadcasts and mines both valid transactions; and
11. reports node, wallet, transaction, and signer state as JSON.

The default persistent paths are:

```text
build-shrincs-labnet/   native build
.shrincs-labnet/        node, chain, wallet, upstream, and signer state
```

## Daily commands

```bash
# Start an existing labnet without erasing its chain or signer state
python3 contrib/shrincs-labnet/labnet.py start

# Show both nodes, heights, balances, connections, and signer state
python3 contrib/shrincs-labnet/labnet.py status

# Mine additional blocks and synchronize both nodes
python3 contrib/shrincs-labnet/labnet.py mine 10

# Exercise a real stateful spend
python3 contrib/shrincs-labnet/labnet.py shrincs-demo --mode stateful

# Exercise stateless recovery without consuming an FXMSS leaf
python3 contrib/shrincs-labnet/labnet.py shrincs-demo --mode stateless

# Stop both nodes cleanly
python3 contrib/shrincs-labnet/labnet.py stop
```

`start --fresh` erases only a directory carrying the controller's marker file. It refuses to recursively delete an unmarked directory.

## Stateful signing invariant

The executable upstream model explicitly warns that reusing a state counter for a different message is a security failure. The controller therefore does not call the stateful signer and then try to save state afterward.

For each stateful signature it performs this order:

```text
BEGIN IMMEDIATE
insert durable reservation for state n
advance next_state to n + 1
COMMIT with SQLite synchronous=FULL
compute signature with state n
self-verify signature
mark reservation signed
broadcast transaction
bind reservation to txid
```

A crash after the reservation burns a leaf. It never makes that leaf available again. A signing failure is recorded as `failed` and also burns the leaf. Exhaustion fails explicitly; it never silently falls back to the stateless path.

The current frozen lab profile uses the draft's unbalanced depth-4 FXMSS structure, which provides five stateful signatures. Stateless recovery remains available after those leaves are consumed.

The database contains private key material in plaintext and is created with owner-only permissions. That is acceptable only for this zero-value research labnet. A production signer requires hardware isolation, authenticated control, side-channel review, secure deletion assumptions, external cryptographic review, and a formally specified backup/recovery process.

## Supply-chain boundary

The controller loads only the exact upstream executable-model commit frozen by this repository. An existing checkout with a different `HEAD` is rejected. Set `SHRINCS_BIP_DIR` to use a pre-existing exact checkout:

```bash
SHRINCS_BIP_DIR=/path/to/shrincs-bip \
python3 contrib/shrincs-labnet/labnet.py signer-init
```

The commit pin is a reproducibility and supply-chain requirement, not an arbitrary release gate.

## Tests

Fast state-machine tests:

```bash
python3 contrib/shrincs-labnet/test_labnet.py -v
```

Native interpreter and transaction-envelope tests:

```bash
build-shrincs-labnet/bin/test_pqbtc \
  --run_test=shrincs_tx_v0_signed_seam_tests,shrincs_tx_v0_tests \
  --catch_system_error=no
```

The branch workflow also performs the complete two-node stateful/stateless funding, rejection, broadcast, and mining sequence.

## What this proves—and what it does not

This labnet proves that the current frozen transaction envelope and verifier can execute through node validation on a mined private chain, with persistent state allocation around the draft signer.

It does **not** prove:

- cryptographic security of the draft construction;
- constant-time or fault-resistant signing;
- safe production key custody;
- safe state coordination across cloned signers;
- economic security of regtest proof of work;
- production wallet backup and restore; or
- readiness for a public-value network.

Those are real engineering and review requirements, not arbitrary blockers.
