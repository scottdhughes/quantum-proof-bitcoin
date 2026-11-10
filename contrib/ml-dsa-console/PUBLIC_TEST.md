# Dedicated public-test wallet

This is the explicitly selected `MLDSA44-PUBLIC-TEST-v1` experiment. Coins have
no value. The public test does not change production admission or the existing
offline demo. Native qualification and the actual public soak have separate
receipts; installing this app does not establish either result.

From a clean checkout with Docker available, launch:

```sh
./contrib/ml-dsa-console/launch-public.command
```

The first launch builds the current committed source and opens
`http://127.0.0.1:8845`. Connect an existing test peer, or explicitly choose
**Initialize empty test chain (H1)** when starting a new dedicated chain.
Choose **Set up new wallet** and a password, reserve a receive address, and use **Mine mature test coins** to make
spendable test coins. Sending requires a `tq` address and an explicit amount/fee.
**Mine one block** confirms a relayed payment. Normal maturity is retained.

To join an existing chain without creating H1 locally, use:

```sh
python3 contrib/ml-dsa-console/public_app.py --runtime-descriptor /absolute/path/runtime.json
```

Connect an operator-supplied P2P endpoint, wait for activation and peer sync,
then set up/unlock the wallet. The public profile uses its own datadir and has
no inherited Bitcoin discovery seeds. A TLS transport endpoint needs the
declared P2P adapter; entering a TLS hostname directly is insufficient for the
native plaintext P2P protocol.

For headless first-chain setup, `--bootstrap` explicitly mines H1 if the chain
is empty. The launcher itself never enables this option automatically.

The dedicated container is `pqbtc-mldsa-public`, with data volume
`pqbtc-mldsa-public-data-v1`. Its immutable image contains binaries; the volume
contains encrypted wallet state and validated chain data. Only P2P is mapped
to host loopback port 23833, for the separately configured public transport.
RPC, browser controls and signer IPC are not published. This launcher does not
enable public ingress or change a Tailscale account setting. The original
`pqbtc-mldsa-local` app and port 8844 keep their separate state.

For an operator-provided public TLS ingress, start the supplied
`contrib/ml-dsa-qualification/public_transport.py` bridge with its declared
public IPv4 address and certificate hostname, inside the node's container.
Connect the node to that bridge's loopback endpoint, for example
`127.0.0.1:23834`. The corresponding public route/account setting must already
be enabled by its owner. No public-soak result is asserted by this guide.

Restart Docker or the computer, then launch the app again. It resumes the same
volume and opens locked. Enter the same password to resume signing. A lost
controller connection causes only this verified public container's process
namespace to restart; the encrypted state and independent address floors stay
intact. No password is retained for automatic unlock.

**Save encrypted backup** requires a clean native signer checkpoint and locks
the wallet. Backups are private JSON files under
`~/quantum-proof-bitcoin-evidence/public-console/backups/`. They contain the
167-byte encrypted root record and public recovery metadata, without a copy
of the blockchain. Keep the independent, private `public-wallet.json` floor
journal in the parent directory with the backups. That journal advances
durably before each address reservation; it is necessary to recover unused
issued addresses safely from an old backup. Missing independent floor data
causes recovery to refuse rather than guess a scan boundary.

Choose a backup and enter the password to recover. The controller first
authenticates staged encrypted custody and has the native signer check every
retained public key against the restored root. It merges current public floors
before selecting the recovered record. Old selected directories are retained
for diagnosis, and node history remains subject to ordinary validation. A
wrong password or corrupt/wrong-profile backup cannot replace selected custody.

For a compatible binary replacement, stop the console, retain its data and
backups, and use an exact source-built descriptor:

```sh
python3 contrib/ml-dsa-console/public_app.py --upgrade-descriptor /absolute/path/new-runtime.json
python3 contrib/ml-dsa-console/public_app.py --rollback-descriptor /absolute/path/previous-runtime.json
```

The replacement must have a genuinely distinct source version and image,
matching architecture, sealed contract and public profile. The previous
descriptor is retained. An interrupted replacement resumes the actual verified
installed version, or the prior version if candidate creation had not occurred.
Rollback changes binaries on the same data volume; it never restores a wallet
data snapshot or launches a second signer. Each version still needs its own
qualification receipts before public use.

Headless Linux can use `--no-browser --docker-sudo` with an existing descriptor
when that host already permits passwordless sudo for Docker. Passwords are
supplied only through the local console or the bounded trusted-operator input;
there is no password CLI argument or environment-variable option.
