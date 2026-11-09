# Local ML-DSA wallet console

A browser interface to the real, two-node ML-DSA regtest prototype. Native
node, client, and signer execution stays inside an isolated Linux
container. The browser and host controller use Python's standard library;
there are no npm packages, CDNs, or live network dependencies.

## Launch

Prerequisites: Git, Python 3.11 or newer, and Docker with Linux containers and
BuildKit. On macOS use Docker Desktop; the launcher starts it when needed. On
Linux start Docker Engine first. Allow several GiB of free Docker storage for
the compiler, native build and image. The first build needs internet access.

Clone this repository and enter the checkout. Fresh source installation requires
a clean Git checkout, including untracked files; build output and wallet state
are stored outside it.

Double-click **Launch Local Wallet.command** in the repository root, or from
Terminal:

```sh
./contrib/ml-dsa-console/launch.command
```

On Linux, the direct entrypoint is also available:

```sh
python3 contrib/ml-dsa-console/app.py
```

The launcher starts Docker Desktop if needed, starts the isolated runtime,
resumes the wallet and its two nodes, and opens **http://127.0.0.1:8844**. Clicking
the launcher again reopens the same console. **Start network** is available
after you have stopped the network from the page. The HTTP server binds to
loopback only.

If the current wallet cannot open, the console stays available and shows
recovery guidance. Open **Backup & recovery**, select a saved backup, and
restore it. The restore validates the retained volume and backup; it does not
require the damaged current wallet file to remain readable.

On a fresh machine the launcher builds the current committed source with GCC12
inside a pinned Debian Linux image. It downloads and checksum-checks OpenSSL
3.6.5, builds the node/client/signer, and runs native integration, signer and
node tests. Compilation and native tests run with network disabled after the
dependency download. No prepared project image, container, binary, host OpenSSL
or private local path is required. The source export includes minimal generated
Git metadata, never the user's original Git configuration or credentials.

The image records Git commit/tree, compiler, architecture, installed dependency
versions, native hashes and test evidence. The first launch initializes
**pqbtc-mldsa-local-data-v1** from that image. Later launches check the saved
image/manifest identity and resume without rebuilding. After installation,
Docker and computer restarts preserve the native runtime, encrypted wallet,
public address record, and node chain state. The container can be recreated
around the same volume; it has no host-folder mounts or internet access.

Signer sockets live in a separate temporary filesystem and are recreated at
launch. A fresh container is accepted only when the labeled volume UUID matches
the retained session. A missing or different volume is refused when resuming a
wallet; the launcher never silently replaces it with a new wallet.

Existing wallets on the earlier prepared runtime continue using their existing
qualified binaries and volume. A new source installation does not migrate or
overwrite them automatically. For an independent test install, use a different
`--container`, `--state-dir`, and `--port`.

Select the Clang16 build or disable the first-build cache explicitly:

```sh
python3 contrib/ml-dsa-console/app.py --compiler clang --no-build-cache
```

Builds retain exact input/toolchain and binary receipts. The operating-system
package versions are recorded rather than locked to a permanent snapshot;
universal bit-for-bit reproducibility across future package updates is not
claimed.

## Try the whole flow

1. Click **Start network**. Check that both nodes have the same height and tip.
2. In **Receive**, click **Create receive address**, then **Copy address**.
3. Click **Add confirmed test coins** to receive 0.02000000 testBTC. This explicit
   faucet action also mines its funding transaction.
4. Open **Backup & recovery** and click **Create backup**.
5. Create another receive address. In **Send**, use that address, enter an
   amount such as `0.00500000`, and leave the default 1,000-sat fee. Sending to
   another address in this wallet is a simple self-transfer demonstration.
6. Click **Send test coins**. The receipt shows the real transaction ID; its
   outputs are pending until you click **Mine a block**. After a self-transfer,
   the total balance decreases by the fee.
7. Select the earlier backup, click **Recover selected backup**, and confirm.
   Recovery retains later public address counters and the latest compatible
   saved chain. Check the balance, create a new address, and send again.
8. **Lock wallet** closes signing. **Unlock wallet** restarts the fixture signer.
   **Stop network** stops both nodes and the signer while leaving the console
   open. Ctrl+C in the launch terminal closes the console and its lab processes.

All coins and wallets are disposable. The operator phrase is a deliberately
public test fixture, and unlocking asks for no password. This console is for
the experimental ML-DSA path. User-owned secret setup, production qualification
and public-network operation remain later milestones. The owner-selected testing
route is public GitHub; independent human review is recorded as not performed.

## Saved state and recovery

The default host directory is `~/quantum-proof-bitcoin-evidence/local-console`
(0700). It contains public session metadata, a public chain snapshot, a runtime
log, and 0600 JSON backup bundles. Bundles contain the 167-byte encrypted wallet
record, public address manifest/counters, source/binary identity, and raw public
blocks with a checksum. The checksum detects accidental corruption; it does not
authenticate an attacker-controlled replacement bundle.

Keep the **whole directory** to retain address floors issued after an older
backup. A lone old encrypted record cannot reconstruct later issued public
addresses. Recovery checks a selected backup before stopping the current lab,
then opens a fresh contained state directory and replays the retained chain.
The UI selects local backups; it does not upload or import arbitrary files.
Keep both this host directory and the Docker volume. Ordinary **Docker Desktop
restart**, **container stop**, and **computer restart** preserve the volume.
Deleting volumes, factory-resetting Docker, or uninstalling Docker can remove
it. Keep the matching source-build descriptor (`runtime.json`) and host backup
directory as well as the volume. An existing wallet requires its matching image
and manifest; a new build does not silently replace missing custody state.

Advanced launch options:

```sh
./contrib/ml-dsa-console/launch.command --no-browser --port 8844 \
  --state-dir /absolute/path/to/a/private-console-directory
```

An existing state directory must be owned by the current user with mode 0700.
Use one active wallet console per managed container. The app reconciles exited
Docker handles after engine restart; one click resumes it. Native prototype
binaries execute only in Linux. To open controls without starting the network,
add `--no-autostart`.

The original ephemeral fixture is available only as an explicit engineering
mode: `--prepared-runtime --container pqbtc-mldsa-demo-20261109`. This mode does
not provision a durable runtime. Its original tmpfs contents disappear when its
container stops; it is not the normal launcher path.

## Validation

The assembled-system GitHub Actions job builds both GCC and Clang from exact
clean source, then runs the real HTTP spend/old-backup recovery flow, app and
container recreation, and another confirmed spend. To run that same job locally
without disturbing an existing wallet:

```sh
python3 contrib/ml-dsa-console/run_assembled_ci.py --compiler gcc --no-cache \
  --container pqbtc-ci-local-gcc --port 8845 \
  --output-dir /absolute/path/outside-the-checkout/new-evidence
```

Use `--compiler clang` with another unique name/output directory for the second
lane. The runner refuses existing containers/volumes in its test namespace,
retains failures for diagnosis, and removes only its own disposable runtime
after success. Native build/test receipts and whole-flow results are retained in
the evidence directory. It never restarts the shared Docker engine.

The focused tests run on the host using only Python fixtures and HTTP:

```sh
python3 -m unittest ci.test.test_ml_dsa_console_runtime \
  ci.test.test_ml_dsa_console_controller ci.test.test_ml_dsa_console_durable \
  ci.test.test_ml_dsa_console_launcher ci.test.test_ml_dsa_console_http
node --check contrib/ml-dsa-console/web/app.js
```

With a console running on a **fresh** state directory and launched with
`--no-autostart`, run the real HTTP flow:

```sh
python3 contrib/ml-dsa-console/test_end_to_end.py \
  --output /absolute/path/to/new-console-flow.json --leave-running
```

That driver creates two real spends separated by an old-backup recovery,
checks non-reuse of an issued address index, stop/start persistence, lock/unlock,
invalid address and insufficient-funds rejection, and matching full UTXO hashes
on both nodes. It spends only disposable fixture coins. The native operations
run in the prepared offline Linux container. Without `--leave-running`, the
driver also requires a successful final stop before reporting PASS.

The restart driver tests the shared Docker engine, so run it only when
interrupting other Docker work is authorized and no unrelated containers are
running. Stop the console first; this driver owns its launch process. Use a
funded disposable wallet:

```sh
python3 contrib/ml-dsa-console/test_restart_end_to_end.py \
  --allow-docker-restart --output /absolute/path/to/new-restart-flow.json
```

It tests an actual Docker Desktop restart with the app alive, forced container
loss/recreation, a stopped Docker engine and new app process launched through
the same one-click script, missing-current-wallet recovery from an older
backup, and another real spend. It
checks wallet identity, balances, increasing address indexes, and both nodes'
full UTXO hashes. It does not reboot the computer itself.
