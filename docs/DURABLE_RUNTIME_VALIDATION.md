# Durable runtime validation — 2026-11-09

The one-click launcher now starts Docker Desktop when needed, resumes the same
disposable ML-DSA wallet, and opens the local browser console. The native runtime
and wallet/chain state are stored in Docker volume
`pqbtc-mldsa-local-data-v1`; signer IPC remains ephemeral.

Double-click **Launch Local Wallet.command** in the repository root, or run:

```sh
./contrib/ml-dsa-console/launch.command
```

Repeated launch reopens/resumes the existing console. If the current wallet
cannot resume, the HTTP console stays available for backup recovery. It does not
silently create a replacement wallet.

## Actual end-to-end result

**PASS** — the final run exercised all of these against actual Linux native
processes and Docker Desktop:

1. Migrate the previously tested wallet and qualified binaries into persistent
   storage, preserving the wallet identity and existing balance.
2. Make a backup, issue a later address, send and mine.
3. Restart **Docker Desktop itself** while the host app remains open, then use
   the same launcher to resume the same wallet and chain.
4. Force-kill and remove the managed container, then recreate it around the
   same volume. Confirm the container ID changed while wallet identity did not.
5. Close the app, stop Docker Desktop, then launch through the one-click script.
   It starts Docker, starts the container, and opens the same wallet.
6. Cleanly stop the wallet and rename its current encrypted record to a unique
   diagnostic file. The record is preserved, not deleted or read on macOS.
7. Relaunch with the current record missing. The console remains available and
   reports the startup error with saved recovery points.
8. Restore the older backup, retain later address floors and confirmed chain,
   create another address, spend again, and mine. Require matching full UTXO
   hashes on both nodes and successful final shutdown.

The final evidence contains **35 steps** and records the same wallet identity
through every boundary: `1bfcc1a4bd726f58c26ee2d8e6ccb62e`.

```text
before restart spend: 06832eb7ef91ab8cad37b5cf966ee94670a90e6773edff4a17ce4183da7aae34
after recovery spend: cbb9a20732878c71b421bad5ba43b93230937900088057196b8503fa85d673e1
final spendable sats: 1,994,000
next receive index:  13
both node heights:   108
both UTXO counts:    115
tip:  1d1a9e7d6399453f9f9f483b3514ce02c8d43b4febb97d234a64ed18b47a3840
UTXO: a4685a0ea48e63ce5c4243bd62b3ccb0c6b9cefe3de2c0d8f7a79a60eb420971
```

The 13 MUSASHI containers were stopped as authorized and remained stopped after
the Docker restart tests. Their containers/volumes and restart policies were
not deleted or changed.

## Tests and evidence

**111 focused tests passed**, covering the console runtime, controller,
durable runtime manager, launcher/HTTP integration, and existing protocol.
All 11 console/test Python files passed compilation and the repository's
selected 38 Ruff rules. JavaScript syntax, both launcher shell scripts, and
`git diff --check` passed.

```sh
python3 -m unittest ci.test.test_ml_dsa_console_runtime \
  ci.test.test_ml_dsa_console_controller ci.test.test_ml_dsa_console_durable \
  ci.test.test_ml_dsa_console_launcher ci.test.test_ml_dsa_console_http \
  ci.test.test_ml_dsa_protocol_v1
python3 contrib/ml-dsa-console/test_restart_end_to_end.py \
  --allow-docker-restart \
  --output /Users/scott/quantum-proof-bitcoin-evidence/20261109-durable-restart-and-missing-wallet-flow.json
node --check contrib/ml-dsa-console/web/app.js
sh -n 'Launch Local Wallet.command' contrib/ml-dsa-console/launch.command
git diff --check
```

The restart driver refuses optimized Python so its assertions and shared-engine
exclusivity checks cannot be disabled with `-O` or `PYTHONOPTIMIZE`. It requires
explicit engine-restart authorization and refuses unrelated running containers.

Evidence files outside the repository:

- `20261109-durable-restart-and-missing-wallet-flow.json` and `.log` — final run.
- `20261109-durable-restart-flow.json` and `.log` — earlier complete restart run.
- `20261109-durable-final-state.json` — final storage identity and live status.
- `20261109-durable-code-sha256.json` — exact uncommitted source/document hashes.
- `20261109-durable-ready.png` — browser after final relaunch.

All are under `/Users/scott/quantum-proof-bitcoin-evidence/`.

## Implementation and limits

`durable.py` manages Docker readiness, labeled storage, bounded migration, and
container recreation. `controller.py` validates volume UUID/native identity,
reconciles exited Docker handles without inventing a clean signer checkpoint,
and restores a backup even if current files are missing or corrupt. `runtime.py`
preserves safe orphan public-write files under the writer lock and refreshes
RPC connections per action without retrying an ambiguous mutation. `app.py`
reopens the same console and keeps recovery available on failed automatic
resume. The existing backup identity/schema remains compatible.

The native source remains clean at
`9f4b20a938e67ef985df0780fb41b6035abef15e`, with the three existing qualified
binary hashes enforced. The copied Git objects are self-contained. The final
container uses network none, read-only rootfs, cap-drop ALL with no additions,
no-new-privileges, 4 CPU/4 GiB limits, one named data volume, ephemeral IPC, and
no host bind mounts. Native prototype code never executes on macOS.

The app has been left running at `http://127.0.0.1:8844`. The whole host state
directory and named volume should be retained. Deleting volumes, resetting or
uninstalling Docker, or losing its backing disk is outside the restart guarantee;
lost native artifacts are not downloaded/rebuilt automatically.

A computer reboot was **not performed**. Actual Docker engine restart, cold
engine start, host app restart, forced container recreation, and missing-wallet
recovery were tested. Those exercise the app's restart path while avoiding a
reboot of the user's other applications.

These are disposable test coins with a public fixture phrase. Production
qualification, independent human cryptographic review, and public soak remain
outstanding. At this checkpoint work remained uncommitted in the isolated console
worktree; no push, merge, publication, or reviewer contact had occurred.
Subsequent publication and CI results are recorded in
[GitHub CI validation](GITHUB_CI_VALIDATION.md).
