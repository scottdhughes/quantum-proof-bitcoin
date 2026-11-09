# Durable Local Runtime Implementation Plan

> **For agentic workers:** Use subagent-driven development or executing-plans; keep ownership boundaries below. User explicitly requested implementation and end-to-end restart/recovery testing. Do not commit or publish.

**Goal:** One click starts Docker if needed, resumes the same wallet/chain after Docker/computer restart, and can recover an older backup and spend again.

**Architecture:** Preserve the qualified native paths in a managed Docker named volume mounted at `/tmp`. Keep signer IPC in an ephemeral `/run/pqbtc-ipc` tmpfs. The host launcher provisions or resumes only the managed container, starts the local server/network, and reopens an already-running console. Existing public metadata and encrypted backups keep their schema/native identity.

**Tech Stack:** Python standard library, existing Docker Desktop CLI, existing qualified Linux arm64 image/binaries. No native prototype execution on macOS.

## Global constraints

- Preserve the old ephemeral container until migrated wallet identity, balance, counters and a new spend pass.
- Exact native source `9f4b20a938e67ef985df0780fb41b6035abef15e` and existing three native SHA256 qualification pins.
- Runtime: read-only rootfs, network none, cap-drop ALL, no-new-privileges, 4 CPU, 4 GiB memory; no host bind mounts after migration.
- Native state volume at `/tmp`; IPC tmpfs `/run/pqbtc-ipc` with `rw,noexec,nosuid,nodev,size=1048576,mode=1777`.
- Separate signer UID1000 and public worker UID1001, shared GID1000.
- User authorized stopping all 13 MUSASHI containers and an actual Docker Desktop restart; leave those MUSASHI containers stopped.
- Only generated disposable fixture records are involved; do not access unrelated credentials or user financial data.

## Review focus

- Missing volume or failed migration must never silently create a replacement wallet.
- Container recreation must bind to the same labeled volume UUID, not only a reusable volume name.
- Abrupt Docker exit leaves no invented clean signer checkpoint; native record/public floors remain authoritative.
- Repeated one-click launch reopens/resumes the existing console and cannot start a competing node pair.
- Migration is self-contained: no source Git alternates or host-path dependency survives in the durable container.

## Task 1 — Managed runtime (durable_manager)

Own `contrib/ml-dsa-console/durable.py`, `ci/test/test_ml_dsa_console_durable.py`.

- [x] Write failing subprocess-boundary tests for stopped/missing daemon/container, foreign storage, partial migration and missing existing wallet state.
- [x] Implement `RuntimeManager(container='pqbtc-mldsa-local', volume=None, seed_container='pqbtc-mldsa-demo-20261109').ensure(state_dir, progress=print) -> {container,volume,volume_id}`.
- [x] Start Docker Desktop when needed, enforce owned labels/config, migrate selected state via contained tar streams preserving UIDs/modes, make copied source Git objects self-contained, validate native pins, and publish durable/migration markers last.
- [x] Run focused tests; root performs actual migration and restart tests.

## Task 2 — Persistent controller (console_controller)

Own `controller.py`, `ci/test/test_ml_dsa_console_controller.py`.

- [x] Pin valid durable mount/label/marker layout in tests; refuse foreign or changed volume UUID.
- [x] Retain legacy tmpfs fixture support for the migration source, bind durable storage identity after explicit migration-marker validation.
- [x] Create ephemeral signer IPC directories, preserving persistent wallet directories.
- [x] Reconcile exited Docker exec handles after engine restart without claiming a clean checkpoint; resume native/public counters safely.
- [x] Test recreation and abrupt exit, then root replays the real flow.

## Task 3 — Crash residue (console_runtime)

Own `runtime.py`, `ci/test/test_ml_dsa_console_runtime.py`.

- [x] Reproduce an orphan public-wallet.tmp and unsafe file cases.
- [x] Preserve safe owned orphan temps under unique diagnostic names after taking the public-store lock; never overwrite/delete uncertain state.
- [x] Keep signer observation as authority for later address floors; verify existing protocol tests.

## Task 4 — One-click app and real evidence (root)

Own `app.py`, `launch.command`, HTTP/launcher tests, restart E2E driver, README/validation docs.

- [x] Add HTTP/launcher tests for managed startup, existing-console reopen and auto-resume.
- [x] Integrate runtime manager with launcher; keep a clearly named prepared-runtime mode for legacy experiments.
- [x] Cleanly back up/stop default fixture, migrate and resume same wallet; preserve old container.
- [x] Exercise actual Docker Desktop restart with host console alive; then stop/remove/recreate only managed container and reopen through launcher, retaining wallet/chain/counters.
- [x] Stop Docker Desktop and relaunch via one-click path to exercise cold daemon start. Test older-backup recovery and a post-recovery spend, matching both node UTXO hashes.
- [x] Run all focused suites/lint/syntax checks, browser smoke test, and save source hashes/public evidence. Report actual reboot boundary: computer reboot is not performed, but Docker daemon, app process and container recreation are tested.
