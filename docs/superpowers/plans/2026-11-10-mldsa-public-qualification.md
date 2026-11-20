# Native qualification and public test soak implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans task-by-task.

**Goal:** Finish actual native qualification, then complete the owner's 24-hour public test-coin soak across Research and this Mac.

**Architecture:** Preserve the offline demo; add an explicit isolated CONTRACT-1 TEST profile. Share verification accounting between mempool, mining and block validation, and make signer/wallet/operator/runtime profile binding explicit. Qualify current-source binaries before a declared public run.

**Tech Stack:** Existing C++20/C ML-DSA node/backend, Python console/orchestration, pinned OpenSSL 3.6.5, Docker Linux x86_64/arm64, existing SSH/control route, native P2P plus a declared public ingress if required.

**Spec:** `docs/superpowers/specs/2026-11-10-mldsa-public-qualification-design.md`

## Global constraints

- Public test only; production flags/hold and sealed CONTRACT-1/regtest bytes stay unchanged.
- `-chain=test -mldsa44test`, distinct mldsa44-test-v1 namespace and frozen TEST identity; old defaults unchanged.
- Native v2/32 outputs and prevouts only, plus zero canonical <=80-byte OP_RETURN; enforce in mempool and ConnectBlock/reindex.
- One active ML-DSA cost of 625; inherited ceilings imply 128/block and 25/standard transaction; measure before public use.
- Research plus Mac, no paid hosting, no unrelated-service changes, sampled Research CPU <90%, original local wallet untouched.
- 24 actual public hours; predeclare workloads, source/versions and criteria; failed attempts cannot be relabeled PASS.

## Review focus

- Wrong network or stale source/profile manifest must refuse before wallet issuance or signing.
- Reindex-chainstate and assumevalid must not bypass output or signature rules.
- Mempool entries and miner templates must use the same active verification cost as blocks.
- Old-backup restore and binary rollback must preserve address floors and a single signer.
- Private peering, mocks, emulation and interrupted time must not become public/native/elapsed evidence.

## Ownership and interfaces

Root owns docs/manifests, `CMakeLists.txt`, `src/test/CMakeLists.txt`, `src/validation.cpp`, source qualification and public orchestration/rollout. Workers are not alone and must not revert others' work. No worker deploys or publishes without root coordination.

Network worker owns chainparams/base/kernel, ML-DSA node profile helpers, public RPC context, policy standardness changes and dedicated profile tests. Resource worker owns shared resource constants, interpreter/consensus accounting and cost tests. Wallet worker owns native signer/client network options, Python public wallet binding and their tests. Any overlapping need is reported to root rather than edited concurrently.

### Task 1: Dedicated public identity and accepted set

- [ ] Write failing identity/namespace/startup tests for explicit test flag, wrong build/config/conflicts and unchanged old fixtures.
- [ ] Add `IsMLDSA44Test()`/`IsMLDSA44Enabled()` profile helpers and `CChainParams::MLDSA44Test()` without adding a new ChainType or changing inherited TEST defaults.
- [ ] Add node helpers for enabled-profile startup/H1 validation, public output/input shape checks and exact TEST identity.
- [ ] Add distinct `valueless_mldsa44_test` RPC context with existing contract hash, public-profile hash and resource constants; old five-field demo context unchanged.
- [ ] Explicitly allow native v2/32 standard outputs only when the new profile selects it; retain other policy checks.
- [ ] Root wires mempool/ConnectBlock/reindex/assumevalid paths, source/spec pins and unit registration. Run valid/forbidden output, input, activation and reindex tests.
- [ ] Review the task diff, fix findings and commit the tested slice.

### Task 2: Verification cost and real native resource tests

- [ ] Reproduce zero v2 cost with a failing native test.
- [ ] Add a small shared header declaring 625 cost, 128/block and 25/standard transaction; charge only active native ML-DSA witness checks.
- [ ] Root adds the active flag before mempool cost computation; existing miner/block cost paths consume the same function.
- [ ] Add native unit cases for legacy-flag invariance, v2 shapes, coinbase, invalid data and no accidental generic witness activation.
- [ ] Add real-node exact-25/26 mempool and exact-128/129 block/template controls and pressure cases; do not substitute a counting-unit test for admission.
- [ ] Generate valid full-weight hostile blocks in an offline fixture namespace, measure 30 release validations and record raw CPU/wall/RSS with thresholds from the spec.
- [ ] Run normal/sanitized GCC/Clang and arm64 cases, entropy/fault/key-lifecycle controls, retaining explicit exclusions. Review and commit verified work.

### Task 3: Explicit wallet/operator/runtime profile

- [ ] Add failing native launcher and Python public-store/witness tests for explicit TEST and wrong binding; preserve regtest defaults.
- [ ] Add `--network test|regtest` to signer and client; MAIN/unknown refused. HELLO, key derivation, address and signing bytes use the selected existing enum.
- [ ] Add explicit network to `validate_manifest`, `PublicStore`, witness attachment and `NodeWallet` deployment checks; exact public RPC context and hashes required.
- [ ] Add a separate public runtime/controller; preserve offline network-none checks. Keep RPC/console local and signer under separate UID/AF_UNIX.
- [ ] Add user-selected create/unlock/recover through operator FD, with no secret in URL/logs/argv/env/IPC; test wrong password and locked-after-backup behavior.
- [ ] Add public peer-resync recovery bundles and compatible upgrade/binary rollback; test old floors, wrong network, missing/corrupt record and two distinct versions.
- [ ] Review and commit verified work.

### Task 4: Current-source qualification and release candidate

- [ ] Replace historical-image orchestration with a current-source qualification driver and actual spend/restore adversarial mode.
- [ ] Build from clean source and pinned dependencies on Research x86_64 GCC/Clang and Mac Linux arm64; record exact images, binaries and source hashes.
- [ ] Execute normal and sanitizer/native lifecycle/resource/operator tests. Fix real failures, not success gates or workloads.
- [ ] Assemble public app status/receive/send/recovery/upgrade flow on both hosts and prove full tip/UTXO agreement.
- [ ] Freeze public profile manifest/spec and candidate version digests only after qualification; retain production hold. Publish reviewable source and exact-source CI, fixing failures.

### Task 5: Actual public 24-hour soak

- [ ] Prove public ingress anonymously from a public IP route, not merely Tailscale; expose P2P only.
- [ ] Write immutable run declaration with exact candidate/version digests, workload/fault schedule, CPU/shutdown controls and 24-hour criteria.
- [ ] Run a bounded public preflight and independent shutdown probe; no preflight time counts toward soak.
- [ ] Start two independent qualified nodes/wallets and the workload. Preserve the original local app and unrelated host work.
- [ ] Monitor actual transactions, blocks, peers, resources and scheduled faults; fix failures and restart a new full-duration attempt if criteria fail.
- [ ] At >=86,400 actual seconds, verify slot/latency/phase criteria, final full UTXO agreement, recovered spend and stopped task-only public exposure.
- [ ] Write exact-source result, hashes, failures/exclusions and release-scope decision record; no human-review or production-admission claim.
