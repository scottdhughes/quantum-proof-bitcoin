# Clean Checkout Installer and Assembled-System CI Implementation Plan

> **For agentic workers:** Use subagent-driven development or executing-plans. User explicitly requested implementation and from-scratch testing. Preserve concurrent edits and the existing wallet; do not commit or publish the workspace.

**Goal:** A clean checkout builds and launches the complete local ML-DSA app without any prepared project container, image or binary; CI exercises the same path.

**Architecture:** Export only committed source and a minimal credential-free Git object database into an isolated Docker build context. Build the native node, signer and tests from pinned source/dependencies inside Linux. Publish a source/binary manifest in the new image, initialize a fresh named volume from that image, and validate the manifest at every launch. Preserve legacy runtime handling for the existing wallet.

**Tech Stack:** Python standard library, Docker/BuildKit, pinned Debian bookworm-slim image, GCC12 or Clang16, pinned OpenSSL3.6.5, existing native C/C++ integration and console.

## Global constraints

- No existing project images, containers, native artifacts or default wallet data may seed the clean-install test.
- Runtime remains network none, rootfs read-only, cap-drop ALL with no additions, no-new-privileges, 4 CPU/4 GiB, separate UIDs1000/1001, one data volume and ephemeral signer IPC.
- All native prototype execution/build tests stay inside Linux; host code only exports source, orchestrates Docker and serves the browser.
- Do not read/copy `.env`, credentials, SSH keys or original Git config. Generated Git metadata contains public source objects and exact HEAD only.
- Preserve native source/spec bytes and legacy admission behavior. Build manifest identity is provenance, not production security approval.
- GCC and Clang use the same installation/test entrypoint. Record source tree, architecture, compiler/dependency versions, binary hashes and exact image identity.
- Current working tree changes are uncommitted. Test a separate clean Git fixture containing the assembled source; do not modify project history or claim a GitHub run occurred.

## Review focus

- A dirty or incomplete checkout cannot be reported as a clean source build.
- Corrupt manifests, wrong image IDs, foreign volume IDs, and source/binary mismatches fail before native custody starts.
- A missing existing wallet volume cannot trigger creation of a replacement wallet.
- First install must succeed with no prepared seed; later launches must resume instead of rebuild or replace state.
- CI must validate actual signing/block admission and old-backup recovery, not only Python fixtures or image construction.

## Task 1 — Source builder (source_builder)

Own `source_build.py`, `container/Dockerfile`, `container/build_native.sh`, `test_ml_dsa_console_source_build.py`.

- [x] RED tests for clean source export, unsafe/untracked inputs, minimal Git identity, manifest hashing and compiler argument bounds.
- [x] Implement `build_image(repo,compiler='gcc',image_tag=None,no_cache=False,progress=print)->descriptor` and CLI.
- [x] Build pinned dependencies and explicit native targets; run native adapter/signer/node tests; package immutable seed and source manifest in image.
- [x] Verify focused tests; root performs actual uncached builds.

## Task 2 — Fresh source runtime (source_runtime)

Own `source_runtime.py`, `controller.py`, `app.py`, corresponding source-runtime tests and necessary legacy test updates.

- [x] RED tests for new runtime descriptor/volume validation, cold bootstrap and wrong/missing existing storage.
- [x] Initialize fresh volume from the new image's immutable seed; retain existing legacy runtime resume path.
- [x] Controller validates exact manifest, image, Git source identity, native hashes and runtime isolation; backups bind to actual build identity.
- [x] Launcher supports compiler selection and an explicitly supplied build descriptor for CI; default fresh install builds source.
- [x] Verify focused and legacy suites, then root tests real install/recovery.

## Task 3 — Assembled CI (assembled_ci)

Own `run_assembled_ci.py`, `.github/workflows/ml-dsa-44-assembled-system.yml`, runner tests.

- [x] RED tests for source cleanliness/ownership, lifecycle failure reporting and isolated namespace guard.
- [x] Build from source or validate supplied descriptor, launch on a private namespace/port, and run full HTTP spend/old-backup restore/spend tests.
- [x] Recreate/force-stop only its own container, relaunch and assert wallet/counter/chain agreement; never restart the shared Docker engine in CI.
- [x] Configure exact-HEAD GCC/Clang PR CI with pinned checkout/artifact actions and retained evidence.
- [x] Verify runner tests; root runs the same jobs locally against new images.

## Task 4 — Clean-room execution and docs (root)

- [x] Construct a separate clean test snapshot of the complete uncommitted implementation, without project history mutation or local binaries.
- [x] Build native artifacts with an empty build cache for both supported compiler lanes; record real evidence and failures.
- [x] Run installer and assembled-system runner against new namespace, empty state and volume, including cold resume, container recreation, recovery and a later spend.
- [x] Repeat a clean build to measure the reproducibility actually achieved; distinguish byte identity from recorded input/toolchain provenance.
- [x] Run all focused tests, selected repository lint, shell/JS/workflow validation and independent implementation review.
- [x] Document clone/build/launch instructions, resource requirements, bootstrap downloads, known scope and publishing status. Leave the existing app/wallet intact.
