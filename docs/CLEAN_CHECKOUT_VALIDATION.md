# Clean-checkout installer and assembled-system CI — 2026-11-09

The fresh installation path now builds the complete local ML-DSA app from source.
It requires Git, Python 3.11+ and Docker/BuildKit, with no prepared project image,
container, binary or private host path. See the
[quickstart](../contrib/ml-dsa-console/README.md).

```sh
./contrib/ml-dsa-console/launch.command
```

The first install builds inside Linux; later launches resume the exact saved
runtime. The existing default wallet continues using its prior qualified runtime.

## Clean source and isolation

The implementation was tested from a separate clean Git clone containing the
assembled uncommitted changes, at test-fixture commit
`a8c6b249b79b6d6e7f42c51edea1e13928594a33`, tree
`0fb27b0c1518fe61f1c16376c188d7386fe1f77a`. The fixture contained 3,448 source
files and **zero compiled native inputs**. Creating that fixture did not commit
or change the workspace's Git history. All ten installer/runtime/workflow
implementation files matched the tested fixture at validation time.

Both compiler builds disabled Docker's build cache and pulled the checksum-pinned
public Debian base. Public operating-system layers may be content-addressed and
cached; no prior project binary or prepared project container/image seeded either
build. Dependencies were downloaded and verified before native compilation/tests
ran with build networking disabled. Runtime containers have no network access,
no host bind mounts, read-only rootfs, cap-drop ALL, separate UIDs1000/1001,
4 CPU/4 GiB bounds, a named data volume and ephemeral signer IPC.

Source export preserves the exact Git HEAD/tree using minimal generated Git
objects. It does not copy the user's Git config, remotes, hooks or credentials.
The frozen export supplies both source and build recipes; concurrent working-tree
recipe edits cannot enter the claimed clean build.

## Actual results

| Run | Result |
| --- | --- |
| One-click first install, GCC12, empty state/volume | PASS; created a new zero-balance wallet, then passed full funding/spend/older-backup recovery/spend flow |
| GCC assembled-system runner, fresh second namespace | PASS; host/container recreation, forced container loss, counter preservation, later spend and matching two-node UTXO state |
| Clang16 assembled-system runner, uncached build and fresh namespace | PASS; same full flow, recreation, recovery and post-recreation spend |
| Independent second uncached GCC12 build | PASS; identical hashes for all five executables and the two recorded source/spec artifacts |
| Original default wallet | Same wallet ID and 1,994,000-sat balance, still running; its volume was not used by the clean tests |

The two assembled-system runs ended at height105 with **1,997,000 spendable
sats** in their distinct disposable wallets, after three 1,000-sat fees each.
Within each run, both nodes' chain tips and full UTXO hashes agreed. The runner
reports PASS only after its owned cleanup succeeds. Successful CI namespaces
were removed; failed test evidence was retained for diagnosis.

Each compiler also passed native adapter/signer tests, the actual validation-only
node functional test, and **18 ML-DSA node unit cases / 257 assertions**. The other
28 node unit cases were outside this selected suite. Host verification passed
**125 console tests** plus **25 protocol/symbol checks**. Ten Linux-only public
wallet persistence tests were skipped on macOS and separately passed inside the
fresh Linux image. Selected repository Ruff rules, Python compilation, shell/JS
syntax, local documentation links and `git diff --check` passed.

The final local builds ran on **Linux ARM64**. The new GitHub workflow targets
`ubuntu-24.04` with GCC/Clang matrix jobs. At this local checkpoint those
GitHub-hosted x86_64 jobs had not run. Subsequent publication and exact-commit
CI results are recorded in [GitHub CI validation](GITHUB_CI_VALIDATION.md).

## CI entrypoint

The [workflow](../.github/workflows/ml-dsa-44-assembled-system.yml) uses pinned
checkout/artifact actions, read-only permissions, exact-head checkout, no cached
project build, and retained native/source/whole-flow evidence. It invokes the
same locally exercised runner:

```sh
python3 contrib/ml-dsa-console/run_assembled_ci.py --compiler gcc --no-cache \
  --container pqbtc-ci-example-gcc --port 8845 \
  --output-dir /absolute/path/outside-checkout/new-evidence
```

Repeat with `--compiler clang` and a new name/output path. An explicit descriptor
can reuse the freshly built artifact within the same test campaign; the runner
still requires matching clean source HEAD/tree/compiler and native test receipts.
It refuses existing test namespaces and never restarts the shared Docker engine.

Workflow YAML and the compiler matrix were parsed locally. A semantic regression
checks the supported contexts for job-level environment entries against the
[GitHub context availability contract](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability).
This corrected an unsupported job-level `runner.temp` expression. `actionlint`
was not available; no unperformed validation is claimed.

## Reproducibility and provenance

Each image's immutable manifest records source HEAD/tree, architecture, compiler
and tools, installed package versions, OpenSSL archive digest, seven native/source
hashes, and hash-bound native test logs. The runtime checks manifest/image/volume
identity before opening custody. Native worker code is staged from that image's
clean source, not a later host edit.

Two independent uncached GCC builds matched all seven artifact hashes, including
`pqbtcd`, `pqbtc-cli`, `pqbtc-mldsa-client`, `test_pqbtc` and `pilot-signer`.
Their OCI image IDs differ because image/test/provenance metadata is not asserted
byte-identical. Package versions are recorded, rather than permanently pinned
to an operating-system snapshot; future package updates require new receipts.

Cold testing found and fixed a GNU ARM64 ELF-section parsing difference, default
Docker volume copy-up, inherited image labels, missing-host-session custody
handling and a race involving live build recipes. Strict export, manifest,
empty-volume and custody checks remain enforced.

## Evidence and source package

All evidence is under
`/Users/scott/quantum-proof-bitcoin-evidence/20261109-clean-checkout/`:

- `final-source-2.json`, `implementation-match.json`: clean source identity.
- `installer-gcc2.log`, `installer-gcc2-flow.json`: actual first-install path.
- `ci-gcc2/report.json`, `ci-clang2/report.json`: complete assembled results.
- Their `native-evidence.tar` files: hash-verified native receipts and logs.
- `repeat-gcc-build.log`, `repeat-gcc-descriptor.json`, `reproducibility.json`.
- `linux-public-wallet-tests.log`, `clean-source-ready.png`.
- `pqbtc-clean-source-a8c6b249.tar.gz`: source-only package with minimal Git
  metadata; no native binaries or original user Git configuration. SHA256:
  `5c83dd38645f39f8e1362de697b052eb27c95c25a1e4f2f5b4fd32f2ffae43a8`.

The source package was locally assembled and usable for testing at this
checkpoint; it had not been uploaded or published. Workspace changes were still
uncommitted. The owner's subsequent authorization to commit, push and qualify
the GitHub branch is recorded in [GitHub CI validation](GITHUB_CI_VALIDATION.md).

The app remains a disposable, valueless local regtest with a public fixture
phrase. User-owned secret setup and a multi-machine network are separate roadmap
milestones. This work does not change production admission or claim production
cryptographic qualification.
