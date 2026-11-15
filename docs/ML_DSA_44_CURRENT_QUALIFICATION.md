# Current ML-DSA-44 qualification

Updated 2026-11-15 UTC. The qualified app source is F
`3a76cdd6005c1f5d948deb602c6985c1db508375`, tree
`9426d9dd4c3c2d082059b2ffc14fa912a121b1dc`. The public transition cohort uses
application baseline D `cc15838139360a0d6feccacc8707943781fdb002` and candidate F.

The experimental, valueless TEST app builds from a clean checkout and provides
wallet setup, status, receive/send, test funding/mining, lock/unlock,
backup/recovery and persistent runtime controls. Normal first installation
builds the Linux node, client and isolated signer from source, without a prepared
project container or private binary. The qualified flows exercise real
transactions, app/container recreation, older-backup recovery and another spend.

**Fresh D/F public preflight: PASS. The separate 24-hour public soak: ACTIVE,
not PASS.**

| Evidence | Observed source | Result and boundary |
| --- | --- | --- |
| Native-v2 comparator | Main-run source `72acd0f566ece43723e8116ff70209e97f354746`; [run 43024791797](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43024791797) | All 13 checks and 70 selected ACVP cases pass with the pinned three implementations. The ASan/UBSan differential campaign records 1,577,151 executions, 83 imported retained seeds and zero crashes over 1,801.211 fuzzer seconds. |
| Portable-wrapper CT | Main-run source `0b6474fd90023e3c13ccdbca0a08d264833e9401`; [run 39604807430](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/39604807430) | Calibrated Linux x86_64 GCC 13.4.0 and Clang 20.1.8 lanes pass with pinned patched Valgrind 3.26.0/Nix 2.24.9. This covers the stated isolated portable-wrapper signing/health-check scope. |
| Assembled app/native qualification | F source above | Linux x86_64 and native Linux aarch64, each with GCC and Clang: all nine native gates per profile and all four private-transport public-profile HTTP flows pass. |
| F continuous checks | Same F source; [manual assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43651886514) and its source/PR checks | All nine recorded runs and seventeen jobs pass, including both compiler lanes, native qualification, controls, lint and inventory. |

The [portable evidence index](reviews/evidence/ml-dsa-44-current-qualification/F-3a76cdd6/SOURCE.json)
preserves these distinct source, compiler, image and workload identities.
Native-v2 is commit `834a90d5e846ffa1e1611bd24e160bb2e9b86d35`; the comparator's
frozen review baseline is `f6b406ecb59bb9d7c9502457daa3be4a1deb7019`. The
source-continuity record preserves the older CT audit identity and its later
readiness-prose delta.

The CT observations do not qualify the complete F app, its GCC12/Clang16 or ARM
binaries, general key generation, secret erasure, or physical/cache/speculative
leakage. Comparator sanitizer coverage excludes the prebuilt OpenSSL provider
and libcrux Rust implementation bodies. Full scopes, exclusions, corpus
inventories, binary hashes and cleanup records remain in the evidence packet.

The sealed admission JSON's `PENDING_V2_REPRODUCTION` and
`PENDING_V2_BINARY_REPRODUCTION` entries describe an earlier checkpoint. The dated
observations above supersede a claim that portable v2 had not been reproduced,
within their stated scopes. The audited JSON bytes remain unchanged. Production
backend `NONE` and `RELEASE_HOLD` remain in force. Independent human review is
NOT PERFORMED; the owner's direction permits continued engineering and accurately
described public experimental testing without paid review or an outside response.

## Install and exercise the tested source

Install Git, Python 3.11+ and Docker/BuildKit with Linux containers and sufficient
build storage, then run:

```sh
git clone https://github.com/scottdhughes/quantum-proof-bitcoin.git
cd quantum-proof-bitcoin
git switch --detach 3a76cdd6005c1f5d948deb602c6985c1db508375
./contrib/ml-dsa-console/launch-public.command
```

The first build downloads pinned/checksummed dependencies, then compiles and
tests inside Linux. Follow the [public wallet guide](../contrib/ml-dsa-console/PUBLIC_TEST.md)
for explicit empty-chain initialization or connection to an existing TEST peer,
operator-selected password setup, send/receive and recovery. Public ingress is
configured separately; launching the app does not expose RPC, console or signer
IPC.

To exercise the assembled clean-source test in a fresh namespace:

```sh
python3 contrib/ml-dsa-console/run_assembled_ci.py --compiler gcc --no-cache \
  --container pqbtc-ci-reader-gcc --port 8846 \
  --output-dir /absolute/path/outside-checkout/new-gcc-evidence
```

Use a new name/output directory for Clang. The [console quickstart](../contrib/ml-dsa-console/README.md),
[native qualification guide](../contrib/ml-dsa-qualification/README.md) and
[public soak procedure](../contrib/ml-dsa-qualification/PUBLIC_SOAK.md) describe
the separate workflows and their limits.

## Public preflight and active soak

Fresh attempt 03 returned `PREFLIGHT_PASS` after 900.009 monotonic seconds and
900.006 wall seconds. It completed all seven declared fault phases: crash,
partition/rejoin, hostile input, old-backup missing-record recovery, reindex,
upgrade and rollback. It recorded 22 confirmed payments, twelve successful
normal slots and three misses only during declared upgrade/rollback faults.
Normal-slot settlement p95 was 13.1855 seconds. Final missing-record old-backup
recovery, another confirmed spend and owned cleanup all passed.

The separate fresh 24-hour soak began at **2026-11-15 01:13:20.645543 UTC**.
Its earliest possible elapsed-time completion is **2026-11-16 01:13:20.645543
UTC**, subject to both clocks, the declared workload/fault criteria, final
cross-node state checks and cleanup. Its current status is **ACTIVE**. A start
time or successful preflight is not a completed soak result.

| Public operation | Current result | Evidence boundary |
| --- | --- | --- |
| Fresh D/F preflight, attempt 03 | **PREFLIGHT_PASS** | Complete 900-second public-route run, all seven fault phases, final recovery/spend and cleanup. |
| Separate 24-hour public soak, fresh attempt 01 | **ACTIVE — not PASS** | Requires at least 86,400 actual UTC and monotonic seconds plus the declared acceptance criteria and final report. |

Earlier native-only snapshots retain their recorded pending public-run fields;
the separately dated preflight section supplies the completed preflight result.
Interrupted attempts contribute no elapsed time to the active soak. Update its
status only from the completed, source-bound final report. All coins remain
disposable TEST coins; production activation and an explicit release decision
are separate.
