# Current ML-DSA-44 qualification

Updated 2026-11-16 UTC. The latest completed four-profile qualification is G
`4339d436cdcfce9724476b9786994d347f1a4b06`, tree
`b9923bede37da41119ac69a39d57f16a8a89b3eb`. Its public transition cohort uses
application baseline F `3a76cdd6005c1f5d948deb602c6985c1db508375` and candidate G.
Connection recovery source H is
`52f26f31e2d8fcf52459f9cb2e9159564395f74a`, tree
`d2e07ad8db149f6d3eac1cb15379d97e1484e2e6`. Its host checks pass; exact-source
native/app qualification remains pending. The G results below do not qualify H
or this later evidence/documentation revision.

The experimental, valueless TEST app builds from a clean checkout and provides
wallet setup, status, receive/send, test funding/mining, lock/unlock,
backup/recovery and persistent runtime controls. Normal first installation
builds the Linux node, client and isolated signer from source, without a prepared
project container or private binary. The qualified flows exercise real
transactions, app/container recreation, older-backup recovery and another spend.

**Fresh F/G public preflight: PASS. The separate G 24-hour public soak: FAIL
after approximately 16 hours 46 minutes. The earlier F attempt also failed.
A fresh complete preflight and separate 24-hour run are required.**

| Evidence | Observed source | Result and boundary |
| --- | --- | --- |
| Native-v2 comparator | Main-run source `72acd0f566ece43723e8116ff70209e97f354746`; [run 43024791797](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43024791797) | All 13 checks and 70 selected ACVP cases pass with the pinned three implementations. The ASan/UBSan differential campaign records 1,577,151 executions, 83 imported retained seeds and zero crashes over 1,801.211 fuzzer seconds. |
| Portable-wrapper CT | Main-run source `0b6474fd90023e3c13ccdbca0a08d264833e9401`; [run 39604807430](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/39604807430) | Calibrated Linux x86_64 GCC 13.4.0 and Clang 20.1.8 lanes pass with pinned patched Valgrind 3.26.0/Nix 2.24.9. This covers the stated isolated portable-wrapper signing/health-check scope. |
| Assembled app/native qualification | F source above | Linux x86_64 and native Linux aarch64, each with GCC and Clang: all nine native gates per profile and all four private-transport public-profile HTTP flows pass. |
| F continuous checks | Same F source; [manual assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43651886514) and its source/PR checks | All nine recorded runs and seventeen jobs pass, including both compiler lanes, native qualification, controls, lint and inventory. |
| G assembled app/native qualification | G source above; [assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43770171273) and native aarch64 Docker runs | All nine native gates and all four private-transport public-profile HTTP wallet/recovery flows pass on Linux x86_64/aarch64 with GCC/Clang. |
| G continuous checks | Same G source, including [Promotion Matrix](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43770187266) | All 14 recorded runs and 52 jobs pass on attempt 1, including all 22 platform/fuzz matrix jobs. |

The [sealed G CI snapshot](reviews/evidence/ml-dsa-44-current-qualification/G-4339d436-ci/README.md)
preserves exact run, attempt, source and job attribution separately from native
execution evidence.

The [portable evidence index](reviews/evidence/ml-dsa-44-current-qualification/F-3a76cdd6/SOURCE.json)
preserves these distinct source, compiler, image and workload identities.
The [G native/preflight index](reviews/evidence/ml-dsa-44-current-qualification/G-4339d436/SOURCE.json)
adds four G native profiles and completed public preflight 02. Its
`public_soak_24h: NOT_STARTED` field is explicitly the historical staging
snapshot from 2026-11-15 23:53:32 UTC, before the separate run started.
The [G failed-attempt index](reviews/evidence/ml-dsa-44-public-soak/g-4339d436-attempt02/SOURCE.json)
records that run's subsequent terminal failure; the snapshot is not current
soak status. Earlier evidence bytes remain unchanged.
Native-v2 is commit `834a90d5e846ffa1e1611bd24e160bb2e9b86d35`; the comparator's
frozen review baseline is `f6b406ecb59bb9d7c9502457daa3be4a1deb7019`. The
source-continuity record preserves the older CT audit identity and its later
readiness-prose delta.

The CT observations do not qualify the complete F/G app, its GCC12/Clang16 or ARM
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
git switch --detach 4339d436cdcfce9724476b9786994d347f1a4b06
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

## Earlier D/F public preflight and failed soak

Fresh attempt 03 returned `PREFLIGHT_PASS` after 900.009 monotonic seconds and
900.006 wall seconds. It completed all seven declared fault phases: crash,
partition/rejoin, hostile input, old-backup missing-record recovery, reindex,
upgrade and rollback. It recorded 22 confirmed payments, twelve successful
normal slots and three misses only during declared upgrade/rollback faults.
Normal-slot settlement p95 was 13.1855 seconds. Final missing-record old-backup
recovery, another confirmed spend and owned cleanup all passed.

The separate fresh 24-hour soak began at **2026-11-15 01:13:20.645543 UTC**
and failed at **2026-11-15 22:14:20.798198 UTC**. It completed all seven fault
phases and recorded 1,264 confirmed payments, with 1,255 successful normal slots
and five misses during declared faults. The next payment exhausted its shared
60-second settlement deadline: recipient mempool observation returned only
0.34 seconds before that deadline, leaving insufficient time for mining and
confirmation checks. The final report is `FAIL`; independent owned cleanup
confirmed both backend containers stopped.

The [failed-attempt evidence index](reviews/evidence/ml-dsa-44-public-soak/F-3a76cdd6-attempt01/SOURCE.json)
includes the original final report/declaration, checksummed compressed event
chain, and the [measured failure timeline](reviews/evidence/ml-dsa-44-public-soak/F-3a76cdd6-attempt01/failure-timeline.md).

The event timeline also exposed growing controller overhead: each transaction
poll rebuilt full wallet status, including a scan and over 1,100 individual
owned-output RPCs, and transferred/retained two complete public manifests.
Research poll median grew from approximately 0.25 seconds in the first hour
to 1.61 seconds in the last. This establishes avoidable poll cost; it does not
attribute the entire roughly 55-second relay-observation delay to that cost.
G removed that avoidable polling cost while preserving the 60-second settlement
gate and specific-transaction checks. Its subsequent qualification and public
results are recorded below. This F attempt contributes no elapsed credit.

| Public operation | Current result | Evidence boundary |
| --- | --- | --- |
| Fresh D/F preflight, attempt 03 | **PREFLIGHT_PASS** | Complete 900-second public-route run, all seven fault phases, final recovery/spend and cleanup. |
| Separate 24-hour public soak, fresh attempt 01 | **FAIL** | Stopped at approximately 21 hours on a payment response deadline; all seven fault phases passed and owned cleanup passed. No 24-hour PASS or final post-soak recovery is claimed. |

## G public preflight and failed soak

Fresh F/G preflight 02 passed over 900.155 event monotonic seconds and 900.161
wall seconds. All seven fault phases passed, with 22 confirmed payments,
twelve successful normal slots and three misses during declared
upgrade/rollback faults. Normal settlement p95 was 14.5671 seconds. Final
missing-record old-backup recovery, another confirmed spend and owned cleanup
passed. This is preflight evidence, with no time credited toward the separate
86,400-second soak.

The separate G soak began at **2026-11-16 00:00:56.248278 UTC** and failed at
**2026-11-16 16:46:56.470020 UTC**. It recorded 1,010 confirmed payments,
1,002 successful normal slots, three declared-fault misses and six completed
fault phases. The upgrade phase passed; rollback and final post-soak recovery
were not reached. Both nodes had zero peers during the final failed payment.
The recipient never observed that transaction in its mempool before the
unchanged 60-second payment deadline. Owned cleanup verified both backends
stopped. The final result is **FAIL**, with zero elapsed credit for a later run.

The [G failure packet](reviews/evidence/ml-dsa-44-public-soak/g-4339d436-attempt02/README.md)
preserves the final report, declaration, all 59,862 hash-chained events,
measured timeline and the available public bridge logs. Run its standard-library
`verify.py` from that directory to verify the packet without a node or wallet.
Transaction polls remained fast: the final 481 negative lookups had a median
of approximately 14.65 milliseconds. The earlier growing wallet-poll cost was
fixed, while loss of the sole connection exposed missing ongoing recovery.

A TLS 1.3 control-record forwarding stall was independently reproduced on
macOS and Linux: a readable TLS file descriptor could contain only control
records, causing a blocking receive to stall opposite-direction application
traffic. The G live log records peer closure without timestamps or side/error
metadata, so it does not establish that defect as the live failure's cause.
The repair handles nonblocking TLS reads, preserves bounded writes, maintains
declared peers across restart, waits for completed ping/pong readiness and can
reannounce the same known transaction. It does not repeat address reservation,
signing or payment creation, reset the settlement clock, or replace the
recipient-mempool and specific-block confirmation checks.

These repairs require their own exact-source native/app qualification, a fresh
900-second public preflight and a fresh full 86,400-second public soak. Neither
failed attempt supplies partial elapsed credit.

## Recovery source H and its evidence successor

H adds persistent, bounded peer settings and transaction-peer readiness based
on a completed native ping/pong exchange. A deliberately paused network stays
paused through native restart, reindex and container replacement. Interrupted
settings are preserved and conservatively reconciled to networking off before
the node starts. The local app displays that state and provides authenticated
**Pause networking** and **Resume networking** controls.

H passes 129 host console tests, 203 related host tests with twelve Linux-only
skips, 25 admission/inventory tests, repository-selected Ruff rules, inventory,
JavaScript syntax and whitespace checks. An initial host run used an older
Python without the required process-ownership primitives; the completed run
uses the host's Python 3.15 for those tests, without an implementation fallback.
Host checks are not native platform or public-soak qualification.

The next cohort uses H as the corrected baseline and a documentation/evidence
successor with the same runtime control code. Both versions must have their own
matching native receipts before use. Their source, image and node binary
identities differ; the upgrade/rollback experiment exercises actual image/node
replacement on retained data. It does not claim a new consensus or wallet-format
transition from an evidence-only change. The existing 60-second settlement and
actual 900/86,400-second elapsed-time requirements remain unchanged.

| Next gate | Status at this documentation checkpoint |
| --- | --- |
| H baseline native GCC images and private app flows on both host architectures | Pending exact-source execution |
| Evidence successor native GCC/Clang profiles on both architectures and CI | Pending exact-source execution |
| Fresh public preflight | Not started |
| Separate fresh 24-hour public soak and final recovery | Not started |

Earlier native-only snapshots retain their recorded pending public-run fields;
the separately dated preflight section supplies the completed preflight result.
Interrupted attempts contribute no elapsed time to a later soak. Update its
status only from the completed, source-bound final report. All coins remain
disposable TEST coins; production activation and an explicit release decision
are separate.
