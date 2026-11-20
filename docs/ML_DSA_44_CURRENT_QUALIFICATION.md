# Current ML-DSA-44 qualification

Updated 2026-11-17 UTC. **LAST_COMPLETED: L**
`7223772e76d2d0a0bb7fd1d35e0e16fba61918fd`, tree
`33b36275b1da7f7fbc27fae00d519206b0f7c16f`. All four native Linux architecture and
compiler profiles passed nine native gates and the 17-event private HTTP app
flow per profile. L's source-bound CI snapshot has 14 successful runs and 52
successful latest logical jobs, including all 22 promotion jobs on attempt 1.

The separate full L public attempt **FAILED** after about 3 hours 23 minutes;
no 86,400-second clock completed and no partial time is credited. There is no
current public clock. Registered-peer recovery code is now under development
and native-CI review; completed L evidence does not automatically qualify that
later code or the moving branch tip.

The H/L public transition cohort uses connection-recovery baseline H
`52f26f31e2d8fcf52459f9cb2e9159564395f74a`, tree
`d2e07ad8db149f6d3eac1cb15379d97e1484e2e6`. H has three completed native
profiles; K and L each have four. Their matching private HTTP receipts retain
their own source identities. Historical K
`18430ea2cfcac66cca0e8612605db47a5c0e935b`, tree
`d397b324f83b82017722073c3c53688e0765fb30`, is an evidence/documentation successor
with the same 15 selected H runtime, test and UI files. Its separate full run
was deliberately superseded after a public-launcher availability defect was
found. L qualified that launcher correction, including actual Docker Desktop
recovery; the current registered-peer follow-up needs its own qualification.

Historical transition sources remain F
`3a76cdd6005c1f5d948deb602c6985c1db508375` and G
`4339d436cdcfce9724476b9786994d347f1a4b06`, tree
`b9923bede37da41119ac69a39d57f16a8a89b3eb`.

The experimental, valueless TEST app builds from a clean checkout and provides
wallet setup, status, receive/send, test funding/mining, lock/unlock,
backup/recovery and persistent runtime controls. Normal first installation
builds the Linux node, client and isolated signer from source, without a prepared
project container or private binary. The qualified flows exercise real
transactions, app/container recreation, older-backup recovery and another spend.

**L public preflight 01: FAIL, with its Research-upgrade cause still unknown.
Fresh preflight 02: PASS over actual 900-second clocks, all seven phases and
22 confirmed payments. The separate full L run: FAIL, with owned cleanup PASS
and zero 24-hour credit. The earlier F/G failures and K's controlled supersession
remain preserved. A qualified repaired source, fresh preflight and separate
complete 24-hour run remain required.**

| Evidence | Observed source | Result and boundary |
| --- | --- | --- |
| Native-v2 comparator | Main-run source `72acd0f566ece43723e8116ff70209e97f354746`; [run 43024791797](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43024791797) | All 13 checks and 70 selected ACVP cases pass with the pinned three implementations. The ASan/UBSan differential campaign records 1,577,151 executions, 83 imported retained seeds and zero crashes over 1,801.211 fuzzer seconds. |
| Portable-wrapper CT | Main-run source `0b6474fd90023e3c13ccdbca0a08d264833e9401`; [run 39604807430](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/39604807430) | Calibrated Linux x86_64 GCC 13.4.0 and Clang 20.1.8 lanes pass with pinned patched Valgrind 3.26.0/Nix 2.24.9. This covers the stated isolated portable-wrapper signing/health-check scope. |
| Assembled app/native qualification | F source above | Linux x86_64 and native Linux aarch64, each with GCC and Clang: all nine native gates per profile and all four private-transport public-profile HTTP flows pass. |
| F continuous checks | Same F source; [manual assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43651886514) and its source/PR checks | All nine recorded runs and seventeen jobs pass, including both compiler lanes, native qualification, controls, lint and inventory. |
| G assembled app/native qualification | G source above; [assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43770171273) and native aarch64 Docker runs | All nine native gates and all four private-transport public-profile HTTP wallet/recovery flows pass on Linux x86_64/aarch64 with GCC/Clang. |
| G continuous checks | Same G source, including [Promotion Matrix](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43770187266) | All 14 recorded runs and 52 jobs pass on attempt 1, including all 22 platform/fuzz matrix jobs. |
| H baseline qualification | H source above; [assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43923679742) and native aarch64 Docker run | Linux aarch64 GCC and Linux x86_64 GCC/Clang: all nine native gates and the extended 17-event private HTTP app flow per executed profile. H ARM Clang was not qualified. |
| K assembled app/native qualification | K source above; [assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43931134439) and native aarch64 Docker runs | All four Linux x86_64/aarch64 GCC/Clang profiles pass nine native gates and the extended 17-event private HTTP app flow. Each includes 30 distinct full-weight/128-verification blocks and the resource/consensus controls. |
| K continuous checks | Same K source, including [Promotion Matrix](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43931134510) | All 13 runs and 51 latest logical jobs pass, including 22 matrix jobs. Each initially unassigned macOS job passed one actual capacity retry; the advisory job passed one retry after its anonymous API quota reset. Original attempts remain recorded. |
| L assembled app/native qualification | L source above; [assembled/export run](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43970911876) and native aarch64 Docker runs | All four Linux x86_64/aarch64 GCC/Clang profiles pass nine native gates and the 17-event private HTTP app flow. Each includes 30 full-weight/128-verification blocks and bounded resource/consensus controls. |
| L continuous checks | Same L source, including [Promotion Matrix](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/43970927737) | All 14 runs and 52 latest logical jobs pass. All 22 promotion/platform/fuzz jobs passed on attempt 1. Two advisory attempts hit anonymous API quota; exactly two scoped retries were retained, with attempt 3 passing without changed inputs or credentials. |

The new selected packets separate completed evidence from outstanding work:

| Packet | Recorded result and limit |
| --- | --- |
| [L native and CI](reviews/evidence/ml-dsa-44-current-qualification/l-7223772e-native-ci/readme.md) | Four native profiles and 14-run/52-job CI snapshot; private HTTP flows, no public-clock credit. |
| [L public preflights](reviews/evidence/ml-dsa-44-current-qualification/l-7223772e-public-preflights/README.md) | Original preflight 01 FAIL and fresh preflight 02 PASS; the later pass does not prove the earlier failure fixed. |
| [L actual Desktop recovery](reviews/evidence/ml-dsa-44-current-qualification/l-7223772e-desktop-recovery/README.md) | Real Docker Desktop restart, stopped-daemon one-click relaunch, cold host-app resume, old-backup recovery and a new confirmed spend PASS; no operating-system reboot. |
| [H large-wallet recovery](reviews/evidence/ml-dsa-44-current-qualification/h-large-wallet-recovery/README.md) | Native recovery of 1,450 retained public keys, old-backup restoration and a new confirmed spend PASS; compressed preparation, no full-day workload claim. |
| [L failed full soak](reviews/evidence/ml-dsa-44-current-qualification/l-7223772e-failed-soak/README.md) | Original FAIL and all 24,085 events preserved; 205 confirmed payments, 202 completed normal successes, one completed phase, no full-clock completion. |
| [L/H relay diagnostics](reviews/evidence/ml-dsa-44-current-qualification/l-h-relay-diagnostics/README.md) | Controlled private-v1 announcement loss with a separate passing reconnect control; read-only sender extraction and offline native H acceptance. The live public failure's cause remains unknown. |

Each packet retains its original source/custody manifest, checksum seal and
offline verifier. All six selected packets are distributed as
deterministic `packet.tar.gz` archives with external checksums and member indexes;
their linked wrapper READMEs give hash-first, mode-preserving fresh-temp
extraction and offline verification commands. This preserves frozen source and
patch evidence without collecting it as live CI code or changing lint rules.
Original staging notes
remain unchanged and describe their creation time; inclusion here does not
relabel historical outcomes or expand their scopes. Raw datasets, wallets,
credentials, native binary/image archives and omitted inventory payloads are not
claimed local custody members.

The [H/K native and completed preflight packet](reviews/evidence/ml-dsa-44-current-qualification/h-k-native-preflight-20261116/readme.md)
contains selected original reports, their exact descriptor bindings, a complete
2,305-event preflight chain and offline positive/negative verification. Omitted
native inventory payloads are explicitly external custody references. The
[K CI packet](reviews/evidence/ml-dsa-44-current-qualification/k-18430ea2-ci/readme.md)
preserves the separate 13-run/51-job snapshot and its retry history.

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

The CT observations do not qualify the complete F/G/H/K/L app or current recovery
follow-up, their GCC12/Clang16 or ARM
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

## Install and exercise the public candidate

Install Git, Python 3.11+ and Docker/BuildKit with Linux containers and sufficient
build storage, then run:

```sh
git clone https://github.com/scottdhughes/quantum-proof-bitcoin.git
cd quantum-proof-bitcoin
git switch codex/mldsa-runpod-soak-20261114
git rev-parse HEAD
git status --short
./contrib/ml-dsa-console/launch-public.command
```

Record the checkout's exact commit before testing. This development branch can
contain the registered-peer follow-up before its native/app, CI and public
qualification completes. The completed results above apply to L's exact commit,
not every later branch revision or `main`. To replay that completed checkpoint
from a fresh clone, select `git switch --detach 7223772e76d2d0a0bb7fd1d35e0e16fba61918fd`
before launching. This qualification record does not claim a fresh-main install
of the unfinished follow-up.

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

H/K subsequently qualified these repairs and completed the fresh preflight
recorded below. A full 86,400-second public soak remains outstanding. Neither
failed attempt supplies partial elapsed credit.

## Recovery sources H/K and the launcher follow-up

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

The completed preflight uses H as the corrected baseline and K as its
documentation/evidence successor with the same runtime control code. Both
versions have their own matching native receipts. Their source, image and node binary
identities differ; the upgrade/rollback experiment exercises actual image/node
replacement on retained data. It does not claim a new consensus or wallet-format
transition from an evidence-only change. The existing 60-second settlement and
actual 900/86,400-second elapsed-time requirements remain unchanged.

The H/K preflight passed over 900.075852 event monotonic seconds and 900.081071
wall seconds. All seven faults, 22 unique confirmed payments, final old-record
recovery followed by another spend, chain/UTXO agreement and owned cleanup
passed. Twelve normal slots succeeded; three misses were confined to declared
upgrade/rollback windows. The final public recovery retained the independent
journal; the private HTTP flow separately tests both records missing.

The separate K soak started at **2026-11-16 19:55:36.167124 UTC**. At
**2026-11-16 22:18:34.166921 UTC**, the operator requested a controlled SIGINT
to supersede this source. Static inspection found that a surviving public HTTP
console could be reopened before Docker Desktop readiness, leaving the app
unusable when Desktop was stopped or still restarting. This availability
defect was outside the observed payment/crash workload; no network-failure
cause is inferred. The raw terminal result is **FAIL/KeyboardInterrupt**, with
owned cleanup successful, and is not relabelled as a completed soak.
The [controlled-supersession packet](reviews/evidence/ml-dsa-44-public-soak/k-18430ea2-superseded01/readme.md)
preserves all 16,164 events, 143 successful normal slots, 146 unique payments,
the completed crash phase and the identity-verified stop request. Its offline
verifier checks the unmodified raw outcome, cleanup and zero elapsed credit.

The launcher follow-up became L: it moves Docker readiness before the
existing-console fast path and adds a stopped-daemon/live-console regression.
L completed the native/app, CI, actual Desktop and fresh-preflight checks
recorded here. Its separate actual 86,400-second attempt failed. The K partial
run contributes zero time to it or any replacement.

## L public attempts and durable recovery

L preflight 01 began at **2026-11-17 00:29:17.286394 UTC** and failed at the
Research upgrade step at **00:40:10.026397 UTC** with a sanitized ConsoleError.
The Mac upgrade had completed; Research replacement had not. Its 2,429 events,
17 confirmed payments, ten completed normal successes, five completed phases
and successful owned cleanup are preserved. A separate private H-to-L-to-H
transition diagnostic passed without reproducing that inner cause. Neither it
nor the later preflight establishes a specific fix; the first failure remains
unknown and unreproduced.

Fresh L preflight 02 passed over **900.172816125 event-clock monotonic seconds**
and **900.177095 wall seconds**, with all seven phases, 22 unique confirmed
payments, twelve normal successes and three declared-fault misses. Final
old-record recovery, another spend, chain/UTXO agreement and owned cleanup
passed. The independent public floor journal remained available; this does not
claim public recovery after both the selected record and journal are missing.
It supplies zero time to the separate full run.

That full L attempt began at **2026-11-17 01:51:39.968062 UTC** and failed at
**05:14:40.050802 UTC**, after **12,180.020856708 monotonic seconds** and
**12,180.082740 wall seconds** to the failure boundary. It recorded 205 unique
confirmed payments, 202 completed normal successes, zero recorded normal misses
and the completed crash phase. The next normal slot did not complete and is not
reclassified as a fault miss. The remaining six phases, full-clock end probe,
terminal old-backup recovery and final recovered spend were not reached.

The pending Mac-to-Research transaction remained absent from the recipient's
mempool in all 320 completed queries. Five same-known rebroadcasts retained its
TXID and raw-byte digest without issuing another payment. Both last peer-status
responses still reported one transaction peer. The original shared 60-second
payment/action budget expired at the final query; these records prove neither
zero peers nor an agent stall. The exact remaining budget was not logged.
Both recorded backends stopped and independent Research cleanup passed. The
registered worker CLI exited 0 during cleanup, 2.270638 seconds after failure;
that exit does not identify the earlier relay cause. The final result remains
**FAIL**, with zero partial credit and no current public clock.

Actual Docker Desktop acceptance on L passed: a real restart with the existing
host app, Desktop stop with surviving HTTP, one-click daemon start/reuse, a new
host-app process after a cold stop, older-backup recovery and a new confirmed
spend. The original wallet's identity, counters, backups and volume were
preserved. All eleven authorized Musashi containers were stopped with data
retained. The disposable backend stopped at PID 0 with its volume retained.
The passing report SHA256 is
`eb9be86d2d8171cad9df36ca418c09b20a24ce7f9441fcef9816ee903f436d8e`.
**An operating-system reboot was not performed.** The original external-driver
FAIL is preserved; its redundant unlock after recovery was corrected in the
driver alone before the fresh passing run.

The separate native H capacity diagnostic recovered an older backup with 1,450
retained public entries, 725 on each branch, after quarantining the selected
record while preserving independent public floors. It then issued receive index
725 and confirmed another spend; both final floors were 726. The complete
instrumented signer-start call took 0.599333125 seconds, and its checkpoint wait
took 0.468505417 seconds for a 1,956,099-byte frame. The existing five-second
operator-input and 45-second checkpoint deadlines were unchanged. Input-transfer
time was not measured directly. The 1,449 additional reservations were prepared
in a bounded native batch; this is a capacity check, not a full 24-hour workload.

## Relay diagnosis and the current follow-up

A private controlled L test forced native-v1 transport and dropped one matching
MSG_WTX announcement. The recipient stayed absent through the original
60-second diagnostic budget despite five byte-identical known rebroadcasts,
unchanged peer IDs and fresh pongs before/after each. A separately declared
positive-control budget reconnected the exact peer, acquired new peer IDs, and
confirmed the same transaction bytes in about 3.686 seconds. The failed harness
startup, socket-mode repair and passing control are preserved. This establishes
that controlled behavior; it does not establish the same loss or transport state
in the failed public run.

Read-only extraction from the stopped sender found the exact pending signed
transaction. A separate network-disabled clone of the receiver's persisted
public blocks, chainstate and mempool then ran qualified native H
`testmempoolaccept`. Its verdict was `allowed=true` at height 408 and UTXO count
547, with matching full tip/UTXO hashes, zero peers and an empty mempool before
and after. The RPC did not admit or broadcast the transaction. The source stayed
unchanged and stopped; the clone stopped at PID 0. Initializer/path-guard
failures and the exact empty process-lock exception are retained in the packet.

Offline persisted-state acceptance does not reconstruct original ephemeral
peer, relay, policy or process state. The **live failure cause remains unknown**.
Registered-peer repair code is under development and native-CI review. These
L/H diagnostics do not qualify that new source, complete its public acceptance,
or change production backend `NONE`, `RELEASE_HOLD` or human-review status.

| Gate | Status at this documentation checkpoint |
| --- | --- |
| H baseline native GCC images and private app flows on both host architectures | PASS; additional x86_64 Clang PASS, no ARM Clang claim |
| K native GCC/Clang profiles on both architectures and CI | PASS: four native profiles and 51 CI jobs |
| H/K fresh public preflight | PREFLIGHT_PASS; actual 900 seconds and final recovery/cleanup |
| Separate K 24-hour run | Controlled source supersession; raw FAIL/KeyboardInterrupt, cleanup PASS, zero credit |
| L native/app/CI | PASS: four native profiles, 17-event private HTTP flows, 14 runs/52 latest CI jobs |
| L actual Desktop restart/cold-app recovery | PASS; original custody preserved, OS reboot not performed |
| H native 1,450-entry old-backup recovery | PASS with unchanged deadlines; separate capacity diagnostic |
| L public preflights | First FAIL/unknown Research-upgrade cause; second PREFLIGHT_PASS/all seven phases |
| Separate L 24-hour run | FAIL after about 3h23m; 205 payments/202 completed normal successes, cleanup PASS, zero credit |
| Controlled L relay loss and offline H receiver test | Loss reproduced with passing separate control; persisted-state native allowed=true; live cause unknown |
| Current registered-peer follow-up | Under development/native-CI review; completed L evidence does not qualify it |
| Repaired-source preflight and separate complete public 24-hour run | Outstanding; no current public clock |

Earlier native-only snapshots retain their recorded pending public-run fields;
the separately dated preflight section supplies the completed preflight result.
Interrupted attempts contribute no elapsed time to a later soak. Update its
status only from the completed, source-bound final report. All coins remain
disposable TEST coins; production activation and an explicit release decision
are separate.
