# PQBTC completion roadmap

Updated 2026-11-16 UTC. This is the current execution order for the ML-DSA path.
The April–July Track A roadmap remains historical. This roadmap builds on the
[owner continuation](ML_DSA_44_OWNER_CONTINUATION.md), the implemented node
integration, and the [durable local app](DURABLE_RUNTIME_VALIDATION.md).
The [current qualification record](ML_DSA_44_CURRENT_QUALIFICATION.md) identifies
the tested sources, completed public preflight and failed 24-hour soak attempt.

## Owner direction

The owner will not pay for external review. The distribution/testing path is
public open-source GitHub publication so anyone can build, run, inspect, and
test the project. Do not repeatedly request a paid reviewer, reviewer budget,
or reviewer engagement. Neither a particular outside reviewer nor a response
from the public is a prerequisite to continuing implementation or publishing an
accurately described experimental release.

Keep independent human review recorded as **not performed**. Public availability
and automated checks do not change that fact. Release decisions must state the
actual evidence, remaining risks, and owner's decision; they do not require
pretending that an audit occurred. Existing production-admission flags remain
unchanged until their technical requirements and explicit release decision are
handled. This is an engineering path to finishing, not a request to hand off the
project.

## Finish line

The first public release must let a new user start from a clean GitHub checkout,
build or obtain the corresponding versioned artifacts, launch the app, create a
wallet, join the designated valueless network, send/receive, back up/recover,
restart, and upgrade with documented behavior. It must work without Scott's
pre-existing containers, private working directories, or captured binaries.
Multiple machines must agree on confirmed transactions and consensus state.

The intended v1 scope is a Bitcoin-derived chain with the existing ML-DSA-44
contract, software wallets and isolated signers. Multisignature, hardware wallets,
mobile apps, xpub/BIP39 interoperability and broad PSBT exchange are deferred.
Their absence does not block this scoped release. Long-term maintenance continues
after release; it is not an undefined prerequisite to shipping v1.

## Already demonstrated

- Actual native ML-DSA witness verification, signing, mempool/block admission,
  two-node spends, and prior reorg/reindex tests on the explicit demo path.
- Local browser status, receive/send, funding/mining, lock/unlock and recovery.
- Durable volume, Docker startup, repeated one-click launch, Docker Desktop
  restart, forced container recreation and host app restart.
- Recovery with a missing current wallet record, later-address non-reuse and
  another confirmed spend, with matching full UTXO hashes on both nodes.
- Historical durable-app checkpoint: 111 focused console/protocol tests. That
  bounded count retains its original scope and is not the current release total.
- Clean-source installation and assembled-system CI, with all nine native gates
  and private app flows passing for F and G on Linux x86_64/aarch64 with GCC/Clang.
- Fresh D/F public preflight 03: all seven fault phases, 22 confirmed payments,
  final missing-record recovery/spend and owned cleanup passed over 900 seconds.
  The separate F 24-hour attempt failed after approximately 21 hours.
- Fresh F/G public preflight 02 also passed all seven fault phases, 22 confirmed
  payments and final recovery/spend/cleanup. Its separate G 24-hour attempt
  failed after 16 hours 46 minutes when both nodes lost their sole connection.
  Neither failed attempt contributes elapsed credit to a new run.

## Build order and acceptance tests

| Order | Deliverable we build | Done when |
| --- | --- | --- |
| 1 | **Fresh-machine build and launch** | A disposable clean environment, with no existing project image/volume/binaries, builds the pinned native source and launches from the public source package. No hardcoded Scott paths or seed container is needed. A second independent clean build verifies the declared reproducibility properties. |
| 2 | **User-owned wallet setup** | Normal setup creates a new wallet with a user-selected secret through an explicit trusted operator channel; the public demo phrase is confined to test mode. Creation, locking, wrong-password rejection, backup, missing/corrupt current record, and recovery are tested. Secrets never enter URL, logs, argv or environment. |
| 3 | **Deployable valueless network** | An explicitly identified network profile with frozen genesis/magic/HRPs and activation rules runs across independent machines. Its protected outputs require the chosen ML-DSA rules, with no classical or unqualified rc2 fallback. Peer discovery/configuration, relay, mining, synchronization, partition/rejoin and invalid signature/block rejection are tested. Existing defaults and old demo fixtures retain their meaning. |
| 4 | **Supported builds and hostile workloads** | Linux x86_64 GCC/Clang and the shipped Linux arm64 Docker build have exact-source/binary test receipts. Measure full-block validation, malformed transactions, mempool pressure, signer entropy/fault handling and crash recovery. Define ML-DSA verification accounting and enforceable block/mempool limits from actual node measurements, including one-over-limit rejection tests. Fix failures and record exclusions. |
| 5 | **Release package and continuous checks** | Versioned source/artifacts, dependency inventory, checksums, build instructions, release notes, console/native functional CI, and an operator guide match the release candidate. Upgrade/rollback and wallet/network identity checks pass. Current implementation/admission documentation reflects the assembled system. |
| 6 | **Public GitHub testing and v1 decision** | Publish the reproducible experimental candidate and test instructions. Run a declared multi-node soak with fixed workloads, duration and failure criteria; publish actual results and fix reproducible defects. Make an explicit evidence-based v1 go/no-go. No paid-audit or mandatory-public-review-response gate is added. |

Public source publication can happen as soon as the assembled changes are
reviewable and the build/test instructions work; it need not wait for every
later milestone. Public networking follows the dedicated network profile, not
exposure of the current isolated local fixture. A soak duration is chosen before
the run, and only actual elapsed time counts.

## Current implemented checkpoint

The normal launcher builds the node, client and isolated signer from a clean
committed checkout. The app has user-selected-secret TEST wallet setup, status,
receive/send, test funding/mining, lock/unlock, private backup/recovery,
persistent volume checks and version-replacement controls. The legacy seed
runtime remains available for its original fixture; it is not the normal
fresh-install prerequisite. See [clean-checkout validation](CLEAN_CHECKOUT_VALIDATION.md)
and the [public wallet guide](../contrib/ml-dsa-console/PUBLIC_TEST.md).

G has passing exact-source native and private app flows for Linux x86_64 and
native Linux aarch64 with both GCC and Clang, plus 52 successful CI jobs across
14 runs. F's earlier qualification and failed-soak evidence remain preserved.
The dedicated TEST accepted-set, reindex and measured resource-bound checks are
implemented. The current qualification record binds these observations to their
sources and exclusions; inherited/default network rules retain their meaning.

## Remaining execution

1. Qualify the TLS forwarding, durable peer maintenance and known-transaction
   recovery fixes, then complete a fresh public preflight and separate fresh
   24-hour public TEST soak. G fixed growing transaction-poll overhead, but its
   separate run failed after 16 hours 46 minutes with both peers disconnected;
   the earlier F run failed after approximately 21 hours. Preserve the live
   failure and independently reproduced TLS defect as distinct observations.
   Both clocks, workload/fault/recovery
   criteria, final cross-node state and cleanup must pass before recording a
   soak PASS. Preserve failed attempts without carrying elapsed time forward.
2. Finish the portable source/evidence packet and public tester instructions,
   preserving source, image, compiler and workload identities. Fix reproducible
   failures found during the soak or public testing.
3. Publish the actual completed soak result and record a scoped, evidence-based
   experimental release decision. Production activation remains a separate
   explicit decision; the production backend and release hold are unchanged.

Public GitHub source testing can continue while the soak is repaired. The completed
900-second preflight does not replace the separate 86,400-second run.

## How work advances

- For each milestone, implement the artifact, run its acceptance scenario, fix
  failures, and publish a concise result with exact source/build/workload identity.
- Use separate automated/code review and open GitHub issue reports as engineering
  inputs. Fix concrete findings; do not replace executable work with another
  design-only review loop.
- Reconcile historical admission/specification prose against verified
  implementation without relabeling old evidence or changing frozen protocol
  bytes. The current admission JSON and production activation remain separately
  controlled decisions, not progress counters to toggle.
- No real-value activation is claimed by a local demo, an open-source upload,
  or a passing test suite. Decide that release posture from the completed
  technical record and explicit owner direction.

Current results and the failed-run status are source-bound in the qualification
record. Update the soak result only from its completed final report.
