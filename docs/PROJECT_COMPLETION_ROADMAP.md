# PQBTC completion roadmap

Updated 2026-11-09. This is the current execution order for the ML-DSA path.
The April–July Track A roadmap remains historical. This roadmap builds on the
[owner continuation](ML_DSA_44_OWNER_CONTINUATION.md), the implemented node
integration, and the [durable local app](DURABLE_RUNTIME_VALIDATION.md).

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
- 111 focused console/protocol tests at the durable-app checkpoint. These are
  bounded engineering results, not a count of all required release checks.

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

## Immediate next implementation

**Start with milestone 1: a source-built, fresh-machine runtime.** The current
`contrib/ml-dsa-console/durable.py` preserves a known-good runtime by copying a
prepared seed container. It cannot bootstrap an unrelated user's machine. Replace
that first-install dependency with a pinned, versioned build/package path while
retaining existing durable-wallet resume and recovery behavior.

The acceptance scenario is executable: create an isolated new runtime namespace,
build from the checked-in source and pinned dependencies, launch, fund/send/mine,
restart, recover and spend again. Keep the existing default wallet/volume intact.
Follow with the supported-build CI matrix and clean-checkout instructions needed
for public GitHub testers. Do not make another private demonstration the finish
line for this milestone.

## Specific gaps in the current code

- `durable.py` still depends on a prepared seed container for first install.
  Restart durability is complete; new-user bootstrap is not.
- Existing cryptographic comparator CI does not build and test the assembled
  ML-DSA node/signer/console flow. Add exact-source integration CI, including
  restart/recovery and both supported compiler builds.
- `-mldsa44demo` is explicitly regtest-only. The local runtime has network none
  and loopback-only peers. A separately identified multi-machine network is new
  work; actual witness verification is already implemented.
- rc2 remains active in the inherited signature registry/default implementation.
  The new network needs a complete accepted-signature/output contract and tests
  that it cannot silently route protected funds through that unqualified path.
- The research verifier batch model is not an enforced block budget. The
  inherited node weight limit and ML-DSA verification accounting must be
  reconciled and measured on the actual node before claiming network capacity.

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

This roadmap was prepared locally; it does not itself commit, push, publish a
release, expose a network service, or claim that unfinished work has passed.
