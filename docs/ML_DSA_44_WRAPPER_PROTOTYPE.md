# ML-DSA-44 Portable Wrapper Prototype

## Status: ISOLATED_PROTOTYPE_IMPLEMENTED - RELEASE_HOLD
## Spec-ID: ML-DSA-44-WRAPPER-PROTOTYPE-v1
## Updated: 2026-08-12
## Consensus-Relevant: NO

## Scope

This slice implements the bounded wrapper authorized by
`ML_DSA_44_BACKEND_ADMISSION.md`. It is an evidence artifact under `contrib/`,
not a PQBTC production backend. It has no node, wallet, Script, consensus,
`ALG_ID`, packaging, or functional-suite inventory connection. The production
backend remains `NONE`, and `RELEASE_HOLD` remains in force.

The wrapper uses raw key buffers because key ownership and wallet formats are
still open under issue `#190`. That prototype ABI is not approval of a
production key-handle or storage design.

## Frozen Source Capsule

The portable dependency closure is stored in
`contrib/ml-dsa-engineering/vendor/mldsa-native/` with its upstream license and
`SOURCE.json`. The manifest records:

- upstream tag `v1.0.0-beta2`;
- commit `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b`;
- upstream tree `c73c7029182122fce2f2dd8ac544ae990abd74a2`;
- full upstream `git archive --format=tar` SHA256
  `4fd08a772d0a142863593471f0c26e239bac8babc8e2a960e072f06ee89ff30b`;
- exactly 34 required files;
- no native backend or assembly files; and
- capsule SHA256
  `2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb`.

The capsule hash is computed from sorted lines containing each relative path
and file SHA256. Tests reject additions, removals, path changes, or byte
changes. Builds require no source download. The exact vendor subtree is exempt
from first-party include, include-guard, and spelling style checks so those
checks cannot require edits to upstream bytes; the project wrapper and harness
remain subject to normal repository lint.

## Build Boundary

`pqbtc_mldsa44.c` is the one compiled translation unit. It includes the
project configuration, project entropy and zeroization hooks, the frozen
portable source, repeat guard, failure mapping, self-verification, and public
wrapper.

The configuration freezes ML-DSA-44, disables native backends and SUPERCOP
aliases, fixes the signing-attempt bound at `821`, and marks upstream internal
and external function APIs `static`. Hidden visibility plus a dynamic symbol
audit restricts the production-shaped shared object to exactly:

```text
pqbtc_mldsa44_sign_hedged
pqbtc_mldsa44_verify_strict
```

The July 31, 2026 FIPS 204 potential-corrections sheet raised the minimum
internal-signing loop limit from `814` to `821`. The frozen upstream capsule's
compile-time guard still describes `814` as sufficient; those provenance-bound
vendor bytes are intentionally unchanged, while the project-owned
configuration supplies the corrected higher limit. A production proposal must
repin and re-review upstream source rather than treating this override as an
upstream correction.

A separately compiled `PQBTC_MLDSA44_TESTING` build exposes fixed-randomizer,
seeded-keygen, entropy-failure, backend-failure, wrong-length, and forced-
verification controls. The production-shaped symbol audit fails if any test or
upstream entry point is exported.

## Signing Behavior

The wrapper validates all sizes and the 255-byte context bound before entropy
acquisition. It obtains exactly 32 bytes inside the same translation unit that
calls the upstream randomized signer. The source adapter is `getentropy` on
the Linux/macOS prototype and `BCryptGenRandom` in the unvalidated Windows
source path. There is no project DRBG, fallback source, public entropy callback,
caller-supplied randomizer, or deterministic production mode.

The module rejects source failure, a short result, an all-zero result, and an
immediate repeat. It stores only a SHAKE256 digest of the last accepted
randomizer. A process-wide C11 atomic lock serializes entropy acquisition,
signing, repeat-state update, self-verification, cleanup, and result release.

Signing occurs into a private temporary buffer. The wrapper requires the exact
2,420-byte result and verifies it against the supplied 1,312-byte public key
before copying it to the caller. Output that overlaps a key, message, or context
is rejected without writing it. Once an exact, non-overlapping output buffer is
accepted, every later failure leaves that complete buffer zeroed. The project
zeroization hook uses volatile byte stores and is also used by the frozen
backend for its signing temporaries.

## Executable Evidence

`run_wrapper_tests.py` builds from the checked-in capsule and verifies:

- the exact source file set and aggregate hash;
- the two-symbol production-shaped export surface;
- the NIST ACVP key-generation `tgId=1`, `tcId=1` public/private key hashes;
- the frozen repo signing hash previously agreed by all three comparator
  implementations;
- strict verification and mutated-signature rejection;
- real OS-entropy signing twice through the production-shaped build;
- source failure, short, all-zero, and repeated entropy;
- backend failure, signing-attempt exhaustion mapping, wrong signature length,
  and self-verification failure;
- output/key alias rejection, including on another malformed argument;
- zero output on every injected failure;
- zeroization-hook execution; and
- concurrent calls in which one repeated randomizer is accepted and the other
  is rejected atomically.

The dedicated workflow runs the harness and ASan/UBSan build with GCC and
Clang on Ubuntu. The local macOS Clang harness also exercises `getentropy`.
Injected failures validate wrapper control flow; they are not physical fault
testing or evidence that the real rejection loop exhausted.

Run the bounded checks with:

```bash
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py --manifest-only
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py --sanitizers
python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py --manifest-only
python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py
CC=clang python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py --sanitizers --runs 10000
python3 contrib/ml-dsa-engineering/run_stateful_signer_fuzz.py --manifest-only
CC=clang python3 contrib/ml-dsa-engineering/run_stateful_signer_fuzz.py \
  --sanitizers --sanitizer address-undefined --runs 10000 \
  --output-dir /tmp/ml-dsa-44-stateful-asan
CC=clang python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py \
  --sanitizers --sanitizer address-undefined --seconds 1800 \
  --coverage --output-dir /tmp/ml-dsa-44-asan
CC=clang python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py \
  --sanitizers --sanitizer memory --seconds 1800 \
  --output-dir /tmp/ml-dsa-44-msan
python3 contrib/ml-dsa-engineering/run_differential_verifier_fuzz.py \
  --manifest-only
python3 contrib/ml-dsa-engineering/run_cbmc_reproduction.py --plan-only
python3 -m unittest ci.test.test_ml_dsa_wrapper_prototype
python3 -m unittest ci.test.test_ml_dsa_sustained_fuzz
python3 -m unittest ci.test.test_ml_dsa_differential_fuzz
python3 -m unittest ci.test.test_ml_dsa_cbmc_reproduction
python3 -m unittest ci.test.test_ml_dsa_stateful_signer_fuzz
```

The verifier harness deterministically regenerates and replays 245 bounded
frames: 180 cases from the pinned C2SP Wycheproof ML-DSA-44 verification file
plus 27 project cases and 38 promoted retained-corpus regressions covering
commitment, `z`, hint, public-key, message, context, length, and null-pointer
boundaries. The frozen manifest records 240
unique frames and their expected strict-wrapper result classes. Its custom
libFuzzer mutator preserves the frame format while targeting those same
ML-DSA-44 fields. CI runs replay with GCC and Clang; the dedicated workflow
runs the bounded sanitizer campaigns described below. The 4,096-byte message
cap, five-second input timeout, 1 GiB RSS cap, and 256 MiB allocation cap are
fuzz-campaign bounds, not production protocol limits or exhaustive resource
proofs.

The dedicated sustained-fuzzing workflow runs separate Linux Clang
ASan/UBSan and MSan jobs. Pull requests and pushes use 60-second smoke
campaigns; the weekly schedule and manual dispatch use 1,800-second campaigns.
Each run retains the complete log, machine-readable campaign metadata,
content-addressed SHA256 provenance, crash inputs, best-effort minimized crash
inputs, and a coverage-minimized corpus for 90 days. ASan/UBSan also emits
text and JSON LLVM source-coverage summaries.
Scheduled and manual runs may seed from the most recent successful retained
corpus; imported files are bounded to the 8,096-byte frame limit and renamed
by content hash. Scheduled and manual campaigns use a varying recorded seed;
pull-request and push smokes retain seed 188 for exact repeatability. MSan
instruments the complete portable backend translation unit, but system-library
coverage still depends on LLVM interceptors and is not an all-code proof. A
retained crash is evidence to investigate, not an
automatically trusted regression vector: promotion into a checked-in corpus
still requires review.

The stateful signer harness adds a separate test-only target for the wrapper's
seeded key generation and hedged-signing transition contract. Every input
resets module state. Every parsed frame derives the same keypair twice from a
32-byte seed and executes a bounded sequence of at most four hedged-signing
calls. The
checked-in 31-frame corpus covers 12 effective state-transition sequences:
fresh and repeated randomizers, short/failed/all-zero entropy, invalid
arguments and output aliases, injected backend/attempt/length/self-verification
failures, output zeroing, reset-and-reuse behavior, empty and maximum-sized
bounded messages, and 0-, 255-, and 256-byte contexts. The target asserts the
exact entropy-request count, post-failure repeat-state transition,
deterministic fixed-randomizer signature, strict verification, and input
immutability.

The sustained workflow runs this target in distinct Clang ASan/UBSan and MSan
jobs so the MSan result does not include uninstrumented OpenSSL or Rust oracle
bodies. Pull requests and pushes use 60-second smoke campaigns; weekly and
manual runs use 1,800 seconds and may import the latest successful minimized
stateful corpus. That restore must come from an ancestor `main` run and pass
the complete evidence checksum inventory, campaign identity, clean-head,
minimized-corpus digest, flat regular-file, and resource-bound checks before
content-addressed import. The stateful evidence has its own artifact and corpus
namespace. Immediately before copying, the importer rechecks the validated
count, byte total, and name-bound aggregate, then records a content-addressed
receipt for the novel imported set. These stateful libFuzzer campaigns do not
call `fork()`; they bind and exercise the exact signing-state sources under
ASan/UBSan and MSan.

The deterministic coordinated POSIX `fork()` case is executed directly by
`run_wrapper_tests.py` and the dedicated wrapper workflow. A worker holds the
signing lock, the at-fork prepare handler waits for that critical section, and
both parent and child subsequently sign and verify under a watchdog on the
tested platform. This is a module-lock observation, not portable POSIX
child-signing support; a multithreaded child must `exec` before using the
non-async-signal-safe signer. The scenario does not establish safety for
reentrant or signal-handler fork, `_Fork`, `vfork`, raw `clone`, arbitrary
handler ordering, module unloading, multi-process key isolation, worst-case
signing resources, or production fitness.

Main-dispatched wrapper run `31521182969`, attempt `1`, completed all five jobs
at exact head `79de77faf112453868779861ae0c982dba533f84`. Portable Clang job
`93878301462` and portable GCC job `93878301523` each ran the normal and
ASan/UBSan harness and reported both passes, so the direct held-lock fork and
fail-closed lifecycle-readiness assertions executed under both compilers. The
injected readiness failure is a deterministic test control, not an observed OS
`pthread_atfork()` failure. Static-analysis artifact `9114717228` has outer
SHA-256 `1a1ea00f21d96a9480ae8161507d2ec8edcbff09d49506daa650f132d3349e65`;
the pinned Valgrind Clang and GCC artifacts `9113442292` and `9113457751` have
outer SHA-256 values
`aeed83dc5e377aa2b79bc4fdc6ec9e70deaee705ecd9424d9dd5eb399e5278d1`
and `1db38123fa59ee0a0c0284163f8ce415abe7492143faf7604e3ef6c411c4deb7`.
Each downloaded archive matched its API digest and all `18/18` internal
checksums passed. Static analysis passed all 12 scoped checks; both calibrated
Valgrind controls fired while the wrapper path recorded zero errors,
variable-latency findings, or leaks.

Exact-main sustained run `31521182965`, attempt `1`, completed all four
1,800-second jobs at
`79de77faf112453868779861ae0c982dba533f84`. The strict-verifier ASan/UBSan
and MSan lanes executed `7,665,005` and `3,012,895` units after importing `121`
and `76` retained seeds; their minimized corpora contain `123` and `83` files.
The stateful-signer ASan/UBSan and MSan lanes executed `105,000` and `51,813`
units over `1,801.122` and `1,801.192` measured fuzzer seconds, imported `173`
and `130` retained seeds, replayed all `31/31` deterministic cases, and
minimized to `261` and `202` files. All four external artifact digests and
internal checksum inventories were independently verified, every source
binding matched the exact repository head, and every crash and minimized-crash
count was zero. No sanitizer or disagreement marker was present. These
campaigns exercise exact sources and state transitions; they do not execute
the fork lifecycle test.

The pinned review-reproduction workflow adds a 60-second pull-request smoke or
a 1,800-second scheduled/manual main Linux Clang ASan/UBSan differential
campaign. Its fuzz target calls the isolated wrapper,
OpenSSL 3.6.3's explicitly selected default provider in a separate library
context, and libcrux 0.0.10 in-process for every parsed frame and aborts
on any setup error or accept/reject disagreement. The wrapper's exact
invalid-argument taxonomy is still checked separately. The retained evidence
records source and binary hashes, both external-oracle pins, the resolved
`libcrypto` binary hash, coverage, minimized corpus, and crash artifacts. A
pull-request run is explicitly labeled `pull_request_head_smoke_only`, records
`promotion_eligible=false`, and uploads a `review-candidate` artifact because
the workflow and local evidence generator are controlled by that pull request.
Scheduled or manual evidence is promotion-eligible only on `main` and retains
the broad frozen-baseline comparison for the workflow definition, engineering
generator tree, adapters, comparator, and the CLI, reference, and differential
control tests. Non-main manual dispatches skip the reproduction job and cannot
upload trusted evidence. The trusted artifact prefix is assigned only after
the main-ref and frozen-input checks complete; earlier failures remain pending
or rejected. A substantive change to the workflow or evidence generator
therefore fails trusted main reproduction while this repository-local guard
remains intact, until a separate, reviewed baseline re-pin. The local guard
closes accidental and ordinary reviewed source drift; it cannot independently
authenticate a malicious workflow edit that removes its own check. Evidence
must remain advisory until that trust decision is anchored outside the
candidate workflow.
A separate sanitized replay executable first sends five named frozen valid,
invalid, malformed, and null-argument frames through the same real three-way
target exactly once. This prevents an always-accepting or
always-rejecting well-shaped wrapper from passing that campaign merely because
the result remained inside the wrapper's documented return-code set. It does
not instrument the complete OpenSSL or Rust implementation bodies with the C
sanitizers and is not long-duration or multi-platform differential evidence.
The versioned clang-tidy/IWYU plan does not cover the differential-only branch
or external adapter sources; those C sources are compiled with fatal warnings
and exercised dynamically in the pinned review workflow instead.

Exact-main review-reproduction run `31521183046`, attempt `1`, passed at
`79de77faf112453868779861ae0c982dba533f84` against frozen baseline
`60e259458d1029fa4193de878f14d41a0793042d`. Its 1,800-second differential
campaign imported `83` retained seeds, completed `1,675,782` executions over
`1,801.174` measured fuzzer seconds, and passed all `5/5` exact replays,
`38/38` promoted regressions, 13 comparator checks, 70 ACVP cases, and every
coverage floor. Crash and minimized-crash counts were zero, and no sanitizer,
oracle-error, or disagreement marker was present. Artifact `9114784945` has
outer SHA-256
`203e6252633f4477af8702e8363b391e59d8b1ae04140174b4b849443b6d91e7`;
all four outer/nested checksum inventories passed. The artifact records
`frozen_baseline_reproduction` and `promotion_eligible=true`. This verifier
campaign binds the changed wrapper sources but does not call `fork()` and does
not extend the direct lifecycle observation.

The versioned
[exact-main evidence receipt](reviews/evidence/ml-dsa-44-trusted-main/79de77faf112453868779861ae0c982dba533f84/SOURCE.json)
records the complete workflow, job, artifact, checksum, retained-source, and
scope metadata for the resource, wrapper, sustained, and review lanes.

## Direct-Verifier Resource-Envelope Observation

The isolated resource lane calls only `pqbtc_mldsa44_verify_strict` in the
production-shaped portable-C build on Linux x86_64. Its deterministic source
set is the 240 unique frozen verifier frames. It expands that set into four
separate 4,287-call batches: a rotating mixed batch, a rotating valid batch,
deep verification rejects, and a same-public-key mixture of the four required
accepts plus the five required deep rejects that retain the frozen key. The
two public-key mutation cases remain in the deep-reject batch. The 4,287-call
size comes from the existing raw-payload
research model and is not a consensus, block, transaction, mempool, or
production limit.

The probe runs inside a 128 KiB guarded pthread and records the configured
stack and guard sizes. GCC and Clang `.su` output is retained as
compiler-specific static-frame observation. It is not treated as a formal
whole-call-chain stack bound. Linker interposition around the project binary
requires zero `malloc`, `calloc`, `realloc`, `free`, `aligned_alloc`, and
`posix_memalign` calls during direct verification; that instrumentation does
not claim visibility into dynamic-loader or system-library internals.

Each batch retains raw integer timing samples plus matched loop-control
samples, and the evidence validator independently recomputes the descriptive
statistics. The control loop is retained but excluded from numeric verifier
aggregation. The separately reviewed schema-`2` policy defines only coarse,
test-only Linux x86_64 gross-regression ceilings: `2,000,000,000` CPU
nanoseconds and `5,000,000,000` wall nanoseconds per batch;
`8,000,000,000` CPU nanoseconds and `20,000,000,000` wall nanoseconds across
the first call plus four batches; `10,000,000` / `25,000,000` CPU/wall
nanoseconds for the first call; `75,000,000` / `200,000,000` CPU/wall
nanoseconds for any retained verifier-batch sample; and `65,536` KiB process peak RSS. It
also retains the exact 128 KiB guarded-thread and zero instrumented project-
heap-call requirements. A rejected numeric observation remains a checksummed
raw diagnostic with a recomputable `FAIL` receipt only when the complete
repository, trust, compiler, build, corpus, stack, and detector-control
evidence remains verifiable; it cannot become a passing job.

Protected-main push run `31520865906`, attempt `1`, observed exact head
`79de77faf112453868779861ae0c982dba533f84` against baseline pointer
`60e259458d1029fa4193de878f14d41a0793042d`. The guarded diff was empty and
both reports were independently revalidated with all internal checksums
passing. GCC artifact `9112965965` has outer SHA-256
`74063a8817bce33541d89bc655e10593507261b22ed60e99f75b7d48ae9af5a2`;
Clang artifact `9112975963` has outer SHA-256
`04c5c3f1283851cb93e4b0488091f74719002500d916f0e404cd14ea72d1cf0d`.
Both are exact-main `TRUSTED_MAIN_OBSERVATION` receipts and remain
`promotion_eligible=false`. Their exact head, workflow/run/job provenance,
archive and internal checksums, observation/report hashes, compiler targets,
and version-output hashes are the frozen basis for the coarse policy. The 31
raw samples partition one batch rather than supplying 31 independent batch
repetitions, so the policy makes no percentile claim and requires at least two
additional protected-main samples per compiler before tightening.

Pull-request observations remain `UNTRUSTED_PR_OBSERVATION`. The numeric-
policy change must merge and then receive a separate reviewed baseline-pointer
advance before a clean protected-main push can produce policy-enforced
`TRUSTED_MAIN_OBSERVATION` evidence. Manual dispatches remain untrusted. No
individual compiler artifact is promotion-eligible: the exact-head GCC and
Clang pair and external GitHub Actions provenance must be verified together.

This is a test-only observation lane, not a supported-platform or worst-case
resource proof. It changes no production linkage or behavior, does not admit
SIMD256, and does not establish a consensus parser or adversarial block limit.
Issue `#188` remains open pending fresh policy-enforced trusted-main evidence,
broader-platform and toolchain coverage, concurrency and production-parser
limits, and exact-commit re-review. Issue `#181` also remains open, production
remains `NONE`, and `RELEASE_HOLD` remains in force.

## Pinned Upstream CBMC Reproduction

The dedicated read-only workflow checks out exact `mldsa-native` commit
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b` and verifies its Git tree, full
archive hash, locked Nix inputs, and critical proof infrastructure before
running the complete normal ML-DSA-44 CBMC lane. Its frozen inventory contains
200 proof directories and 200 unique proof UIDs. A successful reproduction
requires 200 reported successes, zero failures and timeouts, and exact result
name equality with that inventory. It also requires every file in the
checked-in 34-file portable capsule to match the pinned upstream bytes.

The retained report records the repository inputs, upstream and tool
identities, proof and capsule inventories, raw result, full log, host details,
and evidence checksums. These are upstream modular source-level safety and
undefined-behavior contracts. They do not directly model
`pqbtc_mldsa44_sign_hedged`, `pqbtc_mldsa44_verify_strict`, the project wrapper
configuration, entropy and zeroization adapters, repeat guard, error mapping,
or final single-compilation-unit binary. They also do not prove functional
correctness, cryptographic security, constant-time or leakage resistance,
fault resistance, thread safety, or production readiness. The reproduction
does not replace independent human cryptographic review and does not change
the release hold.

## Residual Boundary

This prototype advances engineering evidence but closes no production gate:

- issue `#184`: Linux/macOS OS-RBG calls, fail-closed behavior, and one
  coordinated standard-POSIX-fork parent/child module-lock regression now
  execute, but async-signal-safe child signing, supported-platform RBG
  strength, reentrant/alternate fork and clone behavior, at-fork handler
  ordering, module lifetime, hardware signers, Windows execution, and lifecycle
  review remain open;
- issue `#185`: a bounded x86_64 Valgrind constant-time/variable-latency audit
  with calibrated controls has passed, but ARM, Windows, cache, speculative,
  physical-leakage, rejection-count, and production-binary coverage remain
  open;
- issue `#186`: self-verification and injected errors are partial controls,
  not a complete fault model;
- issue `#187`: explicit source cleanup and sanitizer evidence do not prove
  erasure of compiler copies, registers, caller-owned keys, or crash artifacts;
- issue `#188`: deterministic Wycheproof replay, bounded structure-aware
  ASan/UBSan and MSan campaigns, and bounded three-backend differential
  verifier fuzzing with retained evidence and supplementary portable libcrux
  Miri execution are now implemented; reviewed minimized regressions and the
  bounded stateful signer/seeded-keygen lane have exact-main 1,800-second
  evidence. The three research oracle CLIs now enforce documented argv parser
  limits and replay fixed plus deterministic malformed-input mutations,
  including non-UTF-8 arguments, with separate ASan/UBSan coverage for the C
  adapters. Broader-platform and Rust sanitizer coverage, reviewed
  allocation/stack/CPU and adversarial-batch acceptance limits, and
  exact-commit re-review remain open;
- issue `#189`: a dated fail-closed selected-graph advisory ledger, full-lock
  cargo-audit/OSV scans, selected dependency graph, CycloneDX SBOM, and weekly
  retained refresh are implemented; exact-commit independent re-review remains
  open;
- issue `#190`: key ownership, formats, backup, PSBT, and hardware-wallet
  behavior remain unspecified; and
- issue `#181`: no qualifying independent human cryptographic review has
  accepted this exact implementation commit.

No consensus-design work may use this prototype as production approval.
Issues `#181` and `#184` through `#190` remain open.
