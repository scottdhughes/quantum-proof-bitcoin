# ML-DSA-44 Portable Wrapper Prototype

## Status: ISOLATED_PROTOTYPE_IMPLEMENTED - RELEASE_HOLD
## Spec-ID: ML-DSA-44-WRAPPER-PROTOTYPE-v1
## Updated: 2026-07-20
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
aliases, fixes the signing-attempt bound at `814`, and marks upstream internal
and external function APIs `static`. Hidden visibility plus a dynamic symbol
audit restricts the production-shaped shared object to exactly:

```text
pqbtc_mldsa44_sign_hedged
pqbtc_mldsa44_verify_strict
```

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
CC=clang python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py \
  --sanitizers --sanitizer address-undefined --seconds 1800 \
  --coverage --output-dir /tmp/ml-dsa-44-asan
CC=clang python3 contrib/ml-dsa-engineering/run_verifier_fuzz.py \
  --sanitizers --sanitizer memory --seconds 1800 \
  --output-dir /tmp/ml-dsa-44-msan
python3 contrib/ml-dsa-engineering/run_differential_verifier_fuzz.py \
  --manifest-only
python3 -m unittest ci.test.test_ml_dsa_wrapper_prototype
python3 -m unittest ci.test.test_ml_dsa_sustained_fuzz
python3 -m unittest ci.test.test_ml_dsa_differential_fuzz
```

The verifier harness deterministically regenerates and replays 207 bounded
frames: 180 cases from the pinned C2SP Wycheproof ML-DSA-44 verification file
and 27 project cases covering commitment, `z`, hint, public-key, message,
context, length, and null-pointer boundaries. The frozen manifest records 202
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

The pinned review-reproduction workflow adds a 60-second Linux Clang
ASan/UBSan differential campaign. Its fuzz target calls the isolated wrapper,
OpenSSL 3.6.3's explicitly selected default provider in a separate library
context, and libcrux 0.0.10 in-process for every parsed frame and aborts
on any setup error or accept/reject disagreement. The wrapper's exact
invalid-argument taxonomy is still checked separately. The retained evidence
records source and binary hashes, both external-oracle pins, the resolved
`libcrypto` binary hash, coverage, minimized corpus, and crash artifacts. A
separate sanitized replay executable first sends five named frozen valid,
invalid, malformed, and null-argument frames through the same real three-way
target exactly once. This prevents an always-accepting or
always-rejecting well-shaped wrapper from passing that campaign merely because
the result remained inside the wrapper's documented return-code set. It does
not instrument the complete OpenSSL or Rust implementation bodies with the C
sanitizers and is not long-duration or multi-platform differential evidence.
The versioned clang-tidy/IWYU plan does not cover the differential-only branch
or external adapter sources; those C sources are compiled with fatal warnings
and exercised dynamically in the pinned review workflow instead.

## Residual Boundary

This prototype advances engineering evidence but closes no production gate:

- issue `#184`: Linux/macOS OS-RBG calls and fail-closed behavior now execute,
  but supported-platform RBG strength, fork/clone behavior, hardware signers,
  Windows execution, and lifecycle review remain open;
- issue `#185`: no compiled constant-time or worst-case supported-platform
  assessment has occurred;
- issue `#186`: self-verification and injected errors are partial controls,
  not a complete fault model;
- issue `#187`: explicit source cleanup and sanitizer evidence do not prove
  erasure of compiler copies, registers, caller-owned keys, or crash artifacts;
- issue `#188`: deterministic Wycheproof replay, bounded structure-aware
  ASan/UBSan and MSan campaigns, and bounded three-backend differential
  verifier fuzzing with retained evidence are now implemented, but stateful
  signer fuzzing, long-duration and broader-platform differential campaigns,
  automatic advisory-case ingestion, full Rust sanitizer coverage, minimum
  coverage goals, reviewed regression-vector promotion, and stack, worst-case,
  and adversarial-batch resource limits remain open;
- issue `#189`: the source capsule and network-free build are partial evidence,
  not an SBOM, reproducibility campaign, or ongoing advisory process;
- issue `#190`: key ownership, formats, backup, PSBT, and hardware-wallet
  behavior remain unspecified; and
- issue `#181`: no qualifying independent human cryptographic review has
  accepted this exact implementation commit.

No consensus-design work may use this prototype as production approval.
Issues `#181` and `#184` through `#190` remain open.
