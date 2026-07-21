# ML-DSA-44 Engineering Contracts

This directory contains executable design contracts and an isolated portable-C
wrapper prototype for the selected `ML-DSA-44` engineering candidate. It is
separate from the frozen comparator in `contrib/ml-dsa-ref/` and is not linked
into the node, wallet, Script, or consensus code.

`hedged_signing_contract.py` models the fail-closed boundary required before a
future production signer can be proposed:

- the public API exposes hedged signing only;
- the 32-byte randomizer is generated inside that boundary;
- zero, repeated, short, unavailable, or failed entropy produces no signature;
- signing and self-verification failures produce no signature;
- calls through one signer are serialized and randomizer reuse detection is
  atomic across concurrent callers; and
- the local randomizer buffer is overwritten on every return path.

The Python module deliberately uses opaque key handles and a backend protocol.
It does not provide consensus code or claim that Python buffer clearing
establishes production secret erasure. Test-only entropy injection is private
to the executable contract tests. The private backend protocol is a model
seam, not a production FFI.

`backend_admission.json` records the bounded backend decision. It admits the
pinned `mldsa-native` portable-C path for a separate isolated wrapper prototype
only. The production backend remains unset, OpenSSL and libcrux remain oracles,
and every production gate remains open. The manifest also freezes the proposed
single-translation-unit, static-symbol, portable-C build contract.

`pqbtc_mldsa44.c` implements that contract as a production-shaped but
research-only wrapper. The checked-in `vendor/mldsa-native/` capsule contains
only the exact 34-file portable dependency closure and upstream license. The
normal build exports only `pqbtc_mldsa44_sign_hedged` and
`pqbtc_mldsa44_verify_strict`; deterministic, fixed-randomizer, seeded-keygen,
and failure controls exist only in a separately compiled test build. The
network-free harness checks source hashes, symbols, frozen vectors, OS entropy,
failure behavior, concurrency, and ASan/UBSan execution.

The normative requirements and lifecycle limits are in
`docs/ML_DSA_44_HEDGED_SIGNING_CONTRACT.md`. The admission disposition and
candidate comparison are in `docs/ML_DSA_44_BACKEND_ADMISSION.md`.
The implemented evidence and remaining boundaries are in
`docs/ML_DSA_44_WRAPPER_PROTOTYPE.md`.

## Versioned Static-Analysis Audit

`run_static_analysis.py` defines the isolated wrapper's versioned
clang-tidy/IWYU boundary. The wrapper workflow and the Promotion Matrix tidy
lane constrain LLVM/clang-tidy to major version 20 and record the exact tool
versions and binary hashes. IWYU is built from exact source commit
`6e08906c66b3009f2d590e4bd40d60fa303bf803`. The audit runs clang-tidy over
the production wrapper, test wrapper, smoke harness, and verifier fuzz target,
then checks both public headers for C11 self-containment.
The optional Annex-K `_s` functions recommended by one analyzer check are
unavailable on the supported Linux toolchain. That checker remains enabled and
fatal for new call sites; the 13 reviewed portable API calls use localized,
inventory-checked `NOLINTNEXTLINE` annotations.

IWYU is enforced only on the first-party smoke and verifier-fuzz translation
units and their wrapper headers. It intentionally does not propose edits for
`pqbtc_mldsa44.c`, because that file includes the pinned upstream
single-compilation-unit implementation and its nested `.c` files. Clang-tidy
still parses that implementation as part of the wrapper translation unit, but
the audit reports primary diagnostics only at first-party wrapper locations.
The versioned static plan predates the differential adapters: it does not run
clang-tidy/IWYU over the OpenSSL bridge, Rust bridge, exact-replay driver, or
the differential-only target branch. The review-reproduction workflow instead
compiles those C paths with fatal warnings and exercises them dynamically; the
Rust bridge is checked separately with the pinned Rust 1.89.0 `rustfmt` and
`rustc` toolchain.

Each run retains the exact plan, resolved tool and source identities,
per-command logs,
a machine-readable result, and `SHA256SUMS` in a commit-named workflow
artifact. This is static source-analysis evidence only. It is not a proof of
memory safety, constant-time behavior, secret erasure, or production fitness,
and it does not alter the release hold.

## Versioned Valgrind Constant-Time Audit

`run_valgrind_ct_analysis.py` defines a separate x86_64-Linux audit for the
isolated portable wrapper. The workflow checks out exact `mldsa-native` commit
`9b0ee84f4cf399043eca59eca4e5f8531ca1d61b` solely for its locked Nix
environment, then verifies the commit, Git tree, full `git archive`, and the
KyberSlash-derived variable-latency Valgrind patch. It also requires a clean
upstream worktree and verifies the complete `flake.lock`, its locked nixpkgs
revision and NAR hash, and Nix 2.24.9. Lockfile updates and writes are disabled.
The matrix uses the pinned `valgrind-varlat_clang20` and
`valgrind-varlat_gcc13` shells, Valgrind 3.26.0, and `-O2` wrapper binaries.
The three calibration probes use `-O0` so their intentionally secret-dependent
operations cannot be optimized away.

The analysis-only build marks the generated 32-byte randomizer secret
immediately after the entropy source succeeds, before the wrapper's length,
all-zero, digest, and repeat checks. It adds exactly two project
declassifications: the all-zero and immediate-repeat predicates whose result
is already exposed by distinct public error codes. The pinned upstream
portable ML-DSA implementation has its own separately hashed active/inactive
declassification inventory; the two project sites are not a claim about the
full translation unit.

The harness marks the 2,560-byte secret key undefined only after deterministic
key generation setup, then checks five distinct successful hedged signatures,
an immediate-repeat failure, and an all-zero failure without manually
declassifying status values or released signatures. Separate branch,
effective-address, and integer-division probes must all trigger the configured
Valgrind error sentinel, including the patched variable-latency diagnostic. A
fourth control branches on the marked secret key to prove the harness taint is
active. Each control requires a complete Memcheck XML record, the exact binary
and arguments, and an attributed probe stack frame. The clean wrapper run also
enforces Memcheck memory and leak errors without project suppressions.

Each compiler lane uploads the exact plan, source and tool hashes, build and
execution logs, Valgrind XML, binaries, a machine-readable report, and
`SHA256SUMS`. A pass is bounded to these binaries and scenarios. It does not
establish key-generation constant time, OS-randomness-path behavior, ARM or
other platform coverage, rejection-count independence, cache/speculative or
physical leakage resistance, secret erasure, or production fitness. Issue
`#185` and the release hold remain open.

## Differential Verifier Fuzzing

The pinned review-reproduction workflow runs a separate 60-second in-process
differential campaign. Every parsed frame is evaluated by the admitted
wrapper, OpenSSL 3.6.3's explicitly selected default provider in an isolated
library context, and libcrux 0.0.10; an oracle setup error or
accept/reject disagreement aborts through the normal libFuzzer crash path.
Wrapper argument-error taxonomy remains a separate assertion, while the two
external bridges normalize invalid shapes to rejection. The workflow records
the upstream commits, crate and source hashes, bridge and binary hashes, the
actual linked `libcrypto` path and hash, toolchains, minimized corpus, coverage,
logs, and crash artifacts for 90 days. Before the timed campaign, a separate
sanitized executable replays five named frozen accept/reject cases exactly once
through the real wrapper/OpenSSL/libcrux target and records each frame hash.
The upstream versions are pinned by the frozen reference manifest; the small
first-party adapter sources are review inputs whose exact hashes are evidence,
not a claim that the adapters themselves are independent implementations.

This closes the former self-fulfilling `OK`/`ERR_VERIFY` oracle gap for that
bounded Linux campaign. It is not long-duration or multi-platform
differential evidence, and the prebuilt OpenSSL and Rust implementation bodies
are not fully sanitizer-instrumented by the C fuzz build. It does not alter
the release hold.
