# ML-DSA-44 Backend Admission

## Status: ISOLATED_PROTOTYPE_IMPLEMENTED - RELEASE_HOLD
## Spec-ID: ML-DSA-44-BACKEND-ADMISSION-v1
## Decided: 2026-07-19
## Evidence-Updated: 2026-08-20
## Consensus-Relevant: NO

## Decision

The explicit disposition is:

> **`MLDSA_NATIVE_PORTABLE_C_ISOLATED_PROTOTYPE`**

The pinned `mldsa-native` `v1.0.0-beta2` portable-C path may be used in a
separate `contrib/` prototype to implement and test the project-owned
hedged-signing wrapper. The production backend remains `NONE`, and
`RELEASE_HOLD` remains in force.

The authorized slice now vendors the exact portable dependency closure and
compiles it only inside the isolated `contrib/` wrapper. It does not link that
wrapper into the node, wallet, Script, consensus, packaging, or an `ALG_ID`.
OpenSSL 3.6.3 and libcrux 0.0.10 remain comparator oracles, not production
dependencies.

The machine-readable disposition is
`contrib/ml-dsa-engineering/backend_admission.json`. CI checks that its source
pins match the frozen comparator and that no production backend or closed
release gate is recorded.

## Selection Boundary

Algorithm conformance is not the differentiator in this decision. All three
pinned implementations pass the frozen ML-DSA-44 comparator. Backend admission
also requires a reviewable entropy boundary, secret lifetime, production/test
API separation, toolchain fit, advisory posture, and reproducible source pin.

| Gate | OpenSSL 3.6.3 | mldsa-native beta2 portable C | libcrux 0.0.10 portable |
| --- | --- | --- | --- |
| Exact FIPS 204 evidence | Pass | Pass | Pass |
| Hedged entropy boundary | Internal OpenSSL DRBG, but deterministic and test-entropy controls are public parameters | High-level randomized API calls an integrator-owned `mld_randombytes` hook and propagates RNG failure | Signing API requires the caller to supply the 32-byte randomizer |
| Secret cleanup | Randomizer and signing temporaries are cleansed in the reviewed source; provider and caller key lifetimes remain unreviewed | Signing allocations and randomizer are zeroized; upstream explicitly warns that compiler-created copies remain possible | Signing-key wrapper is clonable raw bytes without an evident zeroizing `Drop` |
| Side-channel evidence | No supported PQBTC binary evidence | Bounded x86_64 Valgrind constant-time/variable-latency audit passes with calibrated positive controls; ARM, Windows, cache/speculative/physical leakage, rejection-count independence, and production binaries remain open. CBMC covers memory/type/selected-UB properties, not timing | Formal scope covers selected arithmetic, NTT, and serialization; not the complete implementation or compiled timing |
| Build fit | Would add a full provider dependency to a node that does not otherwise link OpenSSL | Portable C, minimal dependencies, single-compilation-unit support, and static API qualification fit a narrow C/C++ wrapper | Would add Rust 1.89, Cargo dependency resolution, and a new FFI boundary |
| Lifecycle | Stable 3.6 series, broad maintenance surface | Latest tagged release found on 2026-07-19; substantial post-tag API churn requires a later re-pin | Fresh 0.0.10 release; dated ledger covers nine libcrux-family and three rand/rand_core selected-graph RustSec entries |
| License | Apache-2.0 | Apache-2.0 OR ISC OR MIT | Apache-2.0 |
| Disposition | `ORACLE_ONLY` | `ISOLATED_PROTOTYPE_ADMITTED` | `ORACLE_ONLY` |

These are source and integration assessments, not claims that an upstream
project is insecure. The selected prototype path remains unapproved for
production until PQBTC validates the exact wrapper binary and closes the
project gates below.

## Candidate Findings

### OpenSSL 3.6.3

OpenSSL's ML-DSA provider generates per-message randomness through its private
DRBG, returns failure when generation fails, and cleanses its local randomizer.
It also exposes `deterministic` and `test-entropy` signature parameters. A
PQBTC wrapper could suppress those controls, but the resulting dependency
would include a large provider and configuration surface that the node does
not otherwise require. Provider selection, dynamic configuration, key object
lifetime, and the exact module boundary would all need separate review.

OpenSSL remains the strongest general-purpose differential oracle in this
repository. It is not the narrowest production integration.

### mldsa-native v1.0.0-beta2 portable C

The high-level `mldsa_signature` entry point implements randomized signing,
calls the integrator-provided random-byte hook, returns `MLD_ERR_RNG_FAIL` on
failure, clears signing temporaries, and supports an explicit rejection-loop
bound. The source can be compiled as one C translation unit and can mark all
upstream public entry points `static`, allowing a project wrapper to export
only its hedged operation.

The upstream release describes the portable C backend as production-ready
within its documented verification scope. PQBTC does not adopt that conclusion
for its own product: the exact integration, compiler output, operating-system
RBG adapters, caller-owned key memory, failure paths, and supported platforms
have not been reviewed. The source descends from the PQ-Crystals reference
implementation, so this admission also does not add independent design review.

The beta tag was still the newest tagged release on the evidence date, while
the default branch had substantial API and proof work after the tag. The
prototype therefore stays pinned to the comparator commit. Any later production
proposal must select a then-current tagged source, explain every change from
this pin, and rerun the complete evidence package.

### libcrux-ml-dsa 0.0.10 portable Rust

libcrux provides valuable separate-lineage interoperability evidence and
formally verified components. Its current signing API accepts randomizer bytes
from the caller, its signing-key wrapper is clonable, and the reviewed type has
no evident zeroizing destructor. A production wrapper would have to add an RNG
and secret-owning boundary around the crate, then cross a new Rust/C++ FFI and
toolchain boundary.

The dated ledger now records all 12 current RustSec entries across the 16
packages in the selected graph: nine libcrux-family entries plus three patched
rand/rand_core entries. Every selected pin is at or above its published fixed
version, but regression status is reported separately from version status.
The exact ML-DSA-44 portable malformed-hint check for RUSTSEC-2026-0076 passes;
the retained upstream 0076/0077 tests are explicitly labeled ML-DSA-65, and
pinned Wycheproof ML-DSA-44 tcIds 125 and 126 provide exact three-oracle
regressions for positive and negative signer-response coefficients at the
infinity-norm boundary for 0077. The
AVX2-specific 0125/0126 regressions block any future SIMD256 admission. This is
useful evidence, not a reason to prefer a wider integration boundary for the
first prototype.

The separate SIMD256 test lane implements those exact regressions without
changing the production backend or admitting SIMD256. Trusted-main push run
`30242969373`, attempt `1`, passed at exact commit
`f301227089086dad6918a76814d7227e61e2d71b`; its immutable 20-member artifact
is retained with outer SHA-256
`3c7e4bb5ce00e04186b295c9e1272b9440c5e77627cc3b320f256dd9038305a5`.
The 0125/0126 rows now record exact test-only `PASS`, while current path
applicability remains `NOT_APPLICABLE`, `production_backend` remains `NONE`,
`simd256_admitted` remains false, and the release hold remains true.

## Frozen Prototype Build Contract

The implemented wrapper uses the exact source pin in `backend_admission.json`
and is required to preserve all of these conditions:

1. compile only ML-DSA-44 and the portable C arithmetic/FIPS 202 paths;
2. use one translation unit and mark upstream APIs `static`;
3. disable SUPERCOP aliases and export only a project-owned hedged-signing
   wrapper plus the strict verification operation needed for self-checking;
4. set the signing-attempt bound to `821` and return no partial result when it
   is exhausted;
5. provide project-owned random-byte and zeroization hooks inside that same
   compiled module;
6. expose no caller-supplied `rnd`, deterministic mode, seed, ACVP operation,
   or entropy callback from the production-shaped wrapper;
7. self-verify every generated signature before release; and
8. remain under `contrib/` with no node, wallet, Script, consensus, `ALG_ID`,
   packaging, or inventory connection.

The prototype has two builds. The production-shaped build exports only the
restricted wrapper. A separately named test build exposes deterministic or
fixed-randomizer operations for vector testing. CI inspects the
production-shaped symbol table and fails if a deterministic, test, or upstream
signing entry point is exported.

The `821` bound incorporates NIST's July 31, 2026 potential correction to
Appendix C (previously `814`). The vendored upstream capsule remains at its
exact reviewed commit and still contains the older lower-bound guard; the
project-owned configuration exceeds that guard without changing vendor bytes.
Any production admission still requires an upstream repin and exact-commit
review.

## Implemented Prototype Evidence

`ML_DSA_44_WRAPPER_PROTOTYPE.md` records the completed bounded implementation.
The checked-in source capsule contains the exact 34-file portable dependency
closure and upstream license. Its aggregate SHA256 is
`2588da55bcd4443aea906bf16fe21402d8d5ee4b19be906e3f72c563b81601bb`.
The full pinned upstream Git archive SHA256 is
`4fd08a772d0a142863593471f0c26e239bac8babc8e2a960e072f06ee89ff30b`.
No native backend or assembly source is present.

The production-shaped shared object exports exactly
`pqbtc_mldsa44_sign_hedged` and `pqbtc_mldsa44_verify_strict`. The test build is
separate and exposes deterministic/fixed-randomizer and injected-failure
controls only for evidence generation. The harness exercises real OS entropy,
frozen key/signature hashes, strict verification, fail-closed output,
zeroization-hook execution, concurrent repeat rejection, coordinated standard
POSIX fork parent/child module-lock recovery, fail-closed at-fork registration,
and ASan/UBSan. A deterministic test-build-only checkpoint also flips a bit in
a genuinely generated exact-length candidate immediately before the real
self-verifier and requires verification rejection, all-zero caller output,
observed candidate cleanup, and continued rejection of the consumed
randomizer. `ML_DSA_44_FAULT_MODEL.md` bounds this as issue-`#186` tranche 1;
it is not physical-fault, diversified-verifier, or control-flow-skip evidence.
Child signing is a tested-platform observation, not a portable
POSIX guarantee: the signer is not async-signal-safe, so a portable
multithreaded child must `exec` first. The fork evidence also requires the
module to remain loaded and does not cover reentrant or signal-handler fork,
`_Fork`, `vfork`, raw `clone`, or arbitrary cross-library handler ordering.

The direct lifecycle evidence is main-dispatched wrapper run `31521182969` at
exact commit `79de77faf112453868779861ae0c982dba533f84`. Its GCC and Clang
portable jobs each passed the normal and ASan/UBSan harness, including the
held-lock parent/child fork regression and the injected fail-closed lifecycle
readiness case. All supporting static-analysis and pinned Valgrind jobs also
passed with independently verified artifact and internal checksums. This is a
tested Ubuntu/Linux observation and does not widen the supported lifecycle
boundary described above.

A separate Linux x86_64 test-only lane now defines direct strict-verifier
resource observations. Each of four batches makes 4,287 calls on a 128 KiB
guarded pthread stack while linker interposition requires zero project heap
calls. It retains raw timing samples and compiler-specific `.su` static-frame
observations. These are not consensus, block, supported-platform, or
production limits. The separately reviewed schema-`2` policy enforces only
coarse hosted-CI gross-regression ceilings: `2,000,000,000` CPU nanoseconds and
`5,000,000,000` wall nanoseconds per batch; `8,000,000,000` CPU nanoseconds
and `20,000,000,000` wall nanoseconds across the first call plus all four
batches; `10,000,000` / `25,000,000` CPU/wall nanoseconds for the first call;
`75,000,000` / `200,000,000` CPU/wall nanoseconds for any retained verifier-batch sample; and
`65,536` KiB process peak RSS. The untimed control loop remains reported but
excluded from numeric verifier aggregation.

Protected-main push run `31520865906`, attempt `1`, supplied that exact-head
observation at `79de77faf112453868779861ae0c982dba533f84` against baseline
pointer `60e259458d1029fa4193de878f14d41a0793042d`. Its guarded diff was empty.
The GCC and Clang reports both passed independent validation and every internal
checksum; their artifact IDs and outer SHA-256 values are respectively
`9112965965` / `74063a8817bce33541d89bc655e10593507261b22ed60e99f75b7d48ae9af5a2`
and `9112975963` / `04c5c3f1283851cb93e4b0488091f74719002500d916f0e404cd14ea72d1cf0d`.
Both retain `promotion_eligible=false`. Their exact workflow/job and compiler
identities, archive/observation/report hashes, and observed maxima are frozen
as the numeric-policy basis. Because the 31 samples partition one batch rather
than 31 independent repetitions, the policy makes no percentile or statistical
performance claim and requires at least two additional protected-main samples
per compiler before tightening. Pull-request and manual observations remain
untrusted.

The numeric policy landed at
`18db91c542b51f37c2dabf198979c33d793ecddf`, and the reviewed baseline pointer
now names `1833f20ee66fe7cac9f8e41a98b07f9eab150ec7`. Automatic protected-main push
run `32419767106`, attempt `1`, applied that policy at exact clean head
`6315f49bbde6347bf09e9518e0b4ccc31347b963`; its guarded diff was empty. GCC
job `96589014091` / artifact `9425610867` and Clang job `96589013980` /
artifact `9425628829` both reported `PASS`, and all 24 internal checksums in
each artifact revalidated. Their outer SHA-256 values are respectively
`dd949cf2eff6337191973e303e7544fb5758a96fffccf8638b70b835ecc18019` and
`8d4c293fe8e334da4ad84ed745ed8f8bfcc2dc41b460d417c52cf7a842e09362`.
The GCC/Clang aggregate CPU observations were `1,692,534,302` /
`1,173,297,728` ns, aggregate wall observations were `1,692,761,746` /
`1,173,472,276` ns, and peak RSS observations were `31,780` / `31,820` KiB.
Every enforced numeric and structural check passed without current-run
threshold calibration. The versioned
[policy-enforced exact-main receipt](reviews/evidence/ml-dsa-44-trusted-main/6315f49bbde6347bf09e9518e0b4ccc31347b963/SOURCE.json)
retains the per-batch, first-call, maximum-sample, compiler, stack, and checksum
details. Each artifact remains non-promotion-eligible; only the pair with
external workflow provenance forms this bounded trusted observation. It is the
first of the two additional protected-main samples per compiler required by
the frozen policy before a ceiling-tightening review; one further pair remains.

This is implementation evidence for the admitted experiment, not a production
backend disposition. The raw-key prototype ABI, process-global serialization,
supported-platform behavior, lifecycle, compiler output, fault model, fuzzing,
exact-commit advisory re-review and human review remain unresolved. The
scheduled advisory/SBOM workflow and supplementary portable Miri lane are
described in `ML_DSA_44_ADVISORY_LEDGER.md`.

## Gates That Remain Open

Prototype admission closes no production finding:

| Gate | Tracking | State after this decision |
| --- | --- | --- |
| Entropy and fail-closed binding | #184 | isolated wrapper, Linux/macOS RBG evidence, and one coordinated standard-POSIX-fork module-lock observation; async-signal-safe child signing, alternate/reentrant fork and clone behavior, handler ordering, module lifetime, and broader supported-platform lifecycle remain open |
| Supported-platform side channels | #185 | bounded x86_64 Valgrind constant-time/variable-latency evidence; broader platforms and leakage models open |
| Fault model and injected faults | #186 | test-only pre-self-verification candidate-corruption regression with atomic output and cleanup evidence; broader checkpoints, control-flow and common-mode analysis, platform/hardware model, physical campaign, and exact-commit re-review remain open |
| End-to-end secret erasure | #187 | source cleanup and sanitizer evidence only; compiler/caller/platform boundary open |
| Structure-aware fuzzing and resource limits | #188 | pinned Wycheproof replay, scheduled structure-aware ASan/UBSan and MSan campaigns, bounded differential/stateful fuzzing, promoted regressions, portable Miri evidence, bounded malformed research-CLI argv replay, exact-main GCC/Clang direct-verifier observations, a reviewed coarse Linux x86_64 numeric regression policy, and the first of two additional policy-enforced trusted-main GCC/Clang sample pairs; one further sample pair, broader platform/Rust sanitizer and toolchain coverage, concurrency and production-parser limits, and exact-commit re-review remain open |
| Backend advisories, SBOM, and reproducible build | #189 | dated fail-closed ledger, full-lock cargo-audit/OSV scans, exact selected graph, CycloneDX SBOM, weekly retained refresh, exact portable ML-DSA-44 RUSTSEC-2026-0077 regressions, and promoted trusted-main test-only SIMD256 0125/0126 PASS evidence; exact-commit independent re-review remains open, and optimized-backend admission is a separate future decision |
| Wallet and key format | #190 | open |
| Independent human cryptographic review | #181 | open |

The current comparator, Wolfram arithmetic model, and this admission review are
AI-assisted engineering evidence. None is the independent human review required
by issue #181.

## Validation

Run the bounded decision checks with:

```bash
python3 -m unittest ci.test.test_ml_dsa_backend_admission
python3 -m unittest ci.test.test_ml_dsa_hedged_signing_contract
python3 -m unittest ci.test.test_ml_dsa_wrapper_prototype
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py --manifest-only
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py --sanitizers
python3 -m unittest discover -s ci/test -p 'test_*dsa_reference.py'
python3 contrib/ml-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/slh-dsa-ref/compare_oracles.py --manifest-only
python3 ci/test/check_ci_inventory.py
```

The wrapper commands compile only the isolated production-shaped evidence
artifact. They do not admit or link a production cryptographic backend.

## Primary Sources

- NIST FIPS 204 and potential-updates notice:
  https://csrc.nist.gov/pubs/fips/204/final
- OpenSSL 3.6 ML-DSA signature interface:
  https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-ML-DSA/
- OpenSSL 3.6 release and vulnerability status:
  https://www.openssl-library.org/news/openssl-3.6-notes/
- mldsa-native beta2 release and verification scope:
  https://github.com/pq-code-package/mldsa-native/releases/tag/v1.0.0-beta2
- mldsa-native source and soundness record:
  https://github.com/pq-code-package/mldsa-native
- libcrux ML-DSA 0.0.10 source:
  https://github.com/celabshq/libcrux/tree/libcrux-ml-dsa-v0.0.10/libcrux-ml-dsa
- RustSec libcrux-ml-dsa advisory inventory:
  https://rustsec.org/packages/libcrux-ml-dsa.html
