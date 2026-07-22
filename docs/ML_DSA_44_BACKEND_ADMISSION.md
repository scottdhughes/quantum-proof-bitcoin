# ML-DSA-44 Backend Admission

## Status: ISOLATED_PROTOTYPE_IMPLEMENTED - RELEASE_HOLD
## Spec-ID: ML-DSA-44-BACKEND-ADMISSION-v1
## Decided: 2026-07-19
## Evidence-Updated: 2026-07-21
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
the retained upstream 0076/0077 tests are explicitly labeled ML-DSA-65, and an
exact ML-DSA-44 0077 regression remains untested. The AVX2-specific 0125/0126
regressions block any future SIMD256 admission. This is useful evidence, not a
reason to prefer a wider integration boundary for the first prototype.

## Frozen Prototype Build Contract

The implemented wrapper uses the exact source pin in `backend_admission.json`
and is required to preserve all of these conditions:

1. compile only ML-DSA-44 and the portable C arithmetic/FIPS 202 paths;
2. use one translation unit and mark upstream APIs `static`;
3. disable SUPERCOP aliases and export only a project-owned hedged-signing
   wrapper plus the strict verification operation needed for self-checking;
4. set the signing-attempt bound to `814` and return no partial result when it
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
zeroization-hook execution, concurrent repeat rejection, and ASan/UBSan.

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
| Entropy and fail-closed binding | #184 | isolated wrapper and Linux/macOS RBG evidence; supported-platform lifecycle remains open |
| Supported-platform side channels | #185 | bounded x86_64 Valgrind constant-time/variable-latency evidence; broader platforms and leakage models open |
| Fault model and injected faults | #186 | open |
| End-to-end secret erasure | #187 | source cleanup and sanitizer evidence only; compiler/caller/platform boundary open |
| Structure-aware fuzzing and resource limits | #188 | pinned Wycheproof replay, scheduled structure-aware ASan/UBSan and MSan campaigns, bounded differential fuzzing, and supplementary portable Miri evidence; stateful/adversarial resource limits and broader production coverage remain open |
| Backend advisories, SBOM, and reproducible build | #189 | dated fail-closed ledger, full-lock cargo-audit/OSV scans, exact selected graph, CycloneDX SBOM, and weekly retained refresh implemented; exact-commit independent re-review remains open |
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
