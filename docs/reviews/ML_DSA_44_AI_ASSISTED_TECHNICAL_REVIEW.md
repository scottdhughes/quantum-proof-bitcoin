# ML-DSA-44 AI-Assisted Technical Review

**Repository:** `scottdhughes/quantum-proof-bitcoin`
**Tracking issue:** [#181](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/181)
**Review pull request:** [#183](https://github.com/scottdhughes/quantum-proof-bitcoin/pull/183)
**Review date:** 2026-07-19
**Conclusion:** `REMEDIATE_AND_REREVIEW`
**Qualified independent-human gate:** **NOT SATISFIED**
**Production/consensus status:** `RELEASE_HOLD`

## Reviewer disclosure and boundary

This assessment was performed by **GPT-5.6 Pro**, an OpenAI AI system, using the repository owner's connected GitHub account and public primary sources. It is an AI-assisted technical review, not a signed opinion by a named independent human cryptographer. It cannot supply the human identity, qualifications, employment/funding, prior-contribution, or conflict disclosures required by the review package.

The package expressly states that automated analysis may support, but cannot itself satisfy, the external-review gate. This report therefore records reproducibility evidence, answers all 16 required questions, classifies findings, and opens remediation issues. It **does not** close #181, authorize production or consensus use, approve any oracle as a dependency, or remove `RELEASE_HOLD`.

## Executive assessment

The frozen ML-DSA-44 research candidate has strong functional-conformance evidence. A clean pinned run reproduced all 70 selected NIST ACVP cases, exact deterministic and fixed-randomizer signatures, cross-oracle verification, randomized interoperability, strict-length and mutation rejection, malformed-hint regressions, and bounded ASan/UBSan smoke coverage. Every machine-enforced comparator check passed.

No present practical forgery, key-recovery defect, memory-safety defect, or verifier disagreement was identified in the frozen research profile. No Critical or High finding is stated.

Seven Medium findings remain open: production entropy/failure semantics; side-channel assurance; fault resistance; secret erasure; structure-aware fuzzing and resource limits; backend-specific advisory accounting; and the wallet/key/serialization contract. The candidate remains viable for research, but the correct gate disposition is **`REMEDIATE_AND_REREVIEW`**.

## Scope, revisions, and pins

| Item | Exact value |
| --- | --- |
| Frozen cryptographic baseline | `6ffd47881fc2071724fa6e31fb3cf9557a64b467` |
| Main reviewed for package status | `6cff49f33768993d6652b3d22dd5330c64e64c7f` |
| Reproduction workflow head | `7f618aa2c9a57665cd93c4b90ce704dd4b63651d` |
| Reproduction run | [29698982348](https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/29698982348) |
| NIST ACVP Server | `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0` |
| OpenSSL 3.6.3 | `aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f` |
| mldsa-native `v1.0.0-beta2` | `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b` |
| libcrux-ml-dsa 0.0.10 | `c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd` |

The workflow fails if any frozen comparator input differs from the baseline. It verifies exact Git pins, selected source hashes, the libcrux crate hash, and the manifest-pinned FIPS 204, potential-updates, and Section 6 guidance artifacts.

The reviewed profile is final FIPS 204 external, pure ML-DSA-44. The prototype signs exactly one 32-byte Bitcoin-style sighash as the message with context `PQBTC/tx-signature/v1`. Sizes are seed 32 bytes, public key 1,312 bytes, expanded signing key 2,560 bytes, randomizer 32 bytes, and signature 2,420 bytes. Deterministic or caller-fixed `rnd` is limited to evidence generation; the stated future posture is hedged randomized signing.

## Reproduction record

```text
pqbtc_commit=7f618aa2c9a57665cd93c4b90ce704dd4b63651d
event_name=pull_request
github_ref=refs/pull/183/merge
review_head_ref=review/ml-dsa-44-ai-assisted-assessment
review_base_ref=main
runner_os=Linux runnervm3jd5f 6.17.0-1020-azure #20~24.04.1-Ubuntu SMP Fri Jun 19 20:09:14 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
cc=cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
rustc=rustc 1.97.0 (2d8144b78 2026-07-07)
cargo=cargo 1.97.0 (c980f4866 2026-06-30)
openssl=OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)
python=Python 3.12.3
```

Retained evidence:

- [`ml-dsa-44-review-run.json`](evidence/ml-dsa-44-review-run.json)
- [`ml-dsa-44-review-run.sha256`](evidence/ml-dsa-44-review-run.sha256)
- [`ml-dsa-44-review-toolchain.txt`](evidence/ml-dsa-44-review-toolchain.txt)

**JSON SHA-256:** `661bb132d97c6fee227ca49362aa3485cd1ff210898daa7864c96fb411df9b6d`

| Reproduced evidence | Result |
| --- | --- |
| Comparator status | `PASS` |
| ACVP keygen / siggen / sigver | 25 / 30 / 15; total 70 |
| Boundary / cryptographic / malformed rejections | 2 / 12 / 34 |
| Sanitized boundary / cryptographic / malformed rejections | 2 / 12 / 24 |
| Randomized default / fixed-`rnd` interoperability | 6 / 2 rounds |
| All 12 comparator checks | `PASS` |
| Deterministic signature SHA-256 | `f2554d7153750b4deed79f80e5aa237a219fc92f83e59e7317c8d2089c4e7b91` |
| Randomized-vector signature SHA-256 | `8a17b6ff3f9633cd3c7cd0687d6384408e145bfd3725f6c57a8a2727f50ec989` |
| PQBTC prototype signature SHA-256 | `98094b39d9ae1ad76fc734f9e0199ad37315dd4eb7a22f29561582239f64e131` |

The benchmark medians in the JSON are directional single-runner measurements only. They are not a production-backend selection criterion.

## Findings

### F-01 — Production hedged-signing entropy and failure contract is absent

**Severity/Disposition/Confidence:** Medium / OPEN / High
**Affected contract:** future production signer; research CLI adapters must not become production APIs.
**Evidence:** documents distinguish vector signing from future hedging, but adapters expose deterministic and fixed-`rnd` commands; research paths use `/dev/urandom` or provider randomness; no project-owned DRBG, health/reseed, fork/snapshot, concurrency, or fail-closed contract exists.
**Preconditions/impact:** accidental deterministic default, silent entropy downgrade, repeated/attacker-influenced `rnd`, or inconsistent error handling can defeat the intended hedging. Deterministic ML-DSA is not itself alleged broken.
**Recommendation:** generate `rnd` internally; fail atomically on every entropy error; prohibit production fallback to zeros/deterministic mode; isolate test/CAVP fixed-`rnd`; add injected failure, fork, snapshot, restart, and concurrent-caller tests.
**Tracking:** [#184](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/184).

### F-02 — Supported-platform side-channel and repeated-signing assurance is absent

**Severity/Disposition/Confidence:** Medium / OPEN / High that the evidence gap exists; no practical exploit claimed.
**Affected code:** every proposed backend/compiler/optimization/CPU and hardware-signer path.
**Evidence:** mldsa-native and libcrux contain meaningful constant-time/declassification intent, but the package has no optimized-binary review, dudect/ctgrind/cache campaign, remote-timing analysis, TVLA, power, or EM evidence. Signing rejection behavior is observable and justified only at source level.
**Preconditions/impact:** repeated attacker-chosen signing under a long-lived key can amplify small leakage; feasibility depends on platform and attacker proximity.
**Recommendation:** freeze supported builds; map secret-bearing operations and approved declassifications; inspect assembly; run software leakage tests and appropriate hardware TVLA/power/EM testing; analyze rejection-count distributions; retain regression artifacts.
**Tracking:** [#185](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/185).

### F-03 — Fault model and validated fault controls are absent

**Severity/Disposition/Confidence:** Medium / OPEN / High that the design gap exists.
**Affected code:** future software and hardware signers.
**Evidence:** adapters self-verify generated signatures, which is useful but does not cover skipped or common-mode verification, persistent key corruption, corrupted entropy, control-flow faults, bypassed rejection checks, or faults in NTT/constants.
**Preconditions/impact:** platform-dependent faults can produce invalid or information-bearing outputs; published Dilithium-family work demonstrates that nonce/domain and NTT fault classes are realistic on physical targets.
**Recommendation:** define per-platform fault models; make verification atomic and mandatory; add key consistency/integrity controls, diversified or redundant checks where justified, deterministic fault injection, and explicit physical residual-risk treatment.
**Tracking:** [#186](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/186).

### F-04 — End-to-end secret erasure and key-lifecycle guarantees are absent

**Severity/Disposition/Confidence:** Medium / OPEN / High.
**Affected code:** adapters, selected upstream wrapper, FFI/provider boundaries, future wallet/signer integration.
**Evidence:** C adapters use ordinary heap/stack buffers and normal `free`/return for caller-owned seed, expanded key, and randomizer copies; the reviewed libcrux signing-key wrapper is clonable raw bytes without an evident zeroizing `Drop`; mldsa-native wipes many internals but not adapter/FFI copies. Research keygen intentionally prints expanded private keys.
**Preconditions/impact:** memory disclosure, local access, swap/hibernation, core dumps, crash telemetry, logs, or duplicated buffers can expose the full signing key.
**Recommendation:** project-owned secret types, restricted cloning, compiler-resistant zeroization on every exit, FFI ownership rules, optimized-output verification, memory/core-dump/logging policy, and injected-failure cleanup tests.
**Tracking:** [#187](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/187).

### F-05 — Malformed-input, differential-fuzzing, and resource evidence is too narrow

**Severity/Disposition/Confidence:** Medium / OPEN / High.
**Affected code:** verification/parsing paths, adapters, and any later consensus verifier.
**Evidence:** the bounded corpus covers exact lengths, context boundaries, selected mutations, malformed commands, and two hint regressions, with C ASan/UBSan smoke coverage. It is not structure-aware or coverage-guided and does not comprehensively exercise coefficient/hint states, malicious public keys, Rust sanitizer/Miri behavior, allocation failure, stack limits, timeouts, or aggregate verification.
**Preconditions/impact:** arbitrary network inputs can expose backend disagreement, crash, non-canonical acceptance, resource exhaustion, or consensus divergence.
**Recommendation:** structure-aware generators/mutators, multi-backend differential fuzzing, current advisory corpora, C/Rust dynamic analysis, minimized retained corpora, and explicit per-operation and aggregate resource limits.
**Tracking:** [#188](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/188).

### F-06 — Advisory coverage is incomplete and not backend/architecture specific

**Severity/Disposition/Confidence:** Medium / OPEN / High.
**Affected contract:** provenance reporting and future optimized-backend admission.
**Evidence:** libcrux 0.0.10 portable passes hard-coded regressions for RUSTSEC-2026-0076/0077. Current RustSec also lists AVX2/x86-64 RUSTSEC-2026-0125/0126, fixed in 0.0.9. The portable 0.0.10 path is not shown vulnerable, but the package-wide `libcrux_disclosed_advisory_regressions: PASS` label does not record them as fixed-by-version/not exercised, and the workflow lacks a current all-dependency advisory scan. OpenSSL 3.6.3 contains the prior CLI truncation fix; the adapter uses EVP, not the affected `openssl dgst` path.
**Preconditions/impact:** backend changes or new advisories can silently invalidate assurance; this is not an active-vulnerability claim against the frozen paths.
**Recommendation:** dated per-backend/per-architecture inventory with `PASS`/`NOT_APPLICABLE`/`UNTESTED`; current cargo-audit/OSV/upstream scans; 0125/0126 regressions before AVX2 admission; scheduled refresh.
**Tracking:** [#189](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/189).

### F-07 — Wallet, key representation, derivation, and serialization contract is unfrozen

**Severity/Disposition/Confidence:** Medium / OPEN / High.
**Affected contract:** future wallet, hardware signer, descriptor/PSBT, and consensus design.
**Evidence:** the prototype uses standardized sizes and deterministic seed reconstruction; NIST's current FAQ permits the key-generation seed as an alternative private-key representation if standardized outputs are regenerated. No canonical persisted format, derivation domain, import consistency rule, public-key commitment, descriptor/PSBT format, hardware protocol, backup semantics, network/version binding, algorithm agility, migration, or aggregate limit is selected.
**Preconditions/impact:** divergent seed/expanded-key treatment can lose funds or mismatch keys; ambiguous domain/version binding can cause cross-domain misuse; unfrozen encoding/resource rules can become consensus defects.
**Recommendation:** independently review a versioned design specification with exact bytes, derivation/recovery checks, canonical rejection, hardware boundaries, algorithm/network/version binding, rotation/migration, and resource/fee limits before implementation.
**Tracking:** [#190](https://github.com/scottdhughes/quantum-proof-bitcoin/issues/190).

## Required review questions

1. **Final FIPS 204 external/pure profile and potential updates — `LIMITATION`.** Lengths, context handling, ACVP data, artifact hashes, and three-oracle results align. The exact workbook is pinned, but this assessment did not independently adjudicate every workbook row; no tested conflict was found.
2. **32-byte Bitcoin sighash and context — `PASS`.** The sighash bytes are the pure-ML-DSA message, not HashML-DSA or external `mu`; the context separates the prototype. A later protocol must freeze sighash, algorithm, version, network, and context semantics.
3. **32-byte seed, expanded-key reconstruction, and public-key derivation — `PASS`.** Exact outputs agree with ACVP/oracles, and NIST permits seed representation subject to deterministic standardized regeneration. Wallet semantics remain F-07.
4. **Separation of deterministic vectors from hedged production signing — `FINDING`.** Documentation is clear, but no misuse-resistant production API/build boundary or fail-closed entropy contract exists. F-01.
5. **Sampling, rejection, norms, NTT, decomposition, and hints — `PASS`.** The 70 ACVP cases, exact signatures, three-way agreement, randomized verification, and hint regressions provide strong functional evidence; not a full proof or leakage/fault assessment.
6. **Exact/canonical public-key and signature parsing — `PASS`.** Tested paths enforce exact sizes and reject truncated, extended, mutated, and structured malformed values consistently. Untested state/resource space remains F-05.
7. **Highest-risk decoder states and advisory regressions — `FINDING`.** 0076/0077 pass, but structure-aware fuzzing, optimized-backend regressions, wider current advisories, Rust dynamic analysis, and resource testing remain. F-05/F-06.
8. **Three-oracle independence — `LIMITATION`.** Strong differential conformance evidence, not independent design validation: mldsa-native has PQ-Crystals lineage; libcrux is separate with reference influence; common specification/vector/compiler/hardware assumptions remain.
9. **Secret-dependent timing, branches, memory, allocation, and rejection count — `FINDING`.** Security-sensitive signing paths and declassifications lack supported-platform binary/leakage evidence. F-02.
10. **Entropy source, health checks, rollback, error propagation, and fallback — `FINDING`.** Internal suitable RBG/CSPRNG use, fail-closed behavior, no deterministic fallback, fork/snapshot/concurrency handling, and test-only fixed-`rnd` are mandatory. F-01.
11. **Fault attacks and controls — `FINDING`.** Entropy/nonce, NTT, norm/rejection, key-memory, and control-flow faults matter; self-verification alone is insufficient. F-03.
12. **Secret erasure — `FINDING`.** Seed, expanded key, secret polynomial forms, `rnd`, mask state, and every caller/FFI copy need compiler-resistant lifecycle controls not established here. F-04.
13. **Repeated signing under a long-lived wallet key — `FINDING`.** It amplifies leakage, fault opportunity, entropy/rollback failure, persistent-memory exposure, and misuse. F-01 through F-04.
14. **Consensus strictness and resources — `FINDING`.** Freeze exact lengths, canonical encodings, all malformed behavior, backend equivalence, no panic/partial result, and bounded per-operation/aggregate CPU, memory, stack, and allocation. F-05/F-07.
15. **Backup, import, derivation, PSBT, external signer, and hardware wallet — `FINDING`.** Require canonical representation, regeneration/public-key checks, algorithm/network/version-separated derivation, safe import/export, backup interoperability, authenticated hardware boundaries, no signing-mode downgrade, and migration rules. F-07.
16. **Production basis — `LIMITATION`.** No oracle is approved today. A later implementation should place a project-owned strict API around one deliberately selected, pinned, audited backend; initially prefer a portable path; prohibit the research CLIs; and admit optimized paths only after advisory, leakage, fault, fuzzing, lifecycle, and platform evidence. Speed is not the selection criterion.

## Limitations and residual risk

No qualified independent human has adopted this report. The potential-updates workbook was provenance-checked, not adjudicated row by row. No full formal proof, compiler equivalence proof, supported-platform timing/cache test, physical leakage or fault campaign, long-duration fuzzing, Rust sanitizer/Miri campaign, allocation-failure study, or worst-case aggregate block-validation campaign was performed. No node, Script, wallet, descriptor, PSBT, hardware-signer, activation, migration, or policy design is frozen. Advisory status is time-sensitive. This report does not rehabilitate `PQSig rc2`.

## Gate disposition

Functional evidence supports continuing ML-DSA-44 as an engineering candidate. It does not support selecting a production dependency or beginning consensus implementation. Seven Medium findings are open, the human-independence requirement is unmet, and the separate supported-platform/worst-case gate has not run.

> **`REMEDIATE_AND_REREVIEW`**

Issue #181 must remain open and `RELEASE_HOLD` must remain in force. After remediation, a qualified independent human reviewer should verify exact follow-up commits, refresh standards/advisories, reproduce the evidence, provide identity/qualification/independence disclosures, and issue the actual gate disposition.

## Primary sources

- [NIST FIPS 204 publication](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 204 PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [NIST PQC FIPS FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs)
- [NIST Section 6 guidance](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/faq/fips204-sec6-03192025.pdf)
- [OpenSSL 3.6 vulnerability list](https://www.openssl-library.org/news/vulnerabilities-3.6/)
- [RustSec 0076](https://rustsec.org/advisories/RUSTSEC-2026-0076.html), [0077](https://rustsec.org/advisories/RUSTSEC-2026-0077.html), [0125](https://rustsec.org/advisories/RUSTSEC-2026-0125.html), and [0126](https://rustsec.org/advisories/RUSTSEC-2026-0126.html)
- [IACR ePrint 2018/211](https://eprint.iacr.org/2018/211) and [IACR ePrint 2022/824](https://eprint.iacr.org/2022/824)
