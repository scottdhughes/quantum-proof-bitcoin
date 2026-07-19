# ML-DSA-44 External Cryptographic Review Package

## Status: AWAITING_EXTERNAL_REVIEW - RELEASE_HOLD
## Spec-ID: ML-DSA-44-EXTERNAL-REVIEW-v1
## Prepared: 2026-07-19
## Owner: @scottdhughes
## Tracking: https://github.com/scottdhughes/quantum-proof-bitcoin/issues/181
## Consensus-Relevant: NO

## Review Decision Boundary

This package defines the input, questions, evidence, and acceptance criteria for
an external cryptographic review of PQBTC's `ML-DSA-44` engineering candidate.
It does not record a completed review and does not approve ML-DSA-44 for
production or consensus use.

The review has three bounded subjects:

1. the exact FIPS 204 profile and API semantics frozen below
2. the adequacy and limitations of the three-oracle conformance evidence
3. the cryptographic and implementation risks that a future production design
   must close

The comparator implementation baseline is PQBTC commit
`6ffd47881fc2071724fa6e31fb3cf9557a64b467`, merged on `main` by
`83c47cf6d93e07bb30d1f22f491128ac43c70176`. The reviewer must record the exact
PQBTC revision used for the review and confirm whether any of these files differ
from that baseline:

- `contrib/ml-dsa-ref/vectors.json`
- `contrib/ml-dsa-ref/compare_oracles.py`
- `contrib/ml-dsa-ref/openssl_oracle.c`
- `contrib/ml-dsa-ref/mldsa_native_oracle.c`
- `contrib/ml-dsa-ref/libcrux_oracle.rs`
- `ci/test/test_ml_dsa_reference.py`

Any substantive change to those files or to a pinned upstream artifact requires
an explicit review-delta assessment. A green review of this package does not
automatically cover later code.

## Frozen Candidate Contract

| Property | Review value |
| --- | --- |
| Standard | NIST FIPS 204 |
| Parameter set | `ML-DSA-44` |
| NIST security category | 2 |
| Interface | External |
| Message mode | Pure ML-DSA, not HashML-DSA |
| Prototype message | Exactly 32 bytes |
| Prototype context | ASCII `PQBTC/tx-signature/v1` |
| Context encoding | `0x00 || len(ctx) || ctx || message` |
| Key-generation seed | 32 bytes |
| Public key | 1,312 bytes |
| Expanded private key | 2,560 bytes |
| Signing randomizer | 32 bytes |
| Signature | 2,420 bytes |
| Exact-vector signing | Deterministic or NIST-supplied fixed `rnd` |
| Future production posture | Hedged randomized signing, if approved later |

The 32-byte prototype message is a Bitcoin-style sighash digest. The context is
a research domain-separation contract, not a consensus allocation. No public-
key commitment, witness encoding, stack exception, sighash algorithm,
descriptor, PSBT field, wallet derivation, activation rule, or `ALG_ID` is
selected by this package.

## Pinned Evidence And Provenance

`contrib/ml-dsa-ref/vectors.json` is the machine-readable source of truth. The
tables below make its review boundary visible without replacing manifest
validation.

### Standards

| Artifact | Date or status | SHA256 |
| --- | --- | --- |
| NIST FIPS 204 PDF | Final, 2024-08-13 | `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b` |
| FIPS 204 potential updates | Updated 2026-02-27; not official changes | `0e8ba77b46db71fda2c18e67111303335745a938686cad6faf35eac148f7ed3e` |
| FIPS 204 Section 6 guidance | Dated 2025-03-19 | `4a1d4b8d5aefef56069eb91bd464d5b5e177372e03bdde2541655e8e24d7a056` |

### Official ACVP Inputs

The NIST ACVP source is `usnistgov/ACVP-Server` commit
`15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`.

| File under the ACVP checkout | SHA256 |
| --- | --- |
| `ML-DSA-keyGen-FIPS204/prompt.json` | `02fad612a060bbcf3bbbd164caf7e9da964ba385c90e08bcd26516e3bf8a023d` |
| `ML-DSA-keyGen-FIPS204/expectedResults.json` | `58dca0195226491c9cb117e1f0ec4cb11d4a1e3bd8b0f955371d80c99d4e8810` |
| `ML-DSA-sigGen-FIPS204/prompt.json` | `4305197be3c17be8f99338086eb8033ff2400f7d5b816123fc28b184c6e77a55` |
| `ML-DSA-sigGen-FIPS204/expectedResults.json` | `7b70ffeba6efe24e90760c751a7ebc4907931600645ebfa3f8a2459164d0a95d` |
| `ML-DSA-sigVer-FIPS204/prompt.json` | `2a9b7fcbefdd8e69dd6fbe6b4abb7130d855e8429aaa6f4904385e68b7e63d3a` |
| `ML-DSA-sigVer-FIPS204/expectedResults.json` | `33e0ea7dd9c3b0206712da50286ad746864371433977225ab77e8aae76358842` |

Each path above is rooted at `gen-val/json-files/`. The selected external/pure
ML-DSA-44 tranche contains 25 key-generation, 30 signature-generation, and 15
signature-verification cases, for 70 cases total.

### Oracle Sources

| Oracle | Frozen source | Role and limitation |
| --- | --- | --- |
| OpenSSL | Version 3.6.3, commit `aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f` | Separate provider oracle; not a proposed node dependency |
| `mldsa-native` | Tag `v1.0.0-beta2`, commit `9b0ee84f4cf399043eca59eca4e5f8531ca1d61b` | Portable C; forked from PQ-Crystals, so not independent design |
| libcrux | `libcrux-ml-dsa-v0.0.10`, commit `c5fb80f37530ee9b2df9501ae5ff8cb4a973a4bd` | Portable Rust with separate implementation history and disclosed reference influence |

The libcrux annotated tag object is
`255922337dee37aa32b21dbed27785f535de0336`, its ML-DSA source tree is
`0044b70c4675ba97623c9105387f592e038e837d`, and its initial implementation
commit is `3f14979a2b30c43572bd81fae64cc4743943b5da`. The exact crates.io archive
`libcrux-ml-dsa-0.0.10.crate` has SHA256
`783ebed7cb27de6d44ef2aa662648d1a0869694f2f754f2f1ed45e959ef3b48e`.

The libcrux assessment is
`separate_implementation_lineage_with_reference_influence`. Its normal
dependency graph contains no PQClean, PQ-Crystals, `mldsa-native`, or
`pqcrypto-mldsa` dependency, but unit-test outputs and selected implementation
comments cite PQ-Crystals. This is independent implementation evidence, not
independent design or external cryptographic review.

### Expected Output Hashes

| Output | SHA256 |
| --- | --- |
| NIST keygen group 1 case 1 private key | `0196ccbde5fbd1804e8c784efb83998338076d586fe73ee07ba712ccc9fc32c2` |
| NIST keygen group 1 case 1 public key | `451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34` |
| NIST deterministic siggen group 1 case 1 signature | `f2554d7153750b4deed79f80e5aa237a219fc92f83e59e7317c8d2089c4e7b91` |
| NIST randomized siggen group 13 case 181 signature | `8a17b6ff3f9633cd3c7cd0687d6384408e145bfd3725f6c57a8a2727f50ec989` |
| PQBTC prototype public key | `451a808c522218fadbdab146fc12004b0741c7d069f238f43ad77216159f6a34` |
| PQBTC prototype deterministic signature | `98094b39d9ae1ad76fc734f9e0199ad37315dd4eb7a22f29561582239f64e131` |

## Reproduction Contract

Record the host OS, architecture, compiler, Rust/Cargo, installed OpenSSL, and
exact PQBTC revision. First run the repository-only checks:

```bash
git rev-parse HEAD
git diff --exit-code 6ffd47881fc2071724fa6e31fb3cf9557a64b467 -- \
  contrib/ml-dsa-ref ci/test/test_ml_dsa_reference.py
python3 contrib/ml-dsa-ref/compare_oracles.py --manifest-only
python3 -m unittest ci.test.test_ml_dsa_reference
```

The expected manifest output is exactly:

```text
ML-DSA-44 reference manifest validation passed
```

Obtain the three NIST artifacts and clean, full-history upstream checkouts at
the pins above. Obtain the exact libcrux crate archive independently. Then run:

```bash
python3 contrib/ml-dsa-ref/compare_oracles.py \
  --acvp-server /path/to/pinned/ACVP-Server \
  --openssl-source /path/to/pinned/openssl \
  --mldsa-native /path/to/pinned/mldsa-native \
  --libcrux-source /path/to/full-history/pinned/libcrux \
  --libcrux-crate /path/to/libcrux-ml-dsa-0.0.10.crate \
  --fips204 /path/to/NIST.FIPS.204.pdf \
  --fips204-updates /path/to/fips-204-potential-updates.xlsx \
  --fips204-section6-guidance /path/to/fips204-sec6-03192025.pdf \
  --benchmark-iterations 10 \
  --sanitizers > ml-dsa-44-review-run.json
sha256sum ml-dsa-44-review-run.json
```

On macOS, use `shasum -a 256` for the final report if `sha256sum` is absent.
The report must contain `"status": "PASS"`, 70 ACVP cases, the three expected
signature hashes above, and `PASS` for every entry under `checks`, including
`adapter_asan_ubsan`. The two disclosed libcrux advisory regressions and both
repo-defined malformed-hint regressions must pass.

The complete report has no universal expected SHA256 because it contains host-
specific benchmark values. The run also exercises fresh randomized-signing
outputs, but intentionally records only their counts after diversity and cross-
verification pass. The reviewer must publish the checksum of their own report,
retain the report as a review artifact, and compare the invariant hashes and
pass fields above.

## Threat Model

This is a prospective cryptographic threat model. No ML-DSA code is connected
to PQBTC consensus, Script, wallet, or node runtime today. Impact ratings assume
a future real-value deployment; the current repository state remains research
only.

### Assets

- unforgeability of spends authorized by an ML-DSA key
- confidentiality and integrity of the 32-byte seed, expanded signing key, and
  ephemeral signing state
- canonical agreement among all verifiers on every public key and signature
- signer and node availability under adversarial input and repeated use
- integrity of standards, vectors, source pins, dependencies, and build outputs

### Trust Boundaries

1. wallet seed and derivation state into the signing implementation
2. operating-system or hardware entropy into hedged randomized signing
3. untrusted transaction, public-key, context, and signature bytes into parsing
   and verification
4. high-level ML-DSA operations into arithmetic backends, compiler output, and
   CPU-specific code
5. pinned upstream artifacts into the local evidence build
6. research evidence into a later protocol and production decision

### Attacker Capabilities And Assumptions

Assume a remote attacker can choose messages, public keys, signatures, contexts,
and transaction volume; solicit many signatures from a reused key; and observe
remote timing. Treat co-resident cache observation, malicious dependencies,
entropy degradation, and malformed-input fuzzing as realistic. Treat power,
electromagnetic, glitch, and fault injection as realistic for a future hardware
signer and conditional for a general-purpose host.

Do not assume that ACVP conformance, three-way byte agreement, formal
verification of selected arithmetic, or sanitizer success proves side-channel
safety or construction security. The package assumes no current production
deployment. If real funds or external users depend on ML-DSA code, the review
scope and disclosure process must be reassessed immediately.

### Priority Abuse Paths

| ID | Abuse path | Prospective impact | Evidence or control today | Open review question |
| --- | --- | --- | --- | --- |
| T1 | Profile, domain, or context mismatch allows cross-protocol signing or verifies a different message | Forged or replayed spend | Exact external/pure context contract and official vectors | Is the binding correct and misuse-resistant for Bitcoin sighashes? |
| T2 | Rejection sampling, arithmetic, or encoding defect biases signatures or exposes the key | Key recovery or forgery | Three-oracle exact agreement and 70 ACVP cases | Are distribution, bounds, and all reject conditions correct? |
| T3 | Failed, repeated, attacker-influenced, or silently downgraded `rnd` defeats hedged signing | Key exposure or weaker-than-stated security | Randomized APIs and diversity tests only | What entropy contract and failure behavior are mandatory? |
| T4 | Non-canonical or malformed key, hint, or signature handling differs across implementations | Consensus divergence, memory corruption, or denial of service | Exact-length gates, mutations, advisory and malformed-hint regressions | Are all encodings strict and every failure path uniform? |
| T5 | Timing, cache, power, electromagnetic, or branch leakage exposes secret-dependent sampling or arithmetic | Key recovery after repeated signatures | No production constant-time claim | Which paths leak and what platform-specific evidence is required? |
| T6 | Fault injection or skipped checks creates exploitable faulty signatures or leaks secret state | Key recovery or unauthorized signing | No production fault design | Is sign-then-verify sufficient, and which internal checks are required? |
| T7 | Seeds, expanded keys, sampled vectors, or temporary buffers survive in memory, swap, crash output, or logs | Secret disclosure | Research adapters provide no erasure contract | What must be erased, when, and with which compiler guarantees? |
| T8 | Malicious or drifted upstream source creates false three-oracle confidence | Compromised evidence or future implementation | Exact commits, artifact hashes, lineage audit | Are provenance and implementation independence adequate? |
| T9 | Pathological verification input or block composition exhausts CPU, memory, or parser resources | Node or network denial of service | Bounded single-operation measurements only | What are the worst cases and safe aggregate limits? |
| T10 | Seed derivation, backup, import, or hardware-signer interpretation diverges | Permanent fund loss or wrong keys | No wallet contract selected | Which FIPS-compatible key representation and recovery checks are safe? |

## Required Review Questions

The report must answer each question with `PASS`, `FINDING`, `LIMITATION`, or
`NOT_APPLICABLE`, plus evidence.

### Standard And API

1. Does the frozen contract implement final FIPS 204 external, pure
   `ML-DSA-44`, including context construction and all relevant potential-update
   corrections?
2. Is signing a 32-byte Bitcoin sighash as the pure-ML-DSA message sound, and is
   `PQBTC/tx-signature/v1` sufficient domain separation without creating a
   hidden prehash or external-`mu` ambiguity?
3. Are key generation from a 32-byte seed, expanded-key reconstruction, and
   public-key derivation represented without non-standard assumptions?
4. Are deterministic vectors and future hedged randomized production signing
   separated clearly enough to prevent deterministic signing from becoming an
   accidental production default?

### Construction And Encoding

5. Are sampling distributions, rejection conditions, norm checks, NTT and
   modular arithmetic, decomposition, hint creation, and hint use correct for
   ML-DSA-44?
6. Are public keys and signatures parsed at exact lengths with canonical
   coefficient and hint encodings, no ignored trailing data, no alternate
   encodings, and no implementation disagreement on malformed values?
7. Does the mutation and malformed-input corpus cover the highest-risk decoder
   states, including the failure modes behind `RUSTSEC-2026-0076` and
   `RUSTSEC-2026-0077`? What fuzzing or proof obligations remain?
8. Does the three-oracle methodology provide adequate implementation
   independence, or are there material common-mode assumptions not captured by
   the recorded lineage limits?

### Signing Security

9. Which key-generation and signing operations are secret-dependent in time,
   branches, memory access, allocation, or rejection count on each candidate
   implementation path?
10. What entropy source, health checks, error propagation, rollback behavior,
    and deterministic fallback policy are required for hedged signing?
11. Which realistic fault attacks can expose the key or create exploitable
    signatures, and which recomputation, verification, or redundancy controls
    are required?
12. Which seed, expanded-key, intermediate polynomial, randomizer, and temporary
    buffers require erasure, and can the compiler and runtime provide the
    required guarantee?

### Bitcoin And Operational Implications

13. Does repeated signing under a long-lived wallet key create side-channel,
    fault, or operational risks not represented by the one-shot harness?
14. Which strict-verification and resource properties must a future consensus
    design freeze before implementation, including behavior for every malformed
    public key and signature?
15. What constraints must seed backup, import, deterministic derivation, PSBT,
    external signer, and hardware-wallet designs satisfy to avoid key mismatch
    or silent security downgrade?
16. Is any reviewed oracle a defensible basis for a later production
    implementation? If not, state the required implementation strategy and
    evidence rather than selecting one by benchmark speed.

## Reviewer Independence And Qualifications

The review may be performed by one reviewer or a team. Collectively they must
show:

- demonstrated ML-DSA or structured-lattice cryptography expertise
- implementation-review experience in constant-time arithmetic, parsing,
  randomness, fault resistance, and secret lifecycle
- enough C, Rust, OpenSSL-provider, and build-system expertise to evaluate the
  evidence paths they opine on
- independence from PQBTC authorship and disclosure of employment, funding,
  prior upstream contributions, and other material conflicts

An author or maintainer of one oracle may provide useful specialist input but
cannot be the sole independent reviewer of that oracle. Automated analysis may
support the review but cannot satisfy the external-review gate by itself.

## Deliverables

The reviewer must provide:

1. reviewer identity, qualifications, independence statement, and review dates
2. exact PQBTC commit, upstream pins, toolchain, OS, and architecture
3. the complete three-oracle JSON report and its SHA256
4. a question-by-question response to all 16 required questions
5. findings with severity, evidence, affected code or contract, exploit or
   failure preconditions, recommendation, and confidence
6. an explicit list of limitations, unreviewed surfaces, and residual risks
7. one conclusion: `REVIEW_GATE_PASS`, `REMEDIATE_AND_REREVIEW`, or
   `REJECT_ENGINEERING_CANDIDATE`

Every finding must have one disposition: `OPEN`, `REMEDIATED`, `ACCEPTED_RISK`,
or `NOT_APPLICABLE`. Remediated findings require reviewer verification against
an exact follow-up commit. The report or a stable public link and its checksum
must be attached to issue `#181`; separate remediation issues must be linked
from it.

## Severity And Gate Rules

| Severity | Meaning for a future real-value deployment |
| --- | --- |
| Critical | Credible forgery, key recovery, consensus divergence, or fundamental candidate invalidation with practical or broad exploitation |
| High | Plausible key compromise, signature-security failure, memory-safety failure, or consensus denial of service under realistic but narrower preconditions |
| Medium | Bounded correctness, side-channel, fault, parser, entropy, erasure, or availability gap that must be resolved or explicitly accepted before consensus design |
| Low | Defense-in-depth, maintainability, test, or documentation weakness with no direct security failure shown |
| Informational | Observation or future-design advice with no finding |

`REVIEW_GATE_PASS` requires all required questions to be answered, no unresolved
Critical or High finding, and a tracked remediation or explicit justified
acceptance for every Medium finding. A Critical or High finding yields
`REMEDIATE_AND_REREVIEW` unless it invalidates the candidate, in which case use
`REJECT_ENGINEERING_CANDIDATE`.

Passing this gate authorizes only the separate supported-platform and worst-case
block-validation measurement slice. It does not authorize production code,
consensus design, or removal of `RELEASE_HOLD`.

## Known Limitations And Non-Goals

- None of the three oracles is selected or approved as a node dependency.
- Selected libcrux arithmetic and serialization have formal-verification
  evidence; the complete high-level implementation, compiler output, and side-
  channel behavior do not.
- The C sanitizer tranche is bounded. There is no exhaustive fuzzing, Rust
  sanitizer coverage, production parser, or resource-exhaustion campaign.
- The research wrappers use POSIX `/dev/urandom`; they are not a node, wallet,
  hardware-signer, or entropy-failure design.
- Existing timings are directional arm64 measurements, not supported-platform
  envelopes or worst-case block-validation results.
- Public-key commitment, witness encoding, fee policy, stack limits, wallet and
  backup behavior, algorithm agility, activation, migration, and testnet soak
  remain unfrozen.
- This package does not review or rehabilitate the held `PQSig rc2`
  implementation.

## Next Gate

Issue `#181` remains open until the deliverables and gate rules above are met.
After review intake:

1. remediate and obtain re-review for any blocking finding
2. record the accepted report, checksum, findings, and residual risks in the
   repository
3. run a separate supported-platform and worst-case block-validation benchmark
   slice
4. write a consensus-design specification only if both gates pass

Production remains on `RELEASE_HOLD`. No `ALG_ID`, Script, wallet, node, or
inventory-policy change belongs in this review package.
