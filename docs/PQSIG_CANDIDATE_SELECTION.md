# PQBTC Signature Candidate Selection

## Status: ML_DSA_44_ENGINEERING_CANDIDATE - RELEASE_HOLD
## Spec-ID: PQSIG-CANDIDATE-SELECTION-v1
## Decided: 2026-07-18
## Evidence-Updated: 2026-07-19
## Consensus-Relevant: NO

## Decision

Select FIPS 204 `ML-DSA-44` as PQBTC's primary engineering candidate for the
next isolated evidence and protocol-design work. Retain FIPS 205
`SLH-DSA-SHA2-128s` as the conservative fallback and reference baseline.

The explicit selection outcome is:

`ML_DSA_44_ENGINEERING_CANDIDATE`

This is not production approval. The `RELEASE_HOLD` in
`PQSIG_PRODUCTION_READINESS.md` remains controlling. This record does not add
an implementation to the node, allocate an `ALG_ID`, change Script, modify a
wallet path, or change the consensus accepted set.

## Scope And Evidence Boundary

This decision compares two isolated, final-standard reference profiles:

- `ML_DSA_44_REFERENCE.md`
- `SLH_DSA_SHA2_128S_REFERENCE.md`

Both reference harnesses have official ACVP coverage, deterministic and
randomized interoperability evidence, malformed-input tests, bounded
sanitizer coverage, and directional arm64 macOS measurements. Those results
establish reproducible prototype behavior. They do not establish production
implementation quality, acceptable consensus resource bounds, side-channel
resistance, or independent cryptographic review.

The choice is therefore an engineering-priority decision. It is not a claim
that ML-DSA is cryptographically superior to SLH-DSA or ready to protect real
value.

## Official Standards Refresh

The official-source boundary was refreshed on 2026-07-18. Downloaded static
artifacts were identified as PDF or XLSX files before hashing.

| Artifact | Status | SHA256 |
| --- | --- | --- |
| FIPS 204 PDF | Final, 2024-08-13 | `57239b9f84c03227eda3ca0991204dc7764c79af9ce2e6824eda774918d46b6b` |
| FIPS 204 potential updates | Updated 2026-02-27 | `0e8ba77b46db71fda2c18e67111303335745a938686cad6faf35eac148f7ed3e` |
| FIPS 204 Section 6 guidance | Dated 2025-03-19 | `4a1d4b8d5aefef56069eb91bd464d5b5e177372e03bdde2541655e8e24d7a056` |
| FIPS 205 PDF | Final, 2024-08-13 | `8ef34228276f3386d23cb0da8c14592b8cfb0db3358016bba64df7a004f8d13d` |
| SP 800-230 IPD | Draft, 2026-04-13 | `62d092f787a1f79260454bf332b642ff3b5b73dbcce2678a133a1406065e452e` |
| CSWP 39upd1 | Final update, 2026-06-29 | `e6b147d23eba193653f2abb3abe03fc25e63a9a91df918440b5445f9f58e9ac6` |

Official sources:

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST PQC FIPS FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs)
- [SP 800-230 initial public draft](https://csrc.nist.gov/pubs/sp/800/230/ipd)
- [CSWP 39upd1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final)

The refresh changes no selected-profile vector bytes:

1. FIPS 204 remains final. Its 2026-02-23 planning note points to the
   potential-updates spreadsheet. The current spreadsheet matches the hash
   already pinned by the ML-DSA harness and describes future corrections, not
   a replacement parameter set.
2. The live NIST PQC FIPS FAQ, last revised 2026-06-16 for this question,
   permits an ML-DSA key-generation seed to serve as the stored or transported
   private-key representation when standard derivation reproduces the required
   outputs. This makes a 32-byte seed a viable backup primitive, but does not
   select a wallet encoding or expanded-key cache policy.
3. The 2025-03-19 Section 6 guidance still permits a separately validated
   external-`mu` boundary in specified module arrangements. PQBTC continues to
   use the external/pure Section 5 API in its comparator and does not select an
   external-`mu` interface.
4. FIPS 205 remains final. Its publication page exposes no replacement or
   errata artifact that changes the selected `SLH-DSA-SHA2-128s` baseline.
5. SP 800-230 remains an initial public draft. Its comment period is closed,
   but its limited-use profiles impose a strict `2^24` signatures-per-key
   limit and are not approved for general-purpose use. They are excluded from
   this decision.
6. CSWP 39upd1 is final guidance on cryptographic agility. PQBTC applies it by
   requiring explicit algorithm binding and a replacement path; agility must
   never reinterpret an existing output under different signature semantics.

## Measured Comparison

### Encoded Size And Weight

| Property | ML-DSA-44 | SLH-DSA-SHA2-128s |
| --- | ---: | ---: |
| Public key | 1,312 bytes | 32 bytes |
| Signature | 2,420 bytes | 7,856 bytes |
| Raw public key plus signature | 3,732 bytes | 7,888 bytes |
| Raw-payload upper bound at 16,000,000 WU | 4,287 | 2,028 |

The ML-DSA raw payload is 52.69% smaller. The raw-payload upper bounds assume
all bytes receive witness weight and omit transaction, script, compact-size,
commitment, and reveal overhead. They are comparison aids, not block-capacity
or fee claims.

ML-DSA's public key is expensive if placed directly in non-witness output
data. A hash-commit-and-reveal design could move that cost, but would also
change transaction visibility, recovery, and spending semantics. No such
design is selected here.

Both candidates exceed Bitcoin's retained 520-byte general stack-element
limit. Neither fits the current rc2-only witness exception. Either candidate
requires a new, explicit consensus and policy sizing design.

### Directional Prototype Timing

The common OpenSSL 3.6.3 oracle provides the closest current same-codebase
comparison. Values are medians of ten fixed-vector runs on arm64 macOS and are
not release envelopes.

| Operation | ML-DSA-44 | SLH-DSA-SHA2-128s |
| --- | ---: | ---: |
| Key generation | 0.099 ms | 15.811 ms |
| Randomized signing | 0.752 ms | 135.831 ms |
| Randomized verification | 0.052 ms | 0.120 ms |

On this narrow baseline, ML-DSA randomized signing is about 181 times faster
and verification is about 2.3 times faster. The result favors ML-DSA for
wallet responsiveness and block-validation headroom, but supported-platform,
worst-case, adversarial-input, and full-block measurements remain required.

## Qualitative Comparison

### Security Assumptions And Standards

- ML-DSA-44 is a final FIPS 204 category-2 structured-lattice profile.
- SLH-DSA-SHA2-128s is a final FIPS 205 category-1 stateless hash-based
  profile.
- Category numbers are comparison targets, not a complete ranking of
  construction risk, implementation risk, or Bitcoin-system safety.
- SLH-DSA has the more conservative primitive assumption. ML-DSA has the
  stronger size and performance fit for this application.

### Implementation Independence And Maturity

- The SLH-DSA harness compares OpenSSL with an independently developed
  portable implementation.
- The ML-DSA harness now compares OpenSSL, `mldsa-native`, and libcrux.
  `mldsa-native` descends from the `pq-crystals` reference implementation.
  libcrux has a separate direct-Rust implementation history and no normal
  PQClean, `pq-crystals`, `mldsa-native`, or `pqcrypto-mldsa` dependency,
  while its tests and selected implementation comments disclose PQ-Crystals
  influence.
- The frozen libcrux assessment is
  `separate_implementation_lineage_with_reference_influence`. Complete
  three-oracle byte agreement and cross-verification close the independent
  implementation evidence gate, but do not constitute independent design or
  external cryptographic review.
- Both candidates require a production implementation selected for auditability
  rather than a host OpenSSL consensus dependency.

ML-DSA still does not advance to consensus work. The next gate is external
specialist review, followed by supported-platform and worst-case system
measurements.

### Signing, Entropy, And Side Channels

- Both candidates support deterministic testing and randomized production
  postures. Production entropy acquisition, failure behavior, and retry rules
  remain unfrozen.
- ML-DSA production work must evaluate rejection sampling, structured-lattice
  arithmetic, fault behavior, constant-time signing, and secret erasure.
- SLH-DSA production work must evaluate long-running signer behavior,
  hash-based implementation leakage, constant-time handling, and secret
  erasure.
- Neither current harness establishes side-channel resistance.

### Wallet, Backup, PSBT, And Hardware Signers

- The NIST FAQ clarification allows ML-DSA wallets to back up a 32-byte
  key-generation seed instead of a 2,560-byte expanded private key. Expanded
  keys may be derived or cached only under a separately specified erasure and
  integrity policy.
- SLH-DSA has a 64-byte private key and 32-byte public key, but its 7,856-byte
  signatures and much slower signing path burden PSBT transport, hardware
  signers, QR or air-gapped workflows, fees, and multi-input transactions.
- ML-DSA's 1,312-byte public key burdens descriptors and commitment design,
  while its smaller signature and faster signing path are materially easier
  to carry through transaction and signer workflows.
- Neither candidate has an approved descriptor, PSBT, backup, hardware-signer,
  or recovery contract.

### Strict Encoding And Reviewability

- Both final standards provide fixed parameter-set encodings suitable for
  exact-length parsing.
- Consensus must bind the algorithm, context, sighash mode, public-key
  commitment, signature length, and activation rules without profile
  negotiation or fallback.
- SLH-DSA uses simpler underlying assumptions but a larger hash-tree verifier
  and much larger untrusted input.
- ML-DSA is smaller and faster but requires specialist review of lattice
  arithmetic, malformed keys, rejection sampling, and side channels.

## Selection Rationale

ML-DSA-44 is selected for engineering work because:

1. both candidates are final NIST standards with green isolated conformance
   evidence
2. ML-DSA's raw key-plus-signature payload is 52.69% smaller
3. the current same-oracle timing baseline gives ML-DSA a decisive signing
   advantage and a meaningful verification advantage
4. NIST's seed-storage clarification removes expanded-private-key size as a
   wallet backup blocker
5. the remaining ML-DSA risks are concrete gates that can be tested and
   reviewed before consensus integration

SLH-DSA-SHA2-128s remains the fallback because its hash-based assumptions and
compact keys are valuable if ML-DSA fails review. Its signature size and
signing cost make it a weaker first engineering fit for PQBTC.

Selecting a primary engineering candidate is preferable to an undirected
`HOLD`: it focuses external review, benchmarking, and protocol-design work.
Production nevertheless remains on `HOLD` until all readiness gates pass.

## Rejection And Fallback Criteria

Return the engineering selection to `HOLD`, then reassess the SLH-DSA fallback,
if any of these occur:

1. a genuinely independent ML-DSA implementation disagrees on final-standard
   vectors or cross-verification
2. standards updates change the selected profile or canonical encodings
3. external review identifies an unresolved construction, implementation,
   side-channel, or fault-attack risk
4. worst-case verification or malformed-input behavior cannot be bounded for
   block and mempool validation
5. no strict transaction, wallet, backup, and hardware-signer design can meet
   the project's usability and resource constraints

## Independent Implementation Evidence

Completed on 2026-07-19:

1. pin libcrux 0.0.10 source, tag, subtree, initial implementation commit, and
   exact crates.io archive
2. require all 70 selected-profile ACVP cases, exact signature-byte agreement,
   randomized cross-verification, malformed-input rejection, and the repo
   vector to pass OpenSSL, `mldsa-native`, and libcrux
3. rerun the two disclosed libcrux advisory regressions and two ML-DSA-44
   malformed-hint rejection cases without panic
4. record the qualified lineage assessment rather than claiming independent
   design or external review

## Next Gates

The next work remains evidence acquisition, not node integration:

1. obtain external cryptographic review covering the selected mode,
   randomization, rejection sampling, side channels, fault behavior, secret
   erasure, and key derivation
2. measure supported-platform and worst-case signer, verifier, malformed-input,
   multi-input transaction, and full-block costs
3. only after those gates, write a separate consensus-design specification for
   canonical key commitment, reveal, context, sighash, Script limits, policy,
   activation, and algorithm binding

No external network or user funds depend on rc2. Once a reviewed replacement
is ready, the implementation plan should remove rc2 rather than preserve a
dual-algorithm migration path. Future agility must still use explicit,
immutable algorithm bindings so an existing output can never be reinterpreted.

## Validation Contract

This decision slice is complete when these commands pass:

```bash
git diff --check
python3 ci/test/check_ci_inventory.py
python3 -m unittest discover -s ci/test -p 'test_*dsa_reference.py'
python3 contrib/slh-dsa-ref/compare_oracles.py --manifest-only
python3 contrib/ml-dsa-ref/compare_oracles.py --manifest-only
```

The functional-suite inventory remains `pq_required: 121`, `pq_backlog: 0`,
`legacy_only: 14`, and `dual_profile: 141`.
