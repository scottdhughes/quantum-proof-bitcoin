# PQBTC Signature Production Readiness

## Status: RELEASE_HOLD
## Spec-ID: PQSIG-PRODUCTION-READINESS-v1
## Decided: 2026-07-18
## Evidence-Updated: 2026-07-19
## Consensus-Relevant: NO

## Decision

PQBTC has no signature profile approved for production use. Do not release a
network that carries real value, represent `PQSig rc2` as cryptographically
conformant, or rely on its claimed `2^40` signing bound or NIST Level 1 security.

The implemented `ALG_ID=0x01` path remains available only as a research and
Bitcoin-integration fixture while a standards-conformant replacement is built
and reviewed. This decision changes release posture, not the current consensus
accepted set.

## Evidence Classification

### Observed In The Repository

1. `src/crypto/pqsig/wotsc.h` signs the 32 raw base-16 message digits. It does
   not encode or enforce the WOTS+C fixed digit sum `S_{w,n}=240`.
2. `src/crypto/pqsig/pqsig.cpp` computes one deterministic `R` and one `Hmsg`.
   The `max_counter` argument is range-checked, but signing performs no search.
3. `src/crypto/pqsig/porsfp.h` extracts eight indices directly and does not
   enforce that they are distinct.
4. `src/crypto/pqsig/octopus.h` fills and folds 97 signer-chosen hash chunks. It
   does not reconstruct the authentication-node set of the cited PORS+FP
   construction.
5. `src/crypto/pqsig/hypertree.h` identifies a leaf by layer and 11-bit leaf
   index, without the per-tree address needed to realize a height-44 hypertree
   as many selected subtrees.
6. `contrib/pqsig-ref/pqsig_ref.py` mirrors those implementation choices. Its
   vectors therefore check implementation stability, not conformance to an
   independent construction or standard.

Run the primitive-level reproducer with:

```bash
python3 contrib/pqsig-ref/audit_rc2_conformance.py --expect-release-hold
build/bin/test_pqbtc --run_test=pqsig_tests/pqsig_rc2_release_hold_conformance_evidence
```

The Python audit and C++ unit test both start from a WOTS signature over
all-zero digits, advance each chain to all-15 digits, and reconstruct the same
WOTS public key. The two digit sums are 0 and 480 rather than the required 240.
This is a construction-level counterexample, not a claim that either test
produces a complete transaction forgery.

The PORS check shows that the index extractor can return repeated indices and
has no distinctness enforcement. The no-search signer and non-Merkle auth-pad
observations remain source-backed findings that require replacement rather
than a local patch.

### External Standards And Research

- NIST FIPS 204 standardizes ML-DSA:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- NIST's 2026-02-23 FIPS 204 planning note points to a potential-updates
  spreadsheet. The 2026-07-18 refresh matches the SHA256 already pinned by the
  ML-DSA comparator, so it changes no selected-profile vector bytes:
  https://csrc.nist.gov/pubs/fips/204/final
- NIST's PQC FIPS FAQ, last revised 2026-06-16 for the key-format question,
  permits the ML-DSA key-generation seed to represent the stored or transported
  private key when standard derivation reproduces the required outputs:
  https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs
- NIST FIPS 205 standardizes SLH-DSA:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
- NIST SP 800-230 is an initial public draft, not a final standard. Its
  Bitcoin-oriented `SLH-DSA-*-128-24` profiles have a strict `2^24`
  signatures-per-key limit and are not approved for general-purpose use. Its
  public comment period is closed, but NIST has not published a final:
  https://csrc.nist.gov/pubs/sp/800/230/ipd
- NIST CSWP 39upd1 is final cryptographic-agility guidance. Any PQBTC agility
  mechanism must use explicit algorithm binding and must not reinterpret an
  existing output under replacement signature semantics:
  https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final
- Kudinov and Nick's Bitcoin-specific hash-signature work is a 2025 preprint,
  not a NIST standard:
  https://eprint.iacr.org/2025/2203

Reference encoded sizes from the final standards:

| Profile | Public key | Signature | Status |
| --- | ---: | ---: | --- |
| ML-DSA-44 | 1,312 bytes | 2,420 bytes | FIPS 204 final |
| ML-DSA-65 | 1,952 bytes | 3,309 bytes | FIPS 204 final |
| SLH-DSA-SHA2-128s | 32 bytes | 7,856 bytes | FIPS 205 final |
| SLH-DSA-SHAKE-128s | 32 bytes | 7,856 bytes | FIPS 205 final |
| SLH-DSA-SHA2-128-24 | 32 bytes | 3,856 bytes | SP 800-230 draft |

### Engineering Inference

The rc2 security claims do not follow from matching a parameter-table row or
signature size. The omitted fixed-sum encoding, grinding rules,
authentication-set construction, and hypertree addressing are security
invariants, not optional serialization details. Incrementally repairing rc2
would amount to implementing and reviewing a new consensus algorithm.

FIPS 205 remains the conservative fallback because it is final, stateless,
hash-based, and has compact public keys. Its 7,856-byte signatures impose high
block-space, bandwidth, signer, and hardware-wallet costs. FIPS 204 adds
structured-lattice assumptions and much larger public keys, but offers a much
smaller combined payload and substantially faster signing. The isolated
ML-DSA-44 comparator now passes its complete selected-profile ACVP and
three-codebase differential contract. `mldsa-native` descends from the
`pq-crystals` reference implementation. The added libcrux portable-Rust oracle
has separate implementation history with disclosed PQ-Crystals influence and
no normal reference-code dependency. This closes the independent
implementation evidence gate, but does not replace independent cryptographic
review.

`PQSIG_CANDIDATE_SELECTION.md` selects `ML-DSA-44` as the primary engineering
candidate because its raw key-plus-signature payload, signing latency, and
verification latency fit PQBTC materially better than the current
`SLH-DSA-SHA2-128s` baseline. The hash-based profile remains the conservative
fallback. This prioritizes evidence and design work; neither profile is
selected for activation by this record.

## Implementation Direction

1. Maintain the isolated `SLH-DSA-SHA2-128s` prototype in
   `SLH_DSA_SHA2_128S_REFERENCE.md` against the exact FIPS 205 API, encodings,
   context rules, and test vectors. Its complete selected-profile ACVP,
   randomized interoperability, mutation, and bounded sanitizer tranche is
   green. Do not assign an active `ALG_ID` or connect it to Script yet.
2. Maintain the isolated FIPS 204 `ML-DSA-44` comparator in
   `ML_DSA_44_REFERENCE.md`. Its 70-case ACVP, randomized interoperability,
   mutation, sanitizer, disclosed-advisory regression, timing, and raw-payload
   evidence is green across OpenSSL, `mldsa-native`, and libcrux. Preserve the
   qualified `separate_implementation_lineage_with_reference_influence`
   assessment.
3. Use the OpenSSL 3.6.3 runtime and pinned source checkout only as a prototype
   and differential-test oracle. Do not introduce a host OpenSSL dependency
   into consensus verification.
4. Preserve a second independent implementation or vector source for every
   candidate. The ML-DSA comparator now satisfies this implementation-evidence
   requirement through libcrux; that evidence is not independent design or
   external review. A repo-local signer and repo-local verifier would not be
   independent evidence.
5. Monitor SP 800-230, but do not activate a draft profile. Reassess only after
   a final publication and an explicit one-key-per-output usage-limit design.
6. Retire rc2 or replace it with a ground-up, exact construction. Do not patch
   isolated symptoms while retaining the current security claims.
7. Apply the measured decision in `PQSIG_CANDIDATE_SELECTION.md`: advance
   `ML-DSA-44` only through external cryptographic review and worst-case system
   measurements now that its independent implementation evidence is complete.
   Preserve `SLH-DSA-SHA2-128s` as the fallback and keep production on `HOLD`.

## Required Gates Before Consensus Integration

A candidate may enter a separate consensus-integration proposal only after all
of these are satisfied:

1. exact final standard, parameter set, security category, and usage limits
2. frozen canonical public-key, signature, context, and sighash encodings
3. strict parser with no alternate encodings or silent profile negotiation
4. official known-answer tests plus differential tests against an independent
   implementation
5. malformed-input, mutation, fuzz, sanitizer, and resource-exhaustion coverage
6. constant-time and secret-erasure review for key generation and signing
7. reproducible benchmarks on supported architectures, including worst-case
   verification and block-validation cost
8. wallet, descriptor, PSBT, backup, hardware-signer, fee, mempool, reorg, and
   reindex contracts
9. a deployment and algorithm-agility plan that cannot reinterpret existing
   outputs
10. independent cryptographic review and consensus-code audit
11. public testnet soak with no real-value representation
12. a new, explicit production go/no-go record that removes this hold

For ML-DSA-44, gate 4 is now complete at the isolated comparator level. Gate 5
has bounded evidence but remains open for exhaustive fuzzing and resource
exhaustion. The other integration, system, review, soak, and release gates
remain open. No completion recorded here changes the consensus accepted set.

## Hold Exit Criteria

Green CI for the existing rc2 implementation is necessary regression evidence,
but it cannot lift this hold. The hold exits only after one candidate passes all
gates above and a separate change updates the protocol spec, algorithm registry,
release checklist, and user-facing warnings. Until then, Track A remains on
`HOLD` for production activation.
