# PQBTC Signature Production Readiness

## Status: RELEASE_HOLD
## Spec-ID: PQSIG-PRODUCTION-READINESS-v1
## Decided: 2026-07-18
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
- NIST FIPS 205 standardizes SLH-DSA:
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
- NIST SP 800-230 is an initial public draft, not a final standard. Its
  Bitcoin-oriented `SLH-DSA-*-128-24` profiles have a strict `2^24`
  signatures-per-key limit and are not approved for general-purpose use:
  https://csrc.nist.gov/pubs/sp/800/230/ipd
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

FIPS 205 is the conservative first implementation target because it is final,
stateless, hash-based, and has compact public keys. Its 7,856-byte signatures
increase block-space and bandwidth cost relative to rc2. FIPS 204 is a useful
standardized efficiency comparator, but it adds structured-lattice assumptions
and much larger public keys. Neither profile is selected for activation by this
record.

## Implementation Direction

1. Maintain the isolated `SLH-DSA-SHA2-128s` prototype in
   `SLH_DSA_SHA2_128S_REFERENCE.md` against the exact FIPS 205 API, encodings,
   context rules, and test vectors. Do not assign an active `ALG_ID` or connect
   it to Script yet.
2. Implement or bind an isolated `ML-DSA-44` comparator for size, signing,
   verification, wallet, and block-economics measurements.
3. Use OpenSSL 3.5 or later only as a prototype and differential-test oracle.
   Do not introduce a host OpenSSL dependency into consensus verification.
4. Obtain a second independent implementation or vector source for every
   candidate. A repo-local signer and repo-local verifier are not independent
   evidence.
5. Monitor SP 800-230, but do not activate a draft profile. Reassess only after
   a final publication and an explicit one-key-per-output usage-limit design.
6. Retire rc2 or replace it with a ground-up, exact construction. Do not patch
   isolated symptoms while retaining the current security claims.

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

## Hold Exit Criteria

Green CI for the existing rc2 implementation is necessary regression evidence,
but it cannot lift this hold. The hold exits only after one candidate passes all
gates above and a separate change updates the protocol spec, algorithm registry,
release checklist, and user-facing warnings. Until then, Track A remains on
`HOLD` for production activation.
