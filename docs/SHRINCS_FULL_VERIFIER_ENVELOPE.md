# Strict Full-Profile SHRINCS Verifier Envelope

## Status: RESEARCH PROTOTYPE - CONSENSUS DISABLED - RELEASE HOLD
## Spec-ID: SHRINCS-FULL-VERIFIER-ENVELOPE-v1
## Evidence-Updated: 2026-08-16
## Consensus-Relevant: NO

## Decision

Combine the independently reproduced stateful and stateless verification paths behind one project-owned, fail-closed profile boundary.

This envelope recognizes exactly one 48-byte SHRINCS public-key encoding and exactly two signature shapes belonging to the same pinned scheme:

| Mode | Canonical signature shape |
| --- | --- |
| Stateful FXMSS | `538 + 16 * leaf_depth` bytes for `1 <= leaf_depth <= 255`, yielding 554 through 4,618 bytes |
| Stateless recovery | exactly 5,776 bytes |

Every other length is invalid and is rejected before SHA-256 work. There is no ECDSA, Schnorr, held-rc2, ML-DSA, or unknown-algorithm fallback.

## Why This Length Dispatch Is Narrowly Acceptable

The held PQSig implementation selected between unrelated cryptographic algorithms inside inherited `CHECKSIG` machinery based on signature length. That design mixed algorithm negotiation, fallback, and classical authorization inside one path.

The full SHRINCS envelope is different:

1. the output is assumed to bind one immutable SHRINCS profile;
2. both accepted shapes verify against the same 48-byte SHRINCS public key;
3. the two shapes are the compact stateful mode and static-backup recovery mode defined by that one scheme;
4. their accepted length sets are disjoint and completely enumerated;
5. every unrelated or future algorithm remains invalid;
6. a future algorithm requires a separate output or witness version and cannot reinterpret an existing output.

This record does not select a transaction output, opcode, witness version, tapscript leaf version, or activation rule.

## Immutable KAT Corpus

The complete current-draft KAT corpus is committed under:

```text
contrib/shrincs-ref/vectors/
```

The JSON files are stored as deterministic gzip/base64 chunks so the repository remains reviewable while preserving exact bytes. `kat_loader.py` authenticates every layer before parsing.

### Stateful corpus

| Property | Value |
| --- | --- |
| Vectors | 7 |
| Raw JSON bytes | 12,581 |
| Raw JSON SHA-256 | `059549af4c74f6bd1898fc93add185ec0bffe08063b00cbff5b1eb4080ebc041` |
| Deterministic gzip SHA-256 | `3eb582429e65b6744a8ec898bddeb9c831efdd353fa6078e0b5837f6d5785094` |
| Concatenated base64 SHA-256 | `7b8e87f9df2b0a97edcd4a6ac8ff2c763a2cf16c6ad77fbab3e896a2cf4d9a61` |

### Stateless corpus

| Property | Value |
| --- | --- |
| Vectors | 2 |
| Raw JSON bytes | 24,566 |
| Raw JSON SHA-256 | `67356b917284198f5a89bfbe727391dcde5e0f06c9f6799b0edd31197968eaae` |
| Deterministic gzip SHA-256 | `850fd465f3cd2bb7bf4dfdf539498d9f2c4e71fe9044e3bdc4e02cf818d7f50b` |
| Concatenated base64 SHA-256 | `fa5de8f69e80556e1a4682c5e686519fb3985520c577b120b6815fc15d7e1fc4` |

The corpus is bound to:

```text
SHRINCS/shrincs-bip@acc6bda51dc3b94848d118967247ad0f3cd7a80e
remix7531/libshrincs@53bedb2c4be6b0dcc0a16fee665339d4f7e4e5b5
```

`regenerate_kats.py` regenerates all nine vectors from those exact sources and requires byte-for-byte equality with the commitment.

## Strict Parser Contract

`full_verify.c` enforces:

1. public key must be exactly 48 bytes;
2. 5,776 bytes selects stateless recovery;
3. 554 through 4,618 bytes selects stateful verification only when `(length - 538) mod 16 = 0`;
4. all other lengths fail before a cryptographic backend is called;
5. null public-key or signature pointers fail;
6. no mode is inferred from key contents, a caller-supplied flag, or mutable policy;
7. no alternate encodings are accepted.

The test contract exhausts every signature length from 0 through 6,000. It also verifies that 64-byte Schnorr, 73-byte ECDSA, 2,420-byte ML-DSA-44, and 4,480-byte held-rc2 payloads fail without SHA-256 work.

## Work Accounting

The pinned SHA-256 implementation is wrapped by `sha256_counting.c`. For each one-shot call, it records:

- one SHA-256 call;
- the exact compression count under standard SHA-256 padding: one additional block when the input remainder is at most 55 bytes and two otherwise.

The workflow records calls and compressions for every committed valid vector. These measurements are reproducible algorithmic work counts, not cycle-accurate performance claims. Wall-clock durations are directional CI observations only.

## Reproduction Workflow

`.github/workflows/shrincs-full-profile.yml` performs:

1. exact upstream checkouts;
2. candidate and unit-test validation;
3. authentication and extraction of committed KATs;
4. byte-for-byte regeneration from the pinned draft;
5. build of the strict combined verifier;
6. verification of all nine committed vectors;
7. exhaustive signature-length classification from 0 through 6,000;
8. random rejection for all 255 canonical stateful lengths and the stateless length;
9. invalid public-key-length and cross-mode confusion tests;
10. exact SHA-256 call/compression accounting;
11. complete repetition under ASan/UBSan;
12. retention of KAT and work reports.

## Security Limitations

This tranche does not establish:

- production-quality allocation or fixed-transaction-digest APIs;
- maximum-depth block-validation resource envelopes;
- sustained coverage-guided fuzzing;
- formal verification of the combined C envelope;
- independent cryptographic or consensus review;
- side-channel or fault resistance of signing;
- safe monotonic signer state;
- wallet, descriptor, PSBT, or hardware-signer behavior;
- a transaction sighash or chain-domain separator;
- consensus or production readiness.

The stateful and stateless research verifiers accept arbitrary bounded messages and allocate for contextualized hashing. A production-shaped verifier should consume a fixed transaction digest, eliminate or tightly encapsulate dynamic allocation, expose immutable work accounting, and remain verifier-only in node builds.

## Release Posture

The controlling state remains:

```text
consensus_enabled = false
production_backend = NONE
release_hold = true
```

No real-value use is authorized.

## Strongest Next Attack

After this envelope reproduces successfully, the next tranche should:

1. freeze a fixed 32-byte transaction-digest and domain-separation contract;
2. replace arbitrary-message allocation with a production-shaped verifier ABI;
3. measure maximum-depth and adversarial full-block verification costs;
4. add sustained structure-aware fuzzing and allocation-failure tests;
5. obtain external cryptographic review of the exact profile and verifier;
6. separately design and crash-test the monotonic signer state machine;
7. only then write a disabled transaction-envelope proposal.
