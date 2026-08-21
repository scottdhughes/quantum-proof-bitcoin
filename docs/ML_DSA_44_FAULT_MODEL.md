# ML-DSA-44 Isolated-Wrapper Fault-Control Checkpoint

**Status:** PARTIAL RESEARCH-WRAPPER EVIDENCE - `RELEASE_HOLD`

**Updated:** 2026-08-21
**Tracking:** issue `#186`, tranche 1

## Scope

This document freezes a bounded deterministic fault-injection contract for the
isolated portable-C ML-DSA-44 wrapper. It does not select a production backend,
authorize node or wallet integration, or claim resistance to physical fault
attacks. `production_backend` remains `NONE`, and issue `#186` remains open.
It is not the platform-specific fault model required by that issue: separate
reviewed models for general-purpose hosts, co-resident attackers, and hardware
signers have not yet been produced.

The implemented checkpoint answers one narrow question: if a successful
backend signing operation produces an exact-length signature candidate and
that private candidate is corrupted before the wrapper's self-verification,
does the real verifier reject it without releasing any signature bytes?

## General-Purpose Host Boundary

The current prototype assumes ordinary process execution on a general-purpose
host. Within that boundary, the wrapper owns:

- the private candidate buffer;
- the module-owned entropy request and immediate-repeat guard;
- the call to the pinned portable-C signer;
- the call to the pinned portable-C strict verifier;
- the caller's accepted output buffer after overlap and length checks; and
- cleanup of the candidate on every backend exit.

The wrapper does not own persistent signing-key storage, operating-system or
hardware integrity, compiler-created copies, registers, caches, crash dumps,
or physical sensors. Those remain outside this tranche.

## Deterministic Candidate-Corruption Checkpoint

The test build exposes
`pqbtc_mldsa44_test_corrupt_candidate_before_verify()`. When enabled, it flips
bit zero of the first byte of a genuinely generated, exact-length private
signature candidate after the length gate and immediately before the real
`pqbtc_mldsa44_upstream_verify()` call.

The regression requires all of the following:

1. the signing backend and entropy acquisition succeed;
2. the exact signature-length gate succeeds;
3. the candidate bit is changed only in the separately compiled test build;
4. the real self-verifier returns rejection;
5. `pqbtc_mldsa44_sign_hedged()` returns `PQBTC_MLDSA44_ERR_VERIFY`;
6. the complete caller output remains all zero;
7. the complete private candidate is observed all zero after cleanup; and
8. the consumed randomizer remains consumed, so immediate reuse is rejected
   before a fresh randomizer permits a later successful signature.

The production-shaped shared library still exports exactly
`pqbtc_mldsa44_sign_hedged` and `pqbtc_mldsa44_verify_strict`. It does not
export this checkpoint, fixed-randomizer signing, seeded key generation,
entropy controls, or cleanup observers.

## Existing Adjacent Failure Controls

The same isolated harness already requires atomic zero-output behavior for:

| Injected or constructed condition | Required result |
| --- | --- |
| entropy unavailable or provider failure | entropy-source error |
| short entropy | entropy-length error |
| all-zero entropy | all-zero error |
| immediate randomizer reuse | repeat error |
| backend failure | backend error |
| signing-attempt exhaustion | attempts-exhausted error |
| wrong candidate length | signature-length error |
| signing/public-key mismatch | real self-verification rejection |
| injected verifier error | verification error |
| unavailable POSIX fork lifecycle | lifecycle error |
| pre-self-verification candidate corruption | real self-verification rejection |

These controls establish deterministic error and cleanup behavior at the
wrapper boundary. They are not a statistical or physical fault campaign.

## Required Failure Semantics

Once a valid, non-overlapping output buffer is accepted, every failure in this
model returns no partial signature. The output is cleared before entropy or
backend work begins and is populated only after successful self-verification.
The candidate is a private stack buffer and is cleared in the common cleanup
path. The test observer establishes only that this source-level buffer reads
all zero immediately after that cleanup call; it does not prove erasure of
compiler copies, registers, or other memory. A randomizer accepted by the
entropy guard is not rolled back when a
later signing, length, or verification check fails; treating it as consumed
prevents a failed operation from authorizing reuse.

## Explicit Nonclaims and Remaining Work

This tranche does not establish:

- resistance to skipped control flow or a fault that bypasses both the
  verifier call and its result check;
- independence from a common-mode fault in the signer and same-backend
  verifier;
- detection of corruption after self-verification or during output copying;
- signing-key integrity at generation, import, load, or use;
- protection against faults in `rnd`, NTT constants or arithmetic, rejection
  sampling, hints, norm checks, or persistent process state;
- compiler-, CPU-, kernel-, VM-, enclave-, HSM-, or hardware-signer fault
  resistance;
- electromagnetic, voltage, clock, laser, rowhammer, or other physical fault
  coverage; or
- production fitness or closure of issue `#186`.

A later production proposal must choose whether final verification is
same-backend, independently implemented, or diversified; define key-integrity
and control-flow controls; add platform-specific checkpoints and retained
campaign evidence; specify physical-attacker residual risk; and receive exact-
commit independent review under issue `#181`.

## Reproduction

Run the bounded regression with:

```bash
python3 -m unittest ci.test.test_ml_dsa_wrapper_prototype
python3 -m unittest ci.test.test_ml_dsa_backend_admission
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py
python3 contrib/ml-dsa-engineering/run_wrapper_tests.py --sanitizers
```

The normal and ASan/UBSan harnesses execute the same candidate-corruption
sequence. The symbol audit separately proves that the production-shaped build
retains only its two approved exports.
