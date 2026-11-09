# ML-DSA Native Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Deliver a real native transaction-verification building block and a
tested guarded-signer interoperability path, then continue toward node/wallet/IPC.

**Architecture:** A public-only C verifier compiles the frozen portable capsule
with keygen/sign/randomized APIs absent. A C++ CONTRACT-1 adapter parses unsigned
wire, binds node-supplied prevouts/network and verifies exact v2 witnesses. A
separate test signer uses the existing guarded key owner, never node-side secrets.

**Tech Stack:** C11, C++20, existing CSHA256, frozen mldsa-native2.0.0, Python tests.

**Spec:** docs/ML_DSA_44_PRODUCTION_CONTRACT_V1.md and docs/ML_DSA_44_OWNER_CONTINUATION.md.

## Global Constraints

- Linux x86_64 software signing GCC/Clang is the production target; hardware deferred.
- Current offline test image is aarch64; label its results accurately.
- Frozen wrapper/vendor/key/backup sources and admission JSON remain byte-identical.
- No host-native execution, real wallet roots, backend activation or hold flip.
- Experimental source does not enter the default node build/accepted set yet.
- This phase is not the entire integrated node/wallet/service or production approval.

## Review Focus

- Oversized/truncated/nonminimal wire must fail before unbounded allocation/loops.
- Every signature must bind all prevouts/outputs, network and exact FIPS context.
- Public verifier object must have no signer/keygen/RNG/fork/secret-policy machinery.
- Wrong key, witness shape or metadata must not become a valid accepted spend.
- Empty/null arguments and arithmetic boundaries must fail consistently under sanitizers.

### Task 1: Public-only native verifier and transaction adapter

**Files:** create src/crypto/mldsa44/{verify.h,verify_config.h,verify.c,contract.h,contract.cpp};
create contrib/ml-dsa-integration/{native_smoke.cpp,run_native_tests.py};
create ci/test/test_ml_dsa_native_integration.py.

**Interfaces:** C pqbtc_mldsa44_node_verify(signature,size,pk,size,message,size)
returns1only valid,0otherwise, fixed CONTRACT-1 context. C++ namespace
pqbtc::mldsa44 exposes Transaction/Input/Output, ParseUnsigned, SerializeUnsigned,
SigningMessage, KeyCommitment, VerifyWitness; std::span carries public bytes.

- [ ] Add failing executable test compiling/running the native harness; observe RED.
- [ ] Implement verifier-only config and strict size/context entrypoint.
- [ ] Implement bounded wire/money/duplicate validation and exact component hashes.
- [ ] Exercise real key-owner signing, native witness verification, changed-field,
      context/network/key/shape adversaries, deterministic Python-model joins.
- [ ] Run GCC/Clang normal+ASanUBSan, symbol audit, full contained suite and validators.
- [ ] Commit the source-bound result; no activation or default-build wiring claim.

### Task 2: Separate review and next-stage handoff

**Files:** new external evidence packet, independent review, rulings, source hashes,
receipt and progress/continuation. No old sealed packet overwritten.

**Interfaces:** consume exact clean Task1commit and native reports; produce exact
source-bound review disposition and concrete runtime integration obligations.

- [ ] Supply complete public patch/context to Claude, tools disabled, separate from author.
- [ ] Diagnose/reproduce required findings; one RED/GREEN fix pass and full suite.
- [ ] Seal evidence and record what actually works and what remains unimplemented.

## Following implementation sequence (not completed by this phase)

1. Signer process/peer-authenticated IPC/state machine, no keys in node process.
2. Native private HD, AEAD/scrypt persistence, atomic counters, crash/restore tests.
3. Actual node UTXO/Script/build/RPC path on a valueless dedicated network, exact
   effective identity joins, cross-node spend/restore/reorg/reindex tests.
4. GCC/Clang x86_64 release binaries, independent crypto vectors, hostile aggregate
   workloads, timing/fault/entropy/erasure qualification and operational soak.
5. Disclosed owner go/no-go on exact dossier; never claim external human review.
