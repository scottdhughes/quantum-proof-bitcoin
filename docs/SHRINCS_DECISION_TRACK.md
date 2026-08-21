# PQBTC SHRINCS-Family Decision Track

## Status: REOPENED - RESEARCH CANDIDATE - CONSENSUS DISABLED - RELEASE HOLD
## Spec-ID: SHRINCS-DECISION-TRACK-v2
## Started: 2026-04-13
## Reopened: 2026-08-16
## Evidence-Updated: 2026-08-16
## Consensus-Relevant: NO

## Decision

Open a separate, evidence-first SHRINCS candidate lane for PQBTC.

This does **not**:

- activate SHRINCS
- allocate an `ALG_ID`
- add or reinterpret an opcode
- change the accepted Script or witness set
- replace the current ML-DSA-44 engineering selection
- remove the controlling production release hold
- approve any current SHRINCS implementation for real-value use

The first objective is narrower: freeze the moving upstream artifacts, make
their differences explicit, and establish a deterministic admission contract
for a verifier-only prototype. Consensus, wallet signing, and network
activation remain later proposals.

## Why This Track Is Reopened

The current Blockstream research direction is materially stronger than the
held `PQSig rc2` construction:

1. It has an actively maintained draft specification.
2. It combines a compact stateful path with a stateless recovery path under
   one public key.
3. Its compact path is small enough to change the system-level feasibility
   analysis for a Bitcoin-like chain.
4. Its verifier is hash-based and can be independently reproduced.
5. Its parameter-search work is public and reproducible.

Those advantages justify a serious candidate track. They do not establish
cryptographic or production readiness. The draft still changes, the full
security proof is unfinished, the available implementations are research
implementations, and safe signer-state management is a separate critical
system.

## Current Upstream Pins

The machine-readable source of truth is
`contrib/shrincs/manifest.json`. This decision record is bound to:

| Artifact | Pin | Role |
| --- | --- | --- |
| `BlockstreamResearch/SPHINCS-Parameters` | `d64a217595597d5fe165ba6d236af83e6737da31` | Parameter models and pinned explorer; parameter evidence only |
| `SHRINCS/shrincs-bip` | `acc6bda51dc3b94848d118967247ad0f3cd7a80e` | Current draft specification and executable model |
| `BlockstreamResearch/shrincs-cpp` | `7643d9530c568f8671b21b9502e51bd9722b2e8d` | Historical research implementation; incompatible with the pinned draft |
| `BlockstreamResearch/shrincs-simplicity-verifier` | `d13165d3d21bac73e8794eede21f0f1527f3b837` | Historical constrained-verifier lineage; incompatible with the pinned draft |

No use of `main`, `latest`, an unpinned web page, or an unversioned package is
permitted in a future reproducibility or consensus claim.

## Initial Compatibility Audit

The pinned artifacts do not presently supply two independent implementations
of one common byte-level construction:

1. The pinned draft's `impl/shrincs.py` is the only pinned executable model of
   the current 48-byte-public-key profile. It expressly describes itself as a
   naive, non-constant-time demonstration that performs no state management.
2. The pinned C++ implementation has a 32-byte public-key model and materially
   different WOTS, tree, and stateless parameters. It implements a paper-era
   PORS+FP construction rather than the pinned draft's FORS-based construction.
3. The pinned Simplicity verifier uses an older seed-root public-key model and
   an explicit UXMSS/SPHINCS signature union tied to the older implementation
   lineage. Its serialization is not the pinned draft serialization.
4. The pinned parameter explorer supports the current parameter discussion,
   but is not a signature implementation or an independent verification
   oracle.

Accordingly, `differential_verifiers` remains false. Phase 1 is blocked until a
second genuinely independent implementation of the exact pinned profile exists
or is written. Adapting the draft reference code twice does not satisfy that
gate.

The current draft verifier also selects its stateful or stateless path from
signature length. A later encoding proposal must decide whether to freeze that
rule inside the single SHRINCS profile or place an explicit mode tag in the
PQBTC outer encoding. This is distinct from, and does not justify, dispatching
between unrelated signature algorithms by length.

## Version Drift Is A Blocking Fact

The SHRINCS name currently covers several evolving profiles. They must not be
conflated:

- The original paper-era result included a 324-byte compact-signature headline.
- The May 2026 `OP_CHECKSHRINCS` design post described roughly 580-byte compact
  signatures and multiple specialized profiles.
- The pinned current draft specifies a 48-byte public key, stateful signatures
  from 554 to 4,618 bytes, and a 5,776-byte stateless signature.
- The pinned parameter explorer currently presents stateless parameters
  `(h, d, k, a, w) = (45, 5, 10, 13, 16)` and stateful WOTS+C profiles using
  `w = 64`.

PQBTC therefore does not select “the 324-byte profile” or “latest SHRINCS.”
A later profile-freeze PR must select one exact byte-level construction and
prove that every implementation, vector, parser, and resource bound refers to
that same construction.

## Relationship To Existing PQBTC Work

### Held `PQSig rc2`

`PQSig rc2` remains only a regression and Bitcoin-integration fixture. Its
construction-level defects require replacement, not incremental repair.
SHRINCS must enter through a new isolated implementation boundary; it must not
be spliced into `src/crypto/pqsig` or selected by signature length.

### ML-DSA-44

`ML-DSA-44` remains the primary standards-based engineering candidate under
`PQSIG_CANDIDATE_SELECTION.md`. This SHRINCS lane is a parallel research
candidate because it may offer a much better ordinary-spend size profile at the
cost of statefulness and non-standard parameters. A later evidence review must
choose whether SHRINCS supplements, replaces, or fails the candidate set.

### Existing Assurance Infrastructure

The repository's ML-DSA work provides the model to reuse:

- exact upstream provenance
- independent oracles
- official and project KATs
- strict malformed-input rejection
- differential fuzzing
- sanitizer and resource envelopes
- side-channel and fault-review contracts
- explicit backend admission
- production release hold until independent review

The SHRINCS lane should reuse those gates, not bypass them because the
underlying primitive is SHA-256.

## Candidate Consensus Shape

No consensus encoding is selected by this record. The design direction is:

1. a dedicated, explicitly versioned SHRINCS spend path
2. no signature-length dispatch between unrelated algorithms
3. no ECDSA, Schnorr, rc2, or ML-DSA fallback inside the same key encoding
4. exact public-key and signature parsing before expensive verification
5. a frozen transaction digest and domain-separation context
6. `SIGHASH_ALL` only in the first prototype unless a separate analysis
   justifies additional modes
7. no classical key-path for outputs represented as PQ-only
8. immutable algorithm binding so an existing output cannot later be
   reinterpreted
9. explicit byte and SHA-256-compression accounting
10. fail-closed behavior for every unknown version, profile, or mode

The upstream `OP_CHECKSHRINCS` / leaf-version work is an input to this design,
not automatically the PQBTC consensus design. PQBTC is a distinct chain and
must freeze its own exact semantics.

## Signer-State Safety Contract

The compact path is safe only if state is monotonic. The wallet or hardware
signer must satisfy all of the following:

1. **Reserve before signing.** Durably consume a state index before producing
   signature bytes.
2. **Burn on attempt.** A failed, interrupted, rejected, abandoned, or
   unbroadcast signing attempt never restores the index.
3. **No chain rollback.** Mempool eviction and reorgs never roll signer state
   backward.
4. **RBF uses fresh state.** Every replacement transaction signs a different
   message and consumes a fresh index.
5. **Single authoritative signer or disjoint allocation.** Cloned devices may
   not independently statefully sign from the same index space.
6. **Static-backup recovery is conservative.** A seed-only restore enters a
   stateless recovery or provably safe resynchronization path; it never assumes
   index zero is unused.
7. **Atomic release.** No signature is released before durable reservation and
   successful self-verification.
8. **Corruption fails closed.** State-integrity failure disables compact
   signing and moves to recovery rather than guessing.

These are admission requirements, not optional wallet UX preferences.

## Implementation Sequence

### Phase 0 - Provenance And Hold (this change)

- pin exact upstream commits
- record observed profile values without selecting consensus constants
- classify current implementation compatibility
- enforce `consensus_enabled = false`
- enforce `production_backend = "NONE"`
- enforce the state-safety requirements in a deterministic validator
- add CI that fails if the hold, pins, or compatibility classifications drift
  silently

### Phase 1 - Independent Verifier Reproduction

Create `contrib/shrincs-ref/` with:

- an exact frozen reference implementation
- project-owned KATs generated from fixed seeds and messages
- cross-verification against at least one genuinely independent implementation
- strict public-key and signature decoders
- mutation and malformed-input corpus
- exact SHA-256 compression counters
- a statement of which upstream branches are compatible or incompatible

No node, Script, wallet, or `ALG_ID` integration is permitted in this phase.
Phase 1 is tracked in issue #228.

### Phase 2 - Production-Shaped Verifier Candidate

Select a small, portable verifier-only implementation and expose a narrow
project ABI. Required evidence includes:

- bounded stack and heap use
- no exceptions or process termination on adversarial input
- no host OpenSSL consensus dependency
- deterministic cross-platform output
- ASan, UBSan, MSan where supported, and sustained fuzzing
- worst-case verification measurements
- current dependency and advisory inventory
- external cryptographic review of the exact profile and implementation

The production backend remains `NONE` until the review disposition allows
admission.

### Phase 3 - Consensus Design, Still Disabled

Write a separate normative proposal for:

- key commitment and reveal format
- opcode, witness version, or leaf-version semantics
- transaction digest and context
- canonical encodings
- resource limits and fee/weight accounting
- mempool and block-validation behavior
- activation and upgrade rules
- pure-PQ output construction

The implementation must remain unactivated and unavailable to release builds
until the proposal and audit gates pass.

### Phase 4 - Stateful Signer And Wallet

Implement the state-safety contract with crash injection at every transition.
Required tests include concurrent processes, cloned wallets, RBF, abandoned
transactions, mempool rejection, reorgs, backup restore, corrupted state, and
hardware-signer disconnects.

### Phase 5 - Zero-Value Labnet

Only after the verifier, consensus envelope, wallet state machine, and recovery
path are independently reviewed may a disposable public labnet activate the
candidate. The labnet must make no economic-value representation and must have
a published reset policy.

## Next PR: Exact Acceptance Contract

The strongest next engineering PR is a verifier-reproduction tranche. It is
complete only when:

1. the exact pinned draft profile is named
2. compatible and incompatible upstream implementations are enumerated
3. deterministic KATs are committed
4. at least two independent verifiers agree on every valid and invalid vector
5. every one-bit signature and public-key mutation is rejected unless the
   encoding explicitly permits equivalence
6. parser, CPU, memory, and stack bounds are measured
7. no Script, wallet, registry, or consensus file changes
8. the release hold remains machine-enforced

The initial audit establishes that the currently pinned C++ and Simplicity
lines cannot serve as the second verifier for the pinned draft. That is an
explicit blocking result, not a reason to relax item 4.

## Gates Before Any Consensus Proposal

A SHRINCS profile may enter consensus-design review only after:

1. a stable, exact specification and parameter set
2. a security proof covering the selected construction and usage bounds
3. independently reproduced KATs and differential verification
4. strict canonical encodings and bounded verifier resources
5. current implementation, dependency, and advisory review
6. side-channel and fault analysis for signers
7. a complete state-management and static-backup recovery design
8. hardware-signer feasibility evidence
9. a Bitcoin/PQBTC-specific sighash and domain-separation review
10. independent cryptographic review
11. independent consensus-code audit
12. a separate public go/no-go record

## Validation

```bash
python3 contrib/shrincs/check_manifest.py
python3 -m unittest discover -s ci/test -p 'test_shrincs_candidate.py'
```

Passing these commands proves only that the research pins, compatibility
classifications, release hold, and state-safety admission contract have not
drifted. It does not prove SHRINCS secure or production ready.
