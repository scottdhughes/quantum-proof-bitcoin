# PQBTC SHRINCS-Family Decision Track

## Status: SUPERSEDED - RELEASE HOLD
## Spec-ID: SHRINCS-DECISION-TRACK-v1
## Started: 2026-04-13
## Consensus-Relevant: NO

## Supersession Notice

This is a historical sequencing memo. Its statements that rc2 can remain a
shipping baseline are withdrawn by `PQSIG_PRODUCTION_READINESS.md`. rc2 remains
useful only as a held integration fixture, and no replacement may activate
without the standards-conformance and review gates in that record.

## Purpose

Define how PQBTC should evaluate a future SHRINCS-family or adjacent
SPHINCS-family profile without destabilizing the current Track A execution path.

This document is a sequencing rule, not an activation decision.

## Current Truth

- The implemented research profile remains `PQSig rc2` on `ALG_ID=0x01`, under
  a production release hold.
- The implemented signature path is hash-based in shape and claims a
  SPHINCS-family construction (`WOTS+C` + `PORS+FP` + hypertree), with fixed
  33-byte `PK_script` encoding and fixed 4480-byte signatures. Its conformance
  and security claims are not established.
- PQBTC has working Bitcoin integration around a PQ-shaped signature fixture.
  It does not yet have a cryptographically approved production signature
  profile.
- `PQSIG_CANDIDATE_SELECTION.md` selects FIPS 204 `ML-DSA-44` as the primary
  engineering candidate and retains FIPS 205 `SLH-DSA-SHA2-128s` as the
  conservative fallback. Production remains on `HOLD`.

## Decision Rule

- Do not swap out the active signature profile during ordinary tranche work.
- Do not treat adjacent Blockstream / Delving Bitcoin work as an automatic
  architecture override.
- Do evaluate SHRINCS-family options in parallel, with explicit acceptance
  criteria and a clean go / no-go checkpoint before launch-facing signoff.
- Do not reinterpret the ML-DSA engineering selection as consensus approval or
  as permission to weaken the SLH-DSA fallback evidence.

The repo should avoid mixing two kinds of uncertainty in one step:

1. unfinished Bitcoin-integration work
2. algorithm-family replacement work

If both move at once, failures become hard to classify and the project loses the
ability to reason about causality.

## What Counts As "On Track"

PQBTC is on track for SHRINCS-family evaluation only if all of the following
stay true:

1. `PQSig rc2` remains only a stable, held regression baseline for current
   Track A integration work.
2. The future-profile lane stays explicitly separate from required-gate tranche
   ownership.
3. Any future-profile candidate is judged against operator and wallet reality,
   not just signature size or paper appeal.
4. No future profile becomes `ACTIVE` without a dedicated allocation,
   implementation, benchmark, test-vector, wallet, PSBT, and signoff pass.

## Evaluation Questions

### 1. Cryptographic Fit

- Is the candidate stateless, stateful, or hybrid?
- What exact backup and key-rotation burden does it impose on operators?
- Does it improve confidence or only reduce size?

### 2. Bitcoin-System Fit

- How does it affect `PK_script` size, witness size, and block economics?
- Does it fit the repo's fixed-size script and PSBT assumptions cleanly?
- Does it preserve simple consensus-critical parsing and validation rules?

### 3. Wallet And Recovery Fit

- Can ordinary wallets back up and restore it safely?
- Can multi-device use be made coherent without hidden footguns?
- Does it improve or worsen operator recovery relative to the current rc2
  profile?

### 4. Implementation Fit

- Is there a trustworthy C++ implementation path?
- Are KATs, vectors, and verifier structure mature enough to audit?
- Can the repo support it without turning `src/crypto/pqsig` into a permanent
  experiment shelf?

### 5. Launch Fit

- Does the candidate meaningfully improve the launch story?
- Is the benefit large enough to justify replacing the held profile before any
  block-0 launch proposal?
- If not, should it instead become a post-launch or later-`ALG_ID` migration
  candidate?

## Required Evidence Before Any Pivot

Before any proposal to replace `PQSig rc2`, require:

1. a named candidate profile and exact parameter set
2. a written wire-format and internal-parameter spec
3. a clear `ALG_ID` allocation plan
4. deterministic KATs and fixture vectors
5. signer and verifier benchmarks against the current rc2 profile
6. wallet, descriptor, and PSBT impact analysis
7. recovery and operator-backup analysis
8. a recommendation memo that says either:
   - retain the production `HOLD`
   - or select a final-standard candidate for a separate engineering proposal

`PQSIG_CANDIDATE_SELECTION.md` satisfies item 8 by selecting `ML-DSA-44` for
engineering work while retaining the production hold. Items 2, 3, 5, 6, and 7
remain future consensus-design work, and independent implementation plus
external cryptographic review remain mandatory before that work starts.

## Near-Term Default

The default near-term choice is:

- do not ship rc2 or represent it as production-ready cryptography
- preserve current wallet / PSBT / CI / ops work as integration evidence
- retain the isolated FIPS 205 and FIPS 204 reference evidence
- focus the next evidence work on the selected ML-DSA-44 candidate without
  entering consensus code

## Immediate Next Steps

1. Preserve the rc2 production hold and executable conformance evidence.
2. Retain the completed isolated `SLH-DSA-SHA2-128s` reference prototype.
3. Retain the completed isolated `ML-DSA-44` comparator.
4. Apply the measured `ML_DSA_44_ENGINEERING_CANDIDATE` decision without
   treating it as production approval.
5. Obtain a genuinely independent ML-DSA implementation and external
   cryptographic review.
6. Measure supported-platform and worst-case transaction and block costs.
7. Only after those gates, write a separate consensus-design specification.
8. Make no `ALG_ID`, Script, wallet, or activation change until the readiness
   gates are met in a separate proposal.

## Non-Goals

- silently changing the active algorithm
- implying that PQBTC already ships SHRINCS-family semantics
- reopening the Track A thesis itself
- blocking current tranche work on speculative signature-family research
