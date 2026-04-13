# PQBTC SHRINCS-Family Decision Track

## Status: ACTIVE
## Spec-ID: SHRINCS-DECISION-TRACK-v1
## Started: 2026-04-13
## Consensus-Relevant: NO

## Purpose

Define how PQBTC should evaluate a future SHRINCS-family or adjacent
SPHINCS-family profile without destabilizing the current Track A execution path.

This document is a sequencing rule, not an activation decision.

## Current Truth

- The live chain profile remains `PQSig rc2` on `ALG_ID=0x01`.
- The current active signature path is already hash-based and SPHINCS-family in
  construction (`WOTS+C` + `PORS+FP` + hypertree), with fixed 33-byte
  `PK_script` encoding and fixed 4480-byte signatures.
- PQBTC therefore already has real PQ signing and verification. The open
  question is not "should the repo become post-quantum at all," but "should the
  current active profile later be replaced by a stronger or more practical
  SHRINCS-family alternative?"

## Decision Rule

- Do not swap out the active signature profile during ordinary tranche work.
- Do not treat adjacent Blockstream / Delving Bitcoin work as an automatic
  architecture override.
- Do evaluate SHRINCS-family options in parallel, with explicit acceptance
  criteria and a clean go / no-go checkpoint before launch-facing signoff.

The repo should avoid mixing two kinds of uncertainty in one step:

1. unfinished Bitcoin-integration work
2. algorithm-family replacement work

If both move at once, failures become hard to classify and the project loses the
ability to reason about causality.

## What Counts As "On Track"

PQBTC is on track for SHRINCS-family evaluation only if all of the following
stay true:

1. `PQSig rc2` remains the stable execution baseline for current Track A work.
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
- Is the benefit large enough to justify redoing the active profile before a
  block-0 launch?
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
   - stay on `rc2` for launch
   - or pivot before launch for explicitly stated reasons

## Near-Term Default

The default near-term choice is:

- keep shipping Track A on `PQSig rc2`
- keep the current wallet / PSBT / CI / ops work focused on the active profile
- treat SHRINCS, SHRIMPS, and other adjacent ideas as an evidence-gathering lane
  until the repo has enough execution maturity to compare them cleanly

## Immediate Next Steps

1. Keep current Track A tranche work anchored to the active rc2 profile.
2. Build a small comparison memo between:
   - current `PQSig rc2`
   - a concrete SHRINCS-family candidate
   - any compact-signature follow-on worth serious consideration later
3. Decide whether the first future-profile step should be:
   - a docs-only adoption memo
   - a neutral `ALG_ID` allocation with explicit present-day rejection
   - or a real implementation branch outside the current required gate

## Non-Goals

- silently changing the active algorithm
- implying that PQBTC already ships SHRINCS-family semantics
- reopening the Track A thesis itself
- blocking current tranche work on speculative signature-family research
