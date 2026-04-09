# PQBTC Track A 90-Day Roadmap

## Status: ACTIVE
## Spec-ID: TRACK-A-90D-v1
## Frozen-By: roadmap-pass-20260406
## Consensus-Relevant: NO
## Timebox: 2026-04-06 through 2026-07-05

## Purpose

Turn `TRACK_A_NATIVE_PQ_BITCOIN.md` into an execution plan for the next ninety
days.

This roadmap is intentionally biased toward **native-chain credibility** rather
than novelty theater. The repo does not need a new thesis in this window. It
needs confidence, coverage, and sharper ownership of the remaining migration
surface.

## Day-90 Outcomes

By July 5, 2026, the repo should have:

1. at least one owned Taproot-replacement wallet/RPC/descriptor/PSBT tranche
   moved from deferred posture into explicit semantics plus tests
2. a tighter CI completeness contract with the highest-value backlog suites
   either promoted, rewritten, or explicitly frozen with durable rationale
3. a refreshed and validated post-v1 operational evidence bundle
4. a clearer measured-runtime instrumentation plan, with either landed counters
   or an explicit checked-in decision on what remains deferred
5. a crisp external positioning story explaining how PQBTC differs from
   Blockstream's Liquid/Simplicity path without treating that path as the enemy

## Roadmap Rules

- Do not restart the chain design in this window.
- Do not swap out PQSig rc2 merely because an adjacent architecture looks more
  deployable.
- Prefer evidence-producing work over speculative architecture work.
- Prefer one fully-owned migration tranche over five vague partial surfaces.
- If tradeoffs are required, choose correctness and explicit scope over breadth.

## Phase 1: Confidence And Slice Selection
## Window: 2026-04-06 through 2026-05-03

### Objectives

- lock the first owned post-matrix migration slice for `#23`
- remove ambiguity around which CI backlog work matters first
- refresh local confidence in the required gate and operator evidence paths

### Primary Work

1. Pick the first owned Taproot-replacement product-facing slice.
   Candidate surfaces:
   - `rpc_psbt.py`
   - `wallet_createwalletdescriptor.py`
   - `wallet_address_types.py`
   - descriptor- or PSBT-facing docs already tracked under `docs/`
2. Write the exact semantics for that slice before broad implementation.
3. Audit current `pq_backlog` and `deferred` suites and rank them by:
   - direct relevance to the replacement path
   - operator risk if left ambiguous
   - value as required-gate candidates
4. Re-run and inspect the current required PQ-first functional gate locally.
5. Reproduce and validate the current `OPS_SLO` evidence path so the repo has a
   fresh operational baseline before new churn.

### Exit Criteria

- one first migration slice is explicitly named and scoped
- its acceptance semantics are written down in repo docs
- the highest-value backlog suites are ranked, not just listed
- current required-gate health is understood
- the current ops evidence path is reproducible on demand

## Phase 2: First Owned Migration Tranche
## Window: 2026-05-04 through 2026-05-31

### Objectives

- land the first non-trivial Taproot-replacement tranche beyond pure matrix
  freezing
- convert at least one deferred product-facing surface into explicit semantics
  and tests

### Primary Work

1. Implement the chosen `#23` tranche end to end.
2. Add or update functional coverage so the tranche is exercised in the current
   repo posture, not just documented.
3. Update all affected docs so wallet/RPC/descriptor/PSBT behavior matches the
   actual runtime contract.
4. Decide whether the covered suites become:
   - `pq_required`
   - `pq_backlog` with sharper ownership
   - `dual_profile` with durable rationale

### Preferred Shape

The best tranche for this window is one that is:

- visible to users and operators
- narrow enough to finish cleanly
- strong enough to prove the repo can move beyond block-validation-only seams

### Exit Criteria

- at least one product-facing replacement surface is implemented and testable
- the affected suites have an explicit CI disposition
- the docs no longer imply broader semantics than the code actually owns

## Phase 3: CI Contract Tightening And Ops Hardening
## Window: 2026-06-01 through 2026-06-21

### Objectives

- reduce ambiguity in the CI contract
- strengthen post-v1 operator confidence under PQ load

### Primary Work

1. Promote the best next backlog suites or explicitly freeze them with durable
   rationale.
2. Refresh the checked-in `OPS_SLO` evidence bundle under a new dated stamp.
3. Extend adversarial throughput and scenario coverage under the current PQ
   load assumptions where that improves sign-off confidence.
4. Check for gate flakiness or evidence drift introduced by the migration
   tranche.

### Concrete Targets

- the CI completeness doc reflects actual owned priorities rather than a large
  undifferentiated backlog
- `contrib/soak/capture_ops_slo_evidence.sh` and
  `contrib/soak/validate_ops_slo_evidence.py --signoff ...` produce a fresh,
  valid bundle
- operator-facing restart, reorg, large-witness, and RBF churn confidence is
  refreshed after the tranche lands

### Exit Criteria

- the CI contract is tighter than it was on April 6, 2026
- the repo has a fresh validated ops evidence bundle
- no new unresolved ambiguity has been introduced into the required PQ gate

## Phase 4: Instrumentation And Positioning Checkpoint
## Window: 2026-06-22 through 2026-07-05

### Objectives

- finish the quarter with a clear technical and narrative checkpoint
- avoid ending the ninety-day push with code only and no decision framing

### Primary Work

1. Land measured bench/runtime counters if they are ready, or write the exact
   deferred decision and why.
2. Write a short checked-in comparison note:
   - PQBTC native chain
   - Liquid/Simplicity opt-in verifier path
   - where they overlap
   - where they fundamentally diverge
3. Produce the next-step checkpoint:
   - what shipped in the ninety-day window
   - what remains on `#23`
   - what deserves the next ninety-day slot

### Exit Criteria

- instrumentation direction is explicit rather than hand-wavy
- the repo has a durable external positioning note
- the next roadmap can start from facts, not memory

## Prioritization Order

If bandwidth is constrained, work in this order:

1. first owned `#23` migration tranche
2. CI disposition and gate confidence
3. operational hardening and fresh evidence
4. bench instrumentation hardening
5. external comparison and narrative polish

## Explicit Deferrals For This Window

Do not make these the main effort before July 5, 2026:

- full signature-stack replacement
- consensus redesign for a new cryptographic family
- sidechain pivot or Liquid-first product reset
- speculative mainnet go-to-market planning without stronger implementation
  evidence
- broad multi-feature expansion that outruns tests and operator confidence

## Success Test

This roadmap succeeds if, by July 5, 2026, a technically serious reader can see
that PQBTC is:

- still clearly a native post-quantum Bitcoin project
- materially less ambiguous about its replacement-path migration surface
- more credible operationally
- better positioned against adjacent post-quantum Bitcoin-like approaches
