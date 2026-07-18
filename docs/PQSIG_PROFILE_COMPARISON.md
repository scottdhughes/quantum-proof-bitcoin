# PQBTC Signature-Profile Comparison Memo

## Status: SUPERSEDED - RELEASE HOLD
## Spec-ID: PQSIG-PROFILE-COMPARISON-v1
## Started: 2026-04-13
## Consensus-Relevant: NO

## Supersession Notice

The 2026-04-13 launch recommendation in this memo is withdrawn. Repository
conformance review found that the implemented rc2 path does not satisfy
security-critical invariants of the construction it claims. The controlling
decision and current candidate plan are in
`PQSIG_PRODUCTION_READINESS.md`. Historical execution-maturity observations
below do not establish cryptographic security.

## Purpose

Record the historical comparison of the implemented `PQSig rc2` profile
against one concrete SHRINCS-family candidate and one compact-signature
follow-on candidate, so the repo can make a disciplined launch decision instead
of chasing whichever idea looks newest.

This is a decision memo, not an activation spec.

## Scope And Evidence Level

- `PQSig rc2` size and integration facts below are repo-backed current-state
  facts; its construction and security claims are not validated.
- SHRINCS and SHRIMPS facts below are limited to what the repo's research corpus
  currently asserts directly:
  - `SHRINCS: 324-byte stateful post-quantum signatures with static backups`
  - `SHRIMPS: 2.5 KB post-quantum signatures across multiple stateful devices`
- Where this memo makes an engineering judgment beyond those direct statements,
  treat it as an explicit inference rather than a frozen repo fact.

## Compared Profiles

### 1. Implemented Held Profile: `PQSig rc2`

- Status: implemented for research and regression testing; production held.
- Claimed construction: stateless SPHINCS-family profile using `WOTS+C` +
  `PORS+FP` + hypertree. The implementation is nonconformant with critical
  rules of that construction.
- Signature size: `4480` bytes.
- Public-key script size: `33` bytes.
- Claimed `q_s`: `2^40`; not established for the implementation.
- Current repo posture: consensus, wallet managers, PSBT path, mempool,
  reorg, and tranche-level CI ownership already exist around this profile.

### 2. Concrete Candidate: SHRINCS-Style Profile

- Status: external research/reference candidate only.
- Repo-backed description: `324-byte stateful post-quantum signatures with
  static backups`.
- Repo interpretation today: strongest current lineage reference for the
  design ancestry behind `Spec.md`.
- Working assumption for comparison: a stateful, much smaller-signature
  profile with a more demanding operator recovery story than the current rc2
  baseline.

### 3. Compact Follow-On Candidate: SHRIMPS-Style Profile

- Status: external research/reference candidate only.
- Repo-backed description: `2.5 KB post-quantum signatures across multiple
  stateful devices`.
- Repo interpretation today: high-value follow-on for compact-signature and
  multi-device thinking, but less likely than SHRINCS to be the immediate
  source behind the current spec.
- Working assumption for comparison: a stateful or state-coordinated profile
  that trades some compactness for a more explicit multi-device model.

## Comparison Table

| Dimension | `PQSig rc2` | SHRINCS-style candidate | SHRIMPS-style candidate |
| --- | --- | --- | --- |
| Current repo status | Implemented; held | Research only | Research only |
| Signature size | `4480` bytes | `324` bytes | `2.5 KB` |
| State model | Stateless | Stateful | Stateful / coordinated multi-device |
| Wallet / PSBT integration in repo | Real | None | None |
| Consensus integration in repo | Real | None | None |
| Operator recovery simplicity | Higher | Lower | Medium at best |
| Launch readiness | Blocked | Not evaluated | Not evaluated |
| Migration cost from today | None | Very high | Very high |
| Potential bandwidth / block-space upside | Baseline | Very high | Moderate to high |
| Best role right now | Regression/integration fixture | Historical research input | Historical research input |

## What The Comparison Means

### `PQSig rc2` Has Execution Maturity, Not Security Evidence

`PQSig rc2` is the only profile here with real consensus-critical parsing,
signing, verification, wallet flow, PSBT flow, and tranche-level CI ownership
inside the repo. That matters more than signature-size aesthetics while the
project is freezing launch-facing behavior. That integration maturity cannot
compensate for a nonconformant signature construction.

### SHRINCS Wins On Compactness, But Reopens The Hardest Product Questions

The repo-backed SHRINCS reference is attractive because `324` bytes is a major
economic and usability improvement over `4480` bytes. But the same reference is
also explicitly stateful and backup-sensitive. That means a serious SHRINCS
adoption effort is not just a verifier swap. It is a wallet, backup, operator,
and recovery redesign project.

This is an inference from the repo's own framing around "static backups" and
"stateful-versus-stateless fallback behavior," not a claim that the repo has
already solved those details.

### SHRIMPS Looks Like A More Practical Compactness Research Lane Than An
Immediate Launch Pivot

The repo's current framing of SHRIMPS is useful: it is a strong follow-on for
compact signatures and multi-device operation, but it is not yet positioned as
the likely direct source of the active spec. That makes it more credible as a
later design lane than as the next thing to jam into the current launch path.

## Decision Criteria

Any replacement for `PQSig rc2` requires all of the following:

1. materially better system economics, not just a nicer signature-size number
2. a wallet/recovery model that is safe for ordinary operators
3. a credible C++ implementation and KAT/vector story
4. a clear `ALG_ID` and wire-format plan
5. a bounded migration cost that does not erase current Track A progress
6. independent cryptographic review and consensus-code audit

If those conditions are not met, no profile should be activated.

## Recommendation

### Launch Recommendation Today

Hold production activation. `PQSig rc2` is not a launch baseline.

Reason:

- its WOTS path does not enforce the fixed digit-sum invariant
- its PORS path does not implement distinct-index grinding or the cited
  authentication-set construction
- its hypertree implementation does not establish the claimed signing budget
- repo-local KATs compare two implementations of the same behavior rather than
  an independent standard or construction

### Parallel Research Recommendation

Rank the replacement evaluation lanes this way:

1. FIPS 205 `SLH-DSA-SHA2-128s` as the conservative, hash-based reference
   prototype
2. FIPS 204 `ML-DSA-44` as the standardized efficiency comparator
3. NIST SP 800-230 profiles only after the draft becomes final and their strict
   usage limits are designed into wallet behavior

### Practical Interpretation

The right question is not:

- "Which signature profile sounds coolest?"

The right question is:

- "Which profile gives PQBTC the best chance of launching as a coherent,
  operable block-0 chain?"

Today, no profile has production approval.

## Next Actions

1. Keep rc2 only as a held integration fixture.
2. Build the isolated standards-conformance prototypes defined in
   `PQSIG_PRODUCTION_READINESS.md`.
3. Revisit consensus integration only after independent vectors, differential
   testing, performance evidence, wallet analysis, and external review exist.

## Non-Goals

- claiming that PQBTC already ships SHRINCS or SHRIMPS
- implying that smaller signatures automatically mean a better launch choice
- reopening the active Track A tranche queue around speculative crypto changes
