# PQBTC Signature-Profile Comparison Memo

## Status: ACTIVE
## Spec-ID: PQSIG-PROFILE-COMPARISON-v1
## Started: 2026-04-13
## Consensus-Relevant: NO

## Purpose

Compare the current active `PQSig rc2` profile against one concrete
SHRINCS-family candidate and one compact-signature follow-on candidate, so the
repo can make a disciplined launch decision instead of chasing whichever idea
looks newest.

This is a decision memo, not an activation spec.

## Scope And Evidence Level

- `PQSig rc2` facts below are repo-backed current-state facts.
- SHRINCS and SHRIMPS facts below are limited to what the repo's research corpus
  currently asserts directly:
  - `SHRINCS: 324-byte stateful post-quantum signatures with static backups`
  - `SHRIMPS: 2.5 KB post-quantum signatures across multiple stateful devices`
- Where this memo makes an engineering judgment beyond those direct statements,
  treat it as an explicit inference rather than a frozen repo fact.

## Compared Profiles

### 1. Current Active Profile: `PQSig rc2`

- Status: implemented and active in PQBTC.
- Construction: stateless SPHINCS-family profile using `WOTS+C` + `PORS+FP` +
  hypertree.
- Signature size: `4480` bytes.
- Public-key script size: `33` bytes.
- `q_s`: `2^40`.
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
| Current repo status | Active | Research only | Research only |
| Signature size | `4480` bytes | `324` bytes | `2.5 KB` |
| State model | Stateless | Stateful | Stateful / coordinated multi-device |
| Wallet / PSBT integration in repo | Real | None | None |
| Consensus integration in repo | Real | None | None |
| Operator recovery simplicity | Higher | Lower | Medium at best |
| Launch readiness | High | Low | Low |
| Migration cost from today | None | Very high | Very high |
| Potential bandwidth / block-space upside | Baseline | Very high | Moderate to high |
| Best role right now | Ship baseline | Evaluate as possible pre-launch pivot | Evaluate as later compact-signature follow-on |

## What The Comparison Means

### `PQSig rc2` Wins On Execution Maturity

`PQSig rc2` is the only profile here with real consensus-critical parsing,
signing, verification, wallet flow, PSBT flow, and tranche-level CI ownership
inside the repo. That matters more than signature-size aesthetics while the
project is still freezing launch-facing behavior.

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

Any pre-launch pivot away from `PQSig rc2` should require all of the following:

1. materially better system economics, not just a nicer signature-size number
2. a wallet/recovery model that is safe for ordinary operators
3. a credible C++ implementation and KAT/vector story
4. a clear `ALG_ID` and wire-format plan
5. a bounded migration cost that does not erase current Track A progress
6. evidence that the new profile improves the launch story more than it delays
   the launch

If those conditions are not met, the smaller-signature candidate should remain a
parallel research track rather than become the new active profile.

## Recommendation

### Launch Recommendation Today

Stay on `PQSig rc2` as the launch baseline.

Reason:

- it is real, integrated, and testable now
- the repo is still freezing wallet and migration boundaries
- swapping profiles now would combine unfinished Bitcoin-integration work with
  unfinished algorithm-selection work

### Parallel Research Recommendation

Rank the parallel evaluation lanes this way:

1. SHRINCS-style candidate as the main pre-launch comparison target
2. SHRIMPS-style candidate as a compact-signature follow-on research lane
3. broader algorithm-agility work only after the first two are made concrete

### Practical Interpretation

The right question is not:

- "Which signature profile sounds coolest?"

The right question is:

- "Which profile gives PQBTC the best chance of launching as a coherent,
  operable block-0 chain?"

Today, that answer is still `PQSig rc2`.

## Next Actions

1. Keep current Track A tranche work anchored to `PQSig rc2`.
2. Build a narrower adoption memo for one concrete SHRINCS-style candidate:
   - exact parameter set
   - implementation path
   - wallet/recovery consequences
   - expected `ALG_ID` plan
3. Revisit the pivot question only after that memo can answer the operator story
   as clearly as it answers the cryptography story.

## Non-Goals

- claiming that PQBTC already ships SHRINCS or SHRIMPS
- implying that smaller signatures automatically mean a better launch choice
- reopening the active Track A tranche queue around speculative crypto changes
