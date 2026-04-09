# PQBTC Test Cost Posture

## Status: ACTIVE
## Spec-ID: TEST-COST-POSTURE-v1
## Updated: 2026-04-06
## Consensus-Relevant: NO

## Purpose

Protect development throughput on `quantum-proof-bitcoin` when inherited
Bitcoin-style build and CI surfaces are expensive.

This note exists to prevent a bad default:

- tiny code changes
- tiny commits
- large validation tax
- hours of waiting
- little actual product movement

For this repo, that pattern is a workflow failure, not a quality win.

## Core Rule

The unit of progress is the **tranche**, not the commit.

That means:

- many local edits may belong to one validation decision
- many local commits may belong to one push or promotion event
- expensive test campaigns should validate a coherent tranche, not a single
  sentence change or a tiny UI fix

## Validation Ladder

### Tier 0: Cheap Local Proof

Use for:

- docs
- naming
- comments
- resource strings
- non-consensus UI wording
- obvious local refactors with no behavior change

Allowed proof:

- no tests
- or a compile check for the touched binary or library
- or a single direct smoke command if the touched surface is trivial to verify

Do **not** pay for broad functional suites here.

### Tier 1: Narrow Slice Validation

Use for:

- one owned wallet/RPC/descriptor/PSBT slice
- localized signing-path behavior
- small operator-path or tooling behavior changes

Allowed proof:

- touched-target compile
- one small unit test family
- one to three directly relevant functional tests

Examples:

- `wallet_pq_active_ranged.py`
- `wallet_pq_create_tx.py`
- `wallet_pq_descriptors.py`
- `wallet_pq_psbt.py`
- `wallet_pq_send.py`
- `wallet_pq_sendall.py`
- `wallet_pq_sendmany.py`
- `wallet_createwalletdescriptor.py`
- `./build/bin/test_pqbtc --run_test=pqsig_script_tests`

This is the default working tier for Track A.

### Tier 2: Subsystem Promotion

Use for:

- promoting a tranche from "local confidence" to "shared candidate"
- broader wallet/descriptor/PSBT or policy changes
- any change where the touched surface crosses multiple owned seams

Allowed proof:

- targeted bundle for the subsystem
- medium-cost compile plus multiple functional suites
- optional manual push for broader CI visibility

This tier is a deliberate promotion step, not the default after every edit.

### Tier 3: Milestone Evidence

Use for:

- release candidates
- milestone merges
- sign-off
- operator evidence refresh
- full confidence resets after high-risk consensus work

Allowed proof:

- full PQ gate review
- full `OPS_SLO` evidence refresh
- long soak or multi-hour CI-style campaigns

Examples:

- `contrib/soak/capture_ops_slo_evidence.sh`
- `contrib/soak/validate_ops_slo_evidence.py --signoff ...`

This tier should be paid at milestone boundaries, not continuously.

## Push And Promotion Policy

For this repo:

- local commits are cheap
- pushes are expensive
- heavy CI should be treated as a promotion event

Default working policy:

1. edit locally
2. run Tier 0 or Tier 1 proof
3. accumulate a coherent tranche
4. push only when the tranche is worth paying a broader validation cost

Do **not** push every small cleanup if the remote CI path is going to charge
hours of waiting for it.

## Current Track A Default Bundle

When the touched work is in the active Track A wallet/descriptor/PSBT lane,
prefer this order:

1. build the touched target
2. run the narrowest directly relevant unit or functional test
3. stop unless the tranche is being promoted

Current high-value narrow tests:

- `python3 test/functional/wallet_pq_active_ranged.py`
- `python3 test/functional/wallet_pq_create_tx.py`
- `python3 test/functional/wallet_pq_descriptors.py`
- `python3 test/functional/wallet_pq_psbt.py`
- `python3 test/functional/wallet_pq_send.py`
- `python3 test/functional/wallet_pq_sendall.py`
- `python3 test/functional/wallet_pq_sendmany.py`
- `python3 test/functional/wallet_createwalletdescriptor.py`
- `./build/bin/test_pqbtc --run_test=pqsig_script_tests`

Current expensive milestone path:

- `STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh`
- `python3 contrib/soak/validate_ops_slo_evidence.py --signoff docs/artifacts/ops-slo/$STAMP`

## Risk Classes

### Green

- docs
- naming
- UI text
- metadata
- resource files

Default validation: Tier 0 only.

### Yellow

- wallet
- PSBT
- descriptors
- RPC behavior
- operator flows

Default validation: Tier 1, then Tier 2 only when promoting the tranche.

### Red

- consensus
- script validation
- signature encoding
- chain identity
- network identity
- chainstate safety

Default validation: Tier 1 first, then explicit approval before broad or
expensive promotion work.

## Aineko Operating Rules

Aineko may do without asking:

- Tier 0 validation
- Tier 1 validation
- small compile checks
- one to three narrow tests tied directly to the changed slice

Aineko must ask before:

- Tier 2 subsystem-promotion runs that are likely to take substantial time
- Tier 3 milestone evidence runs
- any multi-hour CI or soak campaign
- paying large remote CI cost for a small local change

## Practical Throughput Goal

The repo should spend most of its time in:

- designing tranches
- landing tranche code
- running narrow proofs

It should spend much less time in:

- watching broad CI for tiny changes
- rerunning long suites mid-thought
- paying milestone-grade validation for non-milestone work

## Related References

- [TRACK_A_STATUS.md](TRACK_A_STATUS.md)
- [CI_COMPLETENESS.md](CI_COMPLETENESS.md)
- [OPS_SLO.md](OPS_SLO.md)
- [TRACK_A_90_DAY_ROADMAP.md](TRACK_A_90_DAY_ROADMAP.md)
