# PQBTC v1.0.0 GA Acceptance Checklist

## Status: TRACKED
## Spec-ID: GA-CHECKLIST-v1.0.0
## Frozen-By: ga-governance-20260223
## Consensus-Relevant: NO

## Purpose

Define hard, evidence-backed release gates for promoting from `v1.0.0-rc1` to `v1.0.0`.

## Scope Rebaseline (Safety-Only GA)

Date: 2026-02-24

`v1.0.0-ga` blockers are restricted to node/consensus safety work:

1. Retained GA P1 issue: `#30` (long-run soak harness under PQ traffic).
2. New GA safety P1 set: `#36`, `#37`, `#38`, `#39`, `#40`.
3. Deferred from GA to post-v1 milestone: `#18`, `#21`, `#24`, `#27`, `#33`.
4. `MAX_BLOCK_WEIGHT` remains fixed at `16,000,000` WU for this GA window.

## Hard Gates (Must All Pass)

1. No open issues labeled `priority:P0` in milestone `v1.0.0-ga`.
2. No open issues labeled `priority:P1` in milestone `v1.0.0-ga`.
3. Required branch protection checks pass on merge commit to `main`.
4. Required technical evidence is attached and current.

## Required Evidence

1. Deterministic artifacts check pass:
   - `python3 ci/test/check_deterministic_artifacts.py`
2. Bench envelope check pass (`repeat=3`):
   - `python3 ci/test/check_pqsig_bench.py --bench build/bin/bench_pqbtc --repeat 3`
3. Unit suites pass:
   - `build/bin/test_pqbtc --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests`
4. PQ functional suite pass:
   - `build/test/functional/test_runner.py --jobs=1 feature_pqsig_basic.py feature_pqsig_multisig.py mempool_pq_limits.py mempool_pq_stress.py feature_pq_reorg.py feature_pq_block_limits.py`
5. Fuzz smoke pass:
   - `FUZZ=pqsig_verify build-fuzz/bin/fuzz <tmpdir>`
6. Gatekeeper pass on merge commit:
   - `.github/workflows/gatekeeper.yml` successful for `main`.
7. Rollback trigger review completed with no trigger breach:
   - no consensus acceptance widening from malformed PQ signatures
   - no crash/hang/assertion under relay/mempool stress campaign
   - no restart/reorg reconciliation regression under PQ-heavy traffic
   - witness item `10,001` bytes remains rejected with stable reject reason before/after restart
   - RBF churn campaign (five sequential replacements with large witnesses) completes with no orphaned mempool state

## Activation/Rollback State Machine

1. `PRECHECK`:
   - required gate commands run clean on candidate merge commit
2. `BURNIN_ACTIVE`:
   - burn-in findings triaged into `priority:P0/P1/P2`
   - any rollback trigger breach transitions immediately to `ROLLBACK_HOLD`
3. `GA_READY`:
   - zero open `priority:P0` and `priority:P1` in milestone `v1.0.0-ga`
   - all hard gates and required evidence are current
4. `ROLLBACK_HOLD`:
   - GA promotion blocked
   - proceed via `v1.0.0-rc2` path until all blockers are resolved and PRECHECK is rerun

## Decision Record

- Decision date (UTC):
- Approver:
- Release decision:
  - [ ] Promote to `v1.0.0`
  - [ ] Hold and cut `v1.0.0-rc2`
- Notes:
