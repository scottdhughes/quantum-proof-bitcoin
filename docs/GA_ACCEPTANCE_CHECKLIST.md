# PQBTC v1.0.0 GA Acceptance Checklist

## Status: TRACKED
## Spec-ID: GA-CHECKLIST-v1.0.0
## Frozen-By: ga-governance-20260223
## Consensus-Relevant: NO

## Purpose

Define hard, evidence-backed release gates for promoting from `v1.0.0-rc1` to `v1.0.0`.

## Release Posture Update (2026-03-06)

1. `v1.0.0` GA on the original `ALG_ID=0x00` profile is held.
2. The active mitigation path is `v1.0.0-rc2`.
3. rc2 retires `ALG_ID=0x00`, introduces `ALG_ID=0x01`, and resets burn-in because the controlled verify path changed.

## Scope Rebaseline (Safety-Only GA)

Date: 2026-02-24

`v1.0.0-ga` blockers are restricted to node/consensus safety work:

1. Retained GA P1 issue: `#30` (long-run soak harness under PQ traffic).
2. New GA safety P1 set: `#36`, `#37`, `#38`, `#39`, `#40`.
3. Deferred from GA to post-v1 milestone: `#18`, `#21`, `#24`, `#27`, `#33`.
4. `MAX_BLOCK_WEIGHT` remains fixed at `16,000,000` WU for this GA window.

## Consensus Verify-Path Change Control

Files under explicit GA change control:

1. `src/crypto/pqsig/pqsig.cpp`
2. `src/script/interpreter.cpp`
3. `src/crypto/pqsig/params.h`
4. `src/script/script.h`

Rules:

1. No patch during the GA window may widen the accepted set of PQ signatures without an explicit governance override.
2. Any PR touching the files above must attach:
   - a before/after accepted-set impact statement
   - a fresh burn-in checkpoint entry in `docs/GA_BURNIN_LOG.md`
   - a fresh Crypto Falsification Court verdict
   - a rerun of the full required evidence bundle below
3. "Quick fix" or "low-risk cleanup" language does not waive this control.
4. If the accepted/rejected-set impact is unknown, the default state is `ROLLBACK_HOLD` until re-adjudicated.

## Hard Gates (Must All Pass)

1. No open issues labeled `priority:P0` in milestone `v1.0.0-ga`.
2. No open issues labeled `priority:P1` in milestone `v1.0.0-ga`.
3. Required branch protection checks pass on merge commit to `main`.
4. Required technical evidence is attached and current.
5. No unreviewed consensus verify-path changes are present in the GA window.

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
   - `cp src/test/data/pqsig/fuzz/pqsig_verify/* <tmpdir>/ && rm -f <tmpdir>/README.md && FUZZ=pqsig_verify build-fuzz/bin/fuzz <tmpdir>`
6. Gatekeeper pass on merge commit:
   - `.github/workflows/gatekeeper.yml` successful for `main`.
7. Rollback trigger review completed with no trigger breach:
   - no consensus acceptance widening from malformed PQ signatures
   - no crash/hang/assertion under relay/mempool stress campaign
   - no restart/reorg reconciliation regression under PQ-heavy traffic
   - witness item `10,001` bytes remains rejected with stable reject reason before/after restart
   - RBF churn campaign (five sequential replacements with large witnesses) completes with no orphaned mempool state
8. Consensus verify-path control review pass (required if files in the controlled set changed):
   - touched-file list recorded in `docs/GA_BURNIN_LOG.md`
   - accepted-set impact statement attached
   - fresh Crypto Falsification Court verdict attached
   - full evidence bundle rerun on the candidate commit

## Activation/Rollback State Machine

1. `PRECHECK`:
   - required gate commands run clean on candidate merge commit
   - verify-path diff review completed for any touch to the controlled file set
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
  - [x] Hold and cut `v1.0.0-rc2`
- Verify-path files touched during GA window:
  - [ ] No
  - [x] Yes (CFC verdict and accepted-set impact statement attached)
- Notes: `2026-03-06` posture change for issue `#48`: old profile held, rc2 exact-root reprofile active, and fresh burn-in evidence required before any blocker closure.
