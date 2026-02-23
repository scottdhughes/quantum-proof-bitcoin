# PQBTC v1.0.0 GA Acceptance Checklist

## Status: TRACKED
## Spec-ID: GA-CHECKLIST-v1.0.0
## Frozen-By: ga-governance-20260223
## Consensus-Relevant: NO

## Purpose

Define hard release gates for promoting from `v1.0.0-rc1` to `v1.0.0`.

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
   - `build/test/functional/test_runner.py --jobs=1 feature_pqsig_basic.py feature_pqsig_multisig.py mempool_pq_limits.py feature_pq_reorg.py feature_pq_block_limits.py`
5. Fuzz smoke pass:
   - `FUZZ=pqsig_verify build-fuzz/bin/fuzz <tmpdir>`
6. Gatekeeper pass on merge commit:
   - `.github/workflows/gatekeeper.yml` successful for `main`.

## Decision Record

- Decision date (UTC):
- Approver:
- Release decision:
  - [ ] Promote to `v1.0.0`
  - [ ] Hold and cut `v1.0.0-rc2`
- Notes:

