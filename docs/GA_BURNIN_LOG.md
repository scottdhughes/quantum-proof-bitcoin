# PQBTC v1 RC Burn-in Log

## Status: TRACKED
## Spec-ID: GA-BURNIN-LOG-v1
## Frozen-By: ga-governance-20260223
## Consensus-Relevant: NO

## Window

- Start: 2026-02-24
- End: 2026-03-09
- Cadence: weekly checkpoints

## Checkpoint Completion Rules

1. A checkpoint is incomplete until every required evidence field below is populated with a concrete artifact path, run link, or command output summary.
2. All gate evidence for a checkpoint must refer to the same candidate commit unless the deviation is explicitly called out in `Summary`.
3. Any unresolved `priority:P0` or `priority:P1` finding at checkpoint close blocks GA promotion.
4. Any edit to `src/crypto/pqsig/pqsig.cpp` or `src/script/interpreter.cpp` during the burn-in window resets the active checkpoint until a fresh verify-path review and evidence bundle are attached.

## Required Evidence Bundle Per Checkpoint

1. Deterministic artifacts:
   - command: `python3 ci/test/check_deterministic_artifacts.py`
   - artifact/run link:
2. Bench envelope:
   - command: `python3 ci/test/check_pqsig_bench.py --bench build/bin/bench_pqbtc --repeat 3`
   - artifact/run link:
3. Unit suites:
   - command: `build/bin/test_pqbtc --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests`
   - artifact/run link:
4. Functional suites:
   - command: `build/test/functional/test_runner.py --jobs=1 feature_pqsig_basic.py feature_pqsig_multisig.py mempool_pq_limits.py mempool_pq_stress.py feature_pq_reorg.py feature_pq_block_limits.py`
   - artifact/run link:
5. Fuzz smoke:
   - command: `cp src/test/data/pqsig/fuzz/pqsig_verify/* <tmpdir>/ && rm -f <tmpdir>/README.md && FUZZ=pqsig_verify build-fuzz/bin/fuzz <tmpdir>`
   - artifact/run link:
6. Gatekeeper on merge commit:
   - run link:
7. Soak campaign:
   - command: `RUNS=<n> JOBS=1 contrib/soak/run_pq_mempool_soak.sh`
   - artifacts path:
8. Verify-path review:
   - touched files:
   - CFC verdict / review link:
   - acceptance-set impact summary:
9. Rollback trigger review:
   - no malformed-PQ acceptance widening:
   - no crash/hang/assert under relay or mempool stress:
   - no restart/reorg reconciliation regression:
   - reject reason for witness item `10,001` bytes stable before/after restart:
   - RBF churn campaign stable:

## Post-Stack Baseline (After #44/#45/#46)

- Date (UTC): 2026-03-03
- Baseline merge commit (`main`): `7c07609f414dce5546257837a539a63c7ce32bd5` (PR #46)
- Stack merge commits:
  - `4f2f88338ba55b6559655273e9b97951eb0d7d3f` (PR #44)
  - `3caffa2319d67772bc31e9f4ae67e7abad6ba0f0` (PR #45)
  - `7c07609f414dce5546257837a539a63c7ce32bd5` (PR #46)
- PR evidence:
  - PR #44 CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22526800151>
  - PR #44 Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22526800160>
  - PR #45 CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22549996865>
  - PR #45 Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22549996838>
  - PR #46 CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22606688905>
  - PR #46 Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22606688908>
- Main baseline runs for `7c07609f414dce5546257837a539a63c7ce32bd5`:
  - CI: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22612154224>
  - Gatekeeper: <https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22612154206>
- Notes:
  - PR #46 merged via admin path due repository base-branch policy behavior.
  - `CI / test each commit` is non-required and was still in progress at merge time.
  - All protected required status-check contexts for PR #46 were green at merge time.

## Checkpoint Template

- Status:
  - [ ] complete
  - [ ] incomplete
- Date (UTC):
- Commit / tag under test:
- Previous checkpoint / merge-base:
- Environment:
- Reviewer / approver:
- Summary:
- Evidence bundle:
  - deterministic artifacts artifact/run:
  - bench envelope artifact/run:
  - unit suites artifact/run:
  - functional suites artifact/run:
  - fuzz smoke artifact/run:
  - gatekeeper run link:
- Soak artifacts path:
- Soak summary (`runs/passed/failed`):
- SLO summary:
  - relay / restart / reorg:
  - resource envelope:
- Verify-path review:
  - touched files:
  - CFC verdict / review link:
  - acceptance-set impact summary:
- Rollback trigger review:
  - malformed-PQ acceptance widening:
  - crash/hang/assert under stress:
  - restart/reorg reconciliation regression:
  - witness `10,001` byte reject stability:
  - RBF churn stability:
- Findings:
  - `priority:P0`:
  - `priority:P1`:
  - `priority:P2`:
- Actions opened:
- Gate status:
  - [ ] deterministic artifacts
  - [ ] bench envelope
  - [ ] unit suites
  - [ ] functional suites
  - [ ] fuzz smoke
  - [ ] gatekeeper on merge commit

## Week 1 Checkpoint (2026-03-02)

- Status:
  - [x] complete
  - [ ] incomplete
- Date (UTC): 2026-03-05
- Commit / tag under test: `8bd1e97bda` + local working tree capture
- Previous checkpoint / merge-base: post-stack baseline `7c07609f414dce5546257837a539a63c7ce32bd5`
- Environment: local macOS workspace, repo-local functional tmpdir prefix under `build/ga-burnin/week1-backfill-2026-03-05/test_runner`
- Reviewer / approver: Scott local operator capture; GA approver pending
- Summary:
  - Fresh March 5 rerun completed deterministic, bench, unit, seeded fuzz smoke, functional PQ suite, and a 10/10 soak window.
  - Historical soak batch `build/soak-artifacts/pq-mempool-20260228T184455Z` is excluded because it failed during HTTP server startup and RPC binding, not during PQ relay or mempool execution.
  - GA remains blocked by the open `priority:P1` offset-`3272` accepted-mutation finding tracked in GitHub issue `#48` and the lack of current merge-commit gatekeeper evidence for the dirty local candidate.
- Evidence bundle:
  - deterministic artifacts artifact/run: `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/deterministic.txt`
  - bench envelope artifact/run: `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/bench.txt`
  - unit suites artifact/run: `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/unit.txt`
  - functional suites artifact/run: `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/functional.txt`
  - fuzz smoke artifact/run: `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/fuzz.txt`
  - gatekeeper run link: main baseline merge-commit gatekeeper for `7c07609f414dce5546257837a539a63c7ce32bd5` (`https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22612154206`)
- Soak artifacts path: `build/soak-artifacts/pq-mempool-20260305T204116Z`
- Soak summary (`runs/passed/failed`): `10 / 10 / 0` (`docs/artifacts/ga-burnin/week1-backfill-2026-03-05/soak-summary.json`, `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/results.tsv`)
- SLO summary:
  - relay / restart / reorg: passed in `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/functional.txt` (`mempool_pq_stress.py`, `feature_pq_reorg.py`) and sustained 10 soak passes
  - resource envelope: soak durations ranged `15s` to `46s` across the March 5 window (`docs/artifacts/ga-burnin/week1-backfill-2026-03-05/results.tsv`)
- Verify-path review:
  - touched files: no verify-path source files changed during the capture window; review targeted the locked v1 verify path
  - CFC verdict / review link: `docs/artifacts/ga-burnin/offset-3272-analysis-2026-03-05.md`, `docs/artifacts/ga-burnin/issue-48-waiver-vs-mitigation-2026-03-06.md`, GitHub blocker `#48`, and `/Users/scott/satoshi-reports/reports/2026/03/2026-03-05_144815_deep-repo-review.md`
  - acceptance-set impact summary: bounded March 6 sweep shows targeted auth-path windows reject, targeted count-field bytes reject, and the surviving known mutation remains offset `3272` at the first byte of the layer-2 WOTS region
- Rollback trigger review:
  - malformed-PQ acceptance widening: blocked by open `priority:P1` offset-`3272` accepted-mutation finding in GitHub issue `#48`; treat as unresolved GA risk
  - crash/hang/assert under stress: none in the March 5 clean rerun; excluded February 28 batch failed before test execution due RPC bind contention
  - restart/reorg reconciliation regression: none observed in `docs/artifacts/ga-burnin/week1-backfill-2026-03-05/functional.txt`
  - witness `10,001` byte reject stability: maintained in `mempool_pq_limits.py`
  - RBF churn stability: maintained in `mempool_pq_stress.py` and the 10/10 soak window
- Findings:
  - `priority:P0`: none
  - `priority:P1`: offset `3272` layer-2 WOTS byte mutation still verifies; tracked in `docs/artifacts/ga-burnin/offset-3272-analysis-2026-03-05.md` and GitHub issue `#48`
  - `priority:P2`: current candidate lacks merge-commit gatekeeper evidence because the capture was taken from a dirty local working tree
- Actions opened:
  - hold GA promotion
  - require explicit sign-off or mitigation for the offset-`3272` accepted mutation
  - use `docs/artifacts/ga-burnin/issue-48-waiver-vs-mitigation-2026-03-06.md` as the March 7 disposition memo
  - keep GitHub issue `#48` open until mitigation lands or an accepted-set waiver is approved
  - rerun gatekeeper on an actual merge commit before any GA decision
- Gate status:
  - [x] deterministic artifacts
  - [x] bench envelope
  - [x] unit suites
  - [x] functional suites
  - [x] fuzz smoke
  - [ ] gatekeeper on merge commit

## Week 2 Checkpoint and GA Decision (2026-03-09)

- Status:
  - [ ] complete
  - [x] incomplete
- Date (UTC): 2026-03-05 snapshot for the 2026-03-09 checkpoint
- Commit / tag under test: `8bd1e97bda` + local working tree snapshot
- Previous checkpoint / merge-base: `docs/artifacts/ga-burnin/week1-backfill-2026-03-05`
- Environment: local macOS workspace, reusing the March 5 clean-host evidence bundle
- Reviewer / approver: Scott local operator snapshot; GA approver pending
- Summary:
  - Current Week 2 entry intentionally reuses the fresh March 5 evidence bundle while the dated checkpoint remains in the future.
  - The entry is incomplete until the burn-in window closes on 2026-03-09, merge-commit gatekeeper evidence is current, and the open offset-`3272` `priority:P1` blocker in GitHub issue `#48` is resolved or explicitly signed off.
- Evidence bundle:
  - deterministic artifacts artifact/run: `docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/deterministic.txt`
  - bench envelope artifact/run: `docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/bench.txt`
  - unit suites artifact/run: `docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/unit.txt`
  - functional suites artifact/run: `docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/functional.txt`
  - fuzz smoke artifact/run: `docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/fuzz.txt`
  - gatekeeper run link: latest protected main baseline run remains `https://github.com/scottdhughes/quantum-proof-bitcoin/actions/runs/22612154206` (not current for the local dirty candidate)
- Soak artifacts path: `build/soak-artifacts/pq-mempool-20260305T204116Z`
- Soak summary (`runs/passed/failed`): `10 / 10 / 0` (`docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/soak-summary.json`, `docs/artifacts/ga-burnin/week2-in-progress-2026-03-05/results.tsv`)
- SLO summary:
  - relay / restart / reorg: current snapshot remains clean; no regressions observed in the reused March 5 functional and soak bundle
  - resource envelope: current soak durations remain within the March 5 `15s` to `46s` window
- Verify-path review:
  - touched files: no additional verify-path changes since the March 5 backfill snapshot
  - CFC verdict / review link: `docs/artifacts/ga-burnin/offset-3272-analysis-2026-03-05.md`, `docs/artifacts/ga-burnin/issue-48-waiver-vs-mitigation-2026-03-06.md`, GitHub blocker `#48`, and `/Users/scott/satoshi-reports/reports/2026/03/2026-03-05_144815_deep-repo-review.md`
  - acceptance-set impact summary: unchanged blocker; bounded March 6 sweep still isolates the surviving targeted mutation to WOTS offset `3272` while targeted auth/count boundary bytes reject
- Rollback trigger review:
  - malformed-PQ acceptance widening: still blocked by the open offset-`3272` finding in GitHub issue `#48`
  - crash/hang/assert under stress: none in the March 5 clean rerun
  - restart/reorg reconciliation regression: none observed
  - witness `10,001` byte reject stability: maintained
  - RBF churn stability: maintained
- Findings:
  - `priority:P0`: none
  - `priority:P1`: offset `3272` layer-2 WOTS byte mutation still verifies; tracked in GitHub issue `#48`
  - `priority:P2`: Week 2 window still open; merge-commit gatekeeper evidence not yet current
- Actions opened:
  - keep GA decision unset
  - refresh the checkpoint on or after 2026-03-09 with current merge-commit evidence
  - use `docs/artifacts/ga-burnin/issue-48-waiver-vs-mitigation-2026-03-06.md` for the pre-March 9 disposition decision
  - keep GitHub issue `#48` open until mitigation lands or an accepted-set waiver is approved
  - resolve or explicitly sign off the offset-`3272` blocker before promotion
- Gate status:
  - [x] deterministic artifacts
  - [x] bench envelope
  - [x] unit suites
  - [x] functional suites
  - [x] fuzz smoke
  - [ ] gatekeeper on merge commit
- Decision:
  - [ ] Promote to `v1.0.0`
  - [ ] Hold and cut `v1.0.0-rc2`
- Decision notes:
  - GA decision intentionally left unset on 2026-03-05 because the dated Week 2 checkpoint is still in progress and the offset-`3272` `priority:P1` blocker in GitHub issue `#48` remains open.
