# PQBTC v1.0.0-rc1 Sign-off Evidence

## Status: FROZEN
## Spec-ID: RC-SIGNOFF-v1.0.0-rc1
## Frozen-By: rc-stack-20260223
## Consensus-Relevant: NO

## Scope
This document captures immutable pre-tag evidence for `v1.0.0-rc1` from the
stacked landing branches and local verification runs.

## Branch Stack (Merge Order)
1. `codex/rc-pr-a-rails-docs` @ `c4f4c08a54d0`
2. `codex/rc-pr-b-genesis-identity` @ `fe46f6028561`
3. `codex/rc-pr-c-limits-policy-taproot` @ `5ee4ee32d546`
4. `codex/rc-pr-d-pqsig-module` @ `966a12bb02de`
5. `codex/rc-pr-e-script-consensus-integration` @ `494dc89c3a12`
6. `codex/rc-pr-f-functional-node-first` @ `4a2ef4363a0e`
7. `codex/rc-pr-g-ci-release-runbook` @ `ed2c0242358c`

Captured at: `2026-02-23T02:21:54Z` (UTC)

## Gatekeeper Verification (Per-PR Base/Head)
All checks below passed:
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base gate0.75-naming --head codex/rc-pr-a-rails-docs`
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base codex/rc-pr-a-rails-docs --head codex/rc-pr-b-genesis-identity`
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base codex/rc-pr-b-genesis-identity --head codex/rc-pr-c-limits-policy-taproot`
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base codex/rc-pr-c-limits-policy-taproot --head codex/rc-pr-d-pqsig-module`
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base codex/rc-pr-d-pqsig-module --head codex/rc-pr-e-script-consensus-integration`
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base codex/rc-pr-e-script-consensus-integration --head codex/rc-pr-f-functional-node-first`
- `python3 contrib/devtools/gatekeeper.py --rules contrib/devtools/gatekeeper.yaml --base codex/rc-pr-f-functional-node-first --head codex/rc-pr-g-ci-release-runbook`

## Deterministic Artifact Verification
Command:
```bash
python3 ci/test/check_deterministic_artifacts.py
```
Output:
```text
Deterministic artifacts verified
  genesis_sha256=264b33774915c5c8b5860b9b1675b6f46407cf0a7d06906acef7754e72bc5bf0
  pqsig_kat_sha256=bb7e12c2c98909c40e06de54e210947d36337ec94382792f3a67e32355fc33d0
```

## Bench Envelope Verification
Command:
```bash
python3 ci/test/check_pqsig_bench.py --bench build/bin/bench_pqbtc --repeat 3 --baseline-out /tmp/pqsig_bench_baseline_rc1.json
```
Output:
```text
PQSIG bench envelope check passed (3 run(s))
```
Baseline file digest:
`/tmp/pqsig_bench_baseline_rc1.json` sha256 = `ed9beeed0150f561466a0f2f8d6344646e58baa035d96bcf57c5739ac4e9641b`

## Unit Test Verification
Command:
```bash
build/bin/test_pqbtc --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests
```
Output:
```text
*** No errors detected
Running 5 test cases...
```

## Functional Test Verification
Command:
```bash
build/test/functional/test_runner.py \
  test/functional/feature_pqsig_basic.py \
  test/functional/feature_pqsig_multisig.py \
  test/functional/mempool_pq_limits.py \
  test/functional/feature_pq_reorg.py \
  test/functional/feature_pq_block_limits.py
```
Result:
- `feature_pqsig_basic.py` passed
- `feature_pqsig_multisig.py` passed
- `mempool_pq_limits.py` passed
- `feature_pq_reorg.py` passed
- `feature_pq_block_limits.py` passed

## Fuzz Smoke Verification
Command:
```bash
FUZZ=pqsig_verify build-fuzz/bin/fuzz <tmpdir>
```
Output:
```text
pqsig_verify: succeeded against 0 files in 0s.
```

## Locked Decisions and Deferred Scope References
- Locked RC decisions and v1 constraints:
  `docs/RELEASE_V1_RC1.md`
- Operator/tester execution posture:
  `docs/RUNBOOK_V1_RC1.md`
- Deferred-to-post-RC items:
  `docs/DECISION_DEFERRAL_LEDGER.md`
  `docs/POST_RC_EPICS.md`

## Tag Procedure (Post-Merge)
After PR-A through PR-H are merged to `main`, run:
```bash
contrib/release/cut_v1_rc1.sh v1.0.0-rc1 HEAD
```
