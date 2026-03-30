# CI/CD Documentation

This document describes the PQBTC v1 CI posture for RC stabilization.

## Overview

PQC-facing CI enforcement is split across two workflows:

| Workflow | Purpose |
|---|---|
| `ci.yml` | Build, tests, benchmarks, fuzz, and PQ gating across platforms |
| `measured-bench.yml` | Dedicated runtime variance gate for PQSig bench performance |
| `gatekeeper.yml` | Docs-first freeze-gate checks against the selected base ref |
| `test-each-commit.yml` | Non-required per-commit replay coverage for multi-commit pull requests |

## RC Stabilization Controls

The following controls are part of the v1 RC posture:

1. Clean rebuilds are required in CI build jobs (`cmake --build ... --clean-first`) to avoid stale binary drift.
2. Gatekeeper runs in dedicated workflow and blocks drift against frozen docs.
3. Deterministic artifact checks run in CI:
   - `contrib/genesis/generated_constants.json`
   - `src/test/data/pqsig/kat_v1.json`
4. PQ bench envelope checks run with repeated samples and baseline output capture.
5. `pqsig_verify` fuzz smoke runs in CI in addition to existing fuzz jobs.

## CI Control Interfaces

These interfaces are intentionally stable for v1:

- `PQBTC_FUNCTIONAL_TESTS`
  - Explicit override for the PQ-first functional gating list.
  - Default source of truth: `ci/test/pq_functional_tests.txt`
- `PQBTC_ENABLE_LEGACY_FUNCTIONAL_TESTS`
  - `true` enables legacy functional profile explicitly.
  - Default keeps legacy non-gating.
- `RUN_GATEKEEPER`
  - Enables gatekeeper execution in container CI script.
  - Default: `true`.
- `RUN_PQSIG_FUZZ_SMOKE`
  - Enables direct `FUZZ=pqsig_verify` smoke run.
  - Default: `true`.
- `PQSIG_BENCH_REPEATS`
  - Number of repeated bench-envelope checks.
  - Default: `3`.
- `PQSIG_BENCH_POLICY`
  - Checked-in bench policy file for exact counters and measured-bench runtime bands.
  - Default: `ci/test/pqsig_bench_policy.json`.

## Gate Ownership

Current workflow and gate ownership remains maintainer-owned:

| Gate | Owner | Notes |
|---|---|---|
| `CI` | `@scottdhughes` | Required build/test/fuzz workflow on pull requests and `main`. |
| `Gatekeeper` | `@scottdhughes` | Freeze-gate and docs drift enforcement. |
| `measured-bench` | `@scottdhughes` | Dedicated runtime variance gate. |
| PQ functional default list | `@scottdhughes` | Canonical file: `ci/test/pq_functional_tests.txt`. |
| Legacy opt-in profile | `@scottdhughes` | Controlled by `PQBTC_ENABLE_LEGACY_FUNCTIONAL_TESTS=true`. |
| `test each commit` workflow | `@scottdhughes` | Non-required long-tail coverage outside the required `CI` wall-clock path. |

## Runtime Budget Contract

Checked-in runtime budget file:

- `ci/test/ci_runtime_budget.json`

Current required-path budgets:

| Workflow | Budget |
|---|---|
| `CI` | under `60` minutes |
| `Gatekeeper` | under `5` minutes |
| `measured-bench` | under `15` minutes |

Wall-clock semantics are frozen as:

- earliest required job start to latest required job completion for that workflow run
- not the sum of job runtimes

Runtime reporting helper:

```bash
gh run view <run-id> --json jobs,createdAt,updatedAt > /tmp/ci-run.json
python3 ci/test/report_ci_runtime.py --workflow CI --input /tmp/ci-run.json
```

or from stdin:

```bash
gh run view <run-id> --json jobs,createdAt,updatedAt | \
  python3 ci/test/report_ci_runtime.py --workflow CI
```

## CI Inventory Contract

The CI completeness foundation is split into two checked-in sources of truth:

- `ci/test/pq_functional_tests.txt`
  - canonical ordered list of the required PQ-first functional tests
- `ci/test/functional_suite_inventory.json`
  - exhaustive classification of the functional test corpus into `pq_required`, `pq_backlog`, `dual_profile`, and `legacy_only`

Inventory validation command:

```bash
python3 ci/test/check_ci_inventory.py
```

The validator is required in the normal PR path and fails if:

1. a functional test file is unclassified
2. an inventory entry references a missing test
3. an entry uses an unknown `policy_class`
4. an owner is empty
5. the `pq_required` entries drift from `ci/test/pq_functional_tests.txt`

## Bench and Determinism Checks

Bench enforcement script:

```bash
python3 ci/test/check_pqsig_bench.py \
  --bench build/bin/bench_pqbtc \
  --repeat 3 \
  --baseline-out /tmp/pqsig_bench_baseline.json
```

Checked-in policy file:

- `ci/test/pqsig_bench_policy.json`
- current default CI uses the `exact_counters` block
- `variance_bands` are enforced only by `measured-bench.yml`

Dedicated measured-bench workflow:

```bash
python3 ci/test/check_pqsig_bench.py \
  --bench build-measured-bench/bin/bench_pqbtc \
  --repeat 8 \
  --enforce-variance \
  --baseline-out /tmp/pqsig_measured_bench_baseline.json
```

Measured-bench rollout:

1. `measured-bench.yml` runs on pull requests, pushes to `main`, weekly schedule, and manual dispatch.
2. The workflow uses the checked-in `variance_bands` block from `ci/test/pqsig_bench_policy.json`.
3. Branch protection should only add the `measured-bench` status after at least one green PR run and one green `main` run.
4. Expected wall-clock budget for the dedicated job is under 15 minutes on `ubuntu-24.04`.

Deterministic artifact check:

```bash
python3 ci/test/check_deterministic_artifacts.py
```

## Gatekeeper Reproduction

```bash
pip3 install pyyaml
python3 contrib/devtools/gatekeeper.py \
  --rules contrib/devtools/gatekeeper.yaml \
  --base origin/main \
  --head HEAD
```

## Local PQ RC Validation

```bash
cmake --build build --clean-first -j8 --target test_pqbtc bench_pqbtc fuzz
build/bin/test_pqbtc --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests
python3 ci/test/check_pqsig_bench.py --bench build/bin/bench_pqbtc --repeat 3
python3 ci/test/check_deterministic_artifacts.py

tmpdir=$(mktemp -d)
cp src/test/data/pqsig/fuzz/pqsig_verify/* "$tmpdir"/
rm -f "$tmpdir"/README.md
FUZZ=pqsig_verify build-fuzz/bin/fuzz "$tmpdir"
rm -rf "$tmpdir"
```

Local measured-bench reproduction:

```bash
cmake -S . -B build-measured-bench -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_BENCH=ON \
  -DBUILD_BITCOIN_BIN=OFF \
  -DBUILD_DAEMON=OFF \
  -DBUILD_CLI=OFF \
  -DBUILD_TX=OFF \
  -DBUILD_UTIL=OFF \
  -DBUILD_UTIL_CHAINSTATE=OFF \
  -DBUILD_KERNEL_LIB=OFF \
  -DBUILD_TESTS=OFF \
  -DBUILD_GUI=OFF \
  -DBUILD_GUI_TESTS=OFF \
  -DBUILD_FUZZ_BINARY=OFF \
  -DENABLE_WALLET=OFF \
  -DENABLE_IPC=OFF \
  -DWITH_ZMQ=OFF \
  -DWITH_USDT=OFF \
  -DENABLE_EXTERNAL_SIGNER=OFF \
  -DWERROR=ON
cmake --build build-measured-bench --clean-first -j3 --target bench_pqbtc
python3 ci/test/check_pqsig_bench.py \
  --bench build-measured-bench/bin/bench_pqbtc \
  --repeat 8 \
  --enforce-variance \
  --baseline-out /tmp/pqsig_measured_bench_baseline.json
```

Functional PQ suites:

```bash
build/test/functional/test_runner.py --jobs=1 \
  feature_pqsig_basic.py \
  feature_pqsig_multisig.py \
  mempool_pq_limits.py \
  mempool_pq_stress.py \
  feature_pq_reorg.py \
  feature_pq_block_limits.py
```

## Post-v1 Ops SLO Capture

Post-v1 operational hardening tracks machine-readable summaries in `docs/artifacts/ops-slo/`.

Operator/local capture:

```bash
contrib/soak/capture_ops_slo_evidence.sh
```

The helper writes tracked summaries under `docs/artifacts/ops-slo/<date>/`, emits a fixed
`manifest.json` and `README.md`, and stores raw logs under `build/ops-slo/<date>/`.

CI-runner style invocation:

```bash
STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh
```

Bundle validation:

```bash
contrib/soak/validate_ops_slo_evidence.py --signoff docs/artifacts/ops-slo/2026-03-23
```

Expected local wall-clock time for the full capture is roughly 5-10 minutes on current developer hardware, depending on soak durations.

The capture includes:

1. `mempool_pq_limits.py`
2. `mempool_pq_stress.py`
3. `feature_pq_reorg.py`
4. `RUNS=10 JOBS=1 contrib/soak/run_pq_mempool_soak.sh`

This capture and validation path is an operator/local evidence surface. It is not a separate
required PR status in the current CI contract.
