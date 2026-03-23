# CI/CD Documentation

This document describes the PQBTC v1 CI posture for RC stabilization.

## Overview

PQC-facing CI enforcement is split across two workflows:

| Workflow | Purpose |
|---|---|
| `ci.yml` | Build, tests, benchmarks, fuzz, and PQ gating across platforms |
| `measured-bench.yml` | Dedicated runtime variance gate for PQSig bench performance |
| `gatekeeper.yml` | Docs-first freeze-gate checks against the selected base ref |

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
  - Explicit test list for PQ-first functional gating.
  - Default: `feature_pqsig_basic.py feature_pqsig_multisig.py mempool_pq_limits.py mempool_pq_stress.py feature_pq_reorg.py feature_pq_block_limits.py`
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

The helper writes tracked summaries under `docs/artifacts/ops-slo/<date>/` and raw logs under `build/ops-slo/<date>/`.

CI-runner style invocation:

```bash
STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh
```

Expected local wall-clock time for the full capture is roughly 5-10 minutes on current developer hardware, depending on soak durations.

The capture includes:

1. `mempool_pq_limits.py`
2. `mempool_pq_stress.py`
3. `feature_pq_reorg.py`
4. `RUNS=10 JOBS=1 contrib/soak/run_pq_mempool_soak.sh`
