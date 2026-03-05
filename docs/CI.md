# CI/CD Documentation

This document describes the PQBTC v1 CI posture for RC stabilization.

## Overview

PQC-facing CI enforcement is split across two workflows:

| Workflow | Purpose |
|---|---|
| `ci.yml` | Build, tests, benchmarks, fuzz, and PQ gating across platforms |
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

## Bench and Determinism Checks

Bench enforcement script:

```bash
python3 ci/test/check_pqsig_bench.py \
  --bench build/bin/bench_pqbtc \
  --repeat 3 \
  --baseline-out /tmp/pqsig_bench_baseline.json
```

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
