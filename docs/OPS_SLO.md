# PQBTC Post-v1 Operational SLOs

## Status: TRACKED
## Spec-ID: OPS-SLO-v1
## Frozen-By: post-v1-hardening-20260323
## Consensus-Relevant: NO

## Purpose

Define the operator-facing pass/fail thresholds for PQBTC post-v1 operational hardening.

## Required SLO Rules

1. PQ mempool soak pass rate is `10/10`.
2. No crash, hang, or assertion failure is allowed during functional stress or soak execution.
3. Restart and reorg reconciliation must return the expected chain tip and mempool contents.
4. Witness item `10,001` bytes must remain rejected before and after restart with a stable reject reason.
5. Large-witness RBF churn must not leave orphaned mempool state after relay, restart, or reorg handling.

## Required Scenarios

1. `mempool_pq_limits.py`
   - covers witness `10,001` byte rejection stability and large-witness RBF churn across restart
2. `mempool_pq_stress.py`
   - covers witness-heavy mempool saturation, repeated large-witness replacements, restart-under-load, and post-load reconciliation
3. `feature_pq_reorg.py`
   - covers competing-branch reorg recovery for PQ-signed spends, including restart before reconnect
4. `run_pq_mempool_soak.sh`
   - repeats `mempool_pq_stress.py` under a fixed pass-rate target

## Operator Signals

For this repository, operator-facing "dashboard signals" are the checked-in machine-readable
summary fields emitted by the required scenarios. This contract does not define or require a
live telemetry or production dashboard system.

Per-scenario JSON summaries use this fixed field set:

- `scenario`
- `pass`
- `duration_s`
- `mempool_before_restart`
- `mempool_after_restart`
- `reorg_result`
- `crash_assert_hang`
- `notes`

The soak aggregate summary extends the fixed field set with:

- `runs`
- `passed`
- `failed`
- `jobs`
- `test`
- `results_tsv`

## Evidence Bundle Contract

Tracked evidence lives under `docs/artifacts/ops-slo/<date>/`.

Required top-level files:

1. `README.md`
2. `manifest.json`
3. `mempool-pq-limits-summary.json`
4. `mempool-pq-stress-summary.json`
5. `feature-pq-reorg-summary.json`
6. `pq-mempool-soak-summary.json`
7. `pq-mempool-soak-results.tsv`

Optional supplemental evidence:

- `soak-summaries/`

The bundle manifest uses this fixed schema:

- `spec_id`
- `stamp`
- `capture_script`
- `soak_runs`
- `artifacts` (the required top-level payload files, excluding `manifest.json` itself)

Raw logs remain untracked under `build/ops-slo/<date>/`.

## Sign-Off Interpretation

Operator sign-off requires:

1. Every required scenario summary has `pass=true`.
2. Every required scenario summary has `crash_assert_hang=false`.
3. The soak summary reports `runs=10`, `passed=10`, and `failed=0`.
4. Restart and reorg reconciliation outcomes remain consistent with the scenario contract.
5. Witness `10,001` byte rejection stability and large-witness RBF churn status remain captured in
   the scenario summaries that produced `pass=true`.

## Invocation And Validation

Local capture:

```bash
contrib/soak/capture_ops_slo_evidence.sh
```

CI-style runner invocation:

```bash
STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh
```

Bundle validation:

```bash
contrib/soak/validate_ops_slo_evidence.py --signoff docs/artifacts/ops-slo/2026-03-23
```

## Reproduce Latest Evidence

The latest checked-in evidence batch lives under `docs/artifacts/ops-slo/2026-03-23/`.

To reproduce a fresh batch locally:

```bash
STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh
```

Then validate the emitted bundle:

```bash
contrib/soak/validate_ops_slo_evidence.py --signoff docs/artifacts/ops-slo/$STAMP
```

## Current Execution Order

1. Close issue `#32` by freezing this bundle contract, publishing the validator, and validating the
   checked-in evidence bundle.
2. Keep issue `#31` open for later adversarial throughput and scenario expansion.
