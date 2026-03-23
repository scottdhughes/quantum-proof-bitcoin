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

## Machine-Readable Evidence

Tracked evidence lives under `docs/artifacts/ops-slo/<date>/`.

Required files:

1. `mempool-pq-limits-summary.json`
2. `mempool-pq-stress-summary.json`
3. `feature-pq-reorg-summary.json`
4. `pq-mempool-soak-summary.json`
5. `pq-mempool-soak-results.tsv`

Per-scenario JSON summaries use this fixed field set:

- `scenario`
- `pass`
- `duration_s`
- `mempool_before_restart`
- `mempool_after_restart`
- `reorg_result`
- `crash_assert_hang`
- `notes`

Raw logs remain untracked under `build/ops-slo/<date>/`.

## Invocation

Local capture:

```bash
contrib/soak/capture_ops_slo_evidence.sh
```

CI-style runner invocation:

```bash
STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh
```

## Reproduce Latest Evidence

The latest checked-in evidence batch lives under `docs/artifacts/ops-slo/2026-03-23/`.

To reproduce a fresh batch locally:

```bash
STAMP=$(date -u +%Y-%m-%d) contrib/soak/capture_ops_slo_evidence.sh
```

Then review the emitted `*-summary.json` files under `docs/artifacts/ops-slo/$STAMP/`.

## Current Execution Order

1. Close issue `#31` by extending the existing stress and soak assets.
2. Close issue `#32` by publishing this SLO contract and committing evidence artifacts from a clean capture run.
3. Only then move to measured-bench work in issues `#33`, `#34`, and `#35`.
