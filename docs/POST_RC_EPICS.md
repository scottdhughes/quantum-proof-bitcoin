# PQBTC Post-RC Epic Tracker

## Status: TRACKED
## Spec-ID: POST-RC-EPICS-v1
## Frozen-By: rc-prep-20260223
## Consensus-Relevant: NO

## Purpose

Execution tracker for work required after `v1.0.0-rc1` to reach full-and-complete implementation.

## Epics

1. Wallet completeness and signing parity
- Scope: descriptors, keypool batching, restore/recovery invariants, PSBT finalization, wallet RPC parity, wallet functional coverage.
- Exit criteria: node+wallet end-to-end PQ signing and recovery with CI coverage.

2. Taproot posture beyond v1
- Scope: coexistence or replacement design, frozen spec set, deployment/activation path, migration tests.
- Exit criteria: decision-complete consensus plan with cross-version test matrix.

3. Multi-algorithm evolution (`ALG_ID` registry)
- Scope: version registry, parser compatibility contract, governance and rollout semantics.
- Exit criteria: at least one forward-compatible algorithm version test path.

4. CI completeness strategy
- Scope: full PQ migration of legacy suites or explicit durable dual-profile guarantees.
- Exit criteria: documented policy with stable gating and ownership.

5. Operational hardening and SLOs
- Scope: long-run soak, adversarial throughput tests, restart/reorg resilience under PQ load.
- Exit criteria: agreed SLO dashboard and sign-off thresholds.

6. Bench instrumentation hardening
- Scope: measured runtime counters replacing fixed-envelope telemetry mode.
- Exit criteria: measured counters validated against frozen acceptance envelopes.
