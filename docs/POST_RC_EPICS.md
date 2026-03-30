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
- Scope: frozen explicit-replacement posture, deployment/activation path, and migration tests.
- Exit criteria: frozen replacement posture, decision-complete deployment plan, and cross-version test matrix.

3. Multi-algorithm evolution (`ALG_ID` registry)
- Scope: frozen `#24` registry rules, `#25` parser compatibility contract, and `#26` neutral `future-0x02` forward-compatible algorithm version path.
- Exit criteria: met once the neutral forward-compatible path is documented and testable.

4. CI completeness strategy
- Scope: full PQ migration of legacy suites or explicit durable dual-profile guarantees.
- Exit criteria: documented policy with stable gating and ownership.

5. Operational hardening and SLOs
- Scope: freeze `#32` checked-in operator signal and evidence-validation contract around the current soak/restart/reorg assets, then extend `#31` adversarial throughput and scenario coverage under PQ load.
- Exit criteria: checked-in operator signal contract and sign-off thresholds are frozen for `#32`, and the remaining workload expansion under `#31` is complete.

6. Bench instrumentation hardening
- Scope: measured runtime counters replacing fixed-envelope telemetry mode.
- Exit criteria: measured counters validated against frozen acceptance envelopes.
