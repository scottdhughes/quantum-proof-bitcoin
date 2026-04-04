# PQBTC Post-RC Epic Tracker

## Status: TRACKED
## Spec-ID: POST-RC-EPICS-v1
## Frozen-By: rc-prep-20260223
## Consensus-Relevant: NO

## Purpose

Execution tracker for work required after `v1.0.0-rc1` to reach full-and-complete implementation.

## Epics

1. Wallet completeness and signing parity
- Status: completed by `#12` wallet confidence closure.
- Delivered scope: descriptor-native PQ wallet managers, restore/recovery invariants, PQ PSBT signing/finalization coverage, and deterministic wallet functional coverage in the required PQ gate.
- Exit criteria: met once node+wallet end-to-end PQ signing and recovery are covered by required CI and default PQ-native unit coverage.

2. Taproot posture beyond v1
- Scope: frozen explicit-replacement posture, concrete dormant replacement deployment/reporting path, frozen migration matrix, and compatibility tests.
- Current state: frozen posture, activation, deployment/reporting, pre-active runtime compatibility evidence, the defined vs active reporting boundary, the first active-semantic negative-control guard, and the first positive PQ-native block-validation seam are now checked in; remaining work is the deferred Taproot-facing wallet/RPC/descriptor/PSBT migration surface tracked under `#23`.
- Exit criteria: frozen replacement posture, concrete dormant deployment/reporting path, and implemented cross-version validation against the frozen matrix.

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
