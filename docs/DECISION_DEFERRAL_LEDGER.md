# PQBTC v1 Decision-Deferral Ledger

## Status: TRACKED
## Spec-ID: PQBTC-DEFERRALS-v1
## Frozen-By: gate-v1-bootstrap-20260223
## Consensus-Relevant: NO

## Purpose
Record v1 delivery decisions that intentionally defer full-scope implementation,
and define the concrete work required for a full-and-complete post-v1 program.

## Deferred Decisions

### 1. Node + consensus first
- v1 state: node validation, script semantics, policy/relay, fuzz/bench, and PQ-first CI are implemented.
- deferred: wallet/keypool UX and end-user signing flows.
- full-complete delta:
  - descriptor-native PQ key types
  - wallet keypool generation/backup/recovery invariants
  - PSBT construction/finalization for PQ scripts
  - wallet RPC parity and wallet functional coverage

### 2. Taproot disabled for v1
- v1 state: taproot activation remains `NEVER_ACTIVE` on PQBTC deployment tracks.
- deferred: coexistence/migration with PQ signature semantics.
- full-complete delta:
  - frozen taproot coexistence spec set
  - activation/deployment process and rollback rules
  - cross-version compatibility and migration functional suites

### 3. PQ-first CI profile
- v1 state: default CI gates PQ suites; legacy profile is explicit opt-in.
- deferred: complete port of the remaining legacy corpus.
- full-complete delta:
  - either full PQ migration of all legacy suites
  - or permanent dual-profile guarantees with documented compatibility boundaries

### 4. Fixed v1 wire/profile
- v1 state: `ALG_ID=0x00`, `PK_script` fixed at 33 bytes, signature fixed at 4480 bytes.
- deferred: multi-algorithm evolution path.
- full-complete delta:
  - `ALG_ID` registry and governance
  - version negotiation and backward-compat parsing guarantees
  - activation policy and interop tests for new formats

### 5. Fixed pre-taproot sighash mode
- v1 state: pre-taproot PQ paths are fixed to `SIGHASH_ALL`.
- deferred: hashtype negotiation/versioning.
- full-complete delta:
  - frozen PQ sighash mode spec
  - mode negotiation and replay/malleability test coverage

### 6. Frozen deterministic network identity with future-dated genesis
- v1 state: constants remain frozen; functional framework includes mocktime alignment shim.
- deferred: long-horizon operational hardening for this posture.
- full-complete delta:
  - permanent mocktime/test-harness guardrails
  - long-run restart/reorg consistency and soak coverage under PQ traffic

### 7. Bench envelope instrumentation mode
- v1 state: CI enforces fixed PQ bench envelopes for sign/verify acceptance.
- deferred: independent per-operation accounting tied to runtime behavior.
- full-complete delta:
  - expose measured (not pre-populated) hash/compression/search counters
  - validate measured counters against frozen envelopes with bounded variance
  - add adversarial/perf-regression suites that fail on envelope drift

## Post-v1 Full-Complete Program (Execution Order)
1. Wallet completeness and PSBT parity.
2. Taproot/PQ coexistence design + deployment path.
3. Multi-alg registry and forward-compat parser strategy.
4. CI completion (full migration or permanent dual-profile contract).
5. Operational SLO hardening and adversarial throughput validation.
6. Bench instrumentation hardening from fixed-envelope mode to measured accounting.
