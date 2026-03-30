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
- post-v1 update: fixed watch-only `pq(<PK_script>)` descriptor import/list/inference is implemented for standard single-sig PQ P2WSH outputs.
- post-v1 update: `#19` validates backup/recovery of statically imported bounded PQ descriptor batches only.
- post-v1 update: active ranged private `pqpriv(...)` receive/change managers are implemented with dedicated PQ address generation and private export.
- deferred: wallet/keypool UX and end-user signing flows.
- full-complete delta:
  - PSBT construction/finalization for PQ scripts
  - wallet RPC parity and wallet functional coverage
  - spendability/signing parity for generated PQ outputs

### 2. Taproot disabled for v1
- v1 state: taproot activation remains `NEVER_ACTIVE` on PQBTC deployment tracks.
- post-v1 update: taproot posture is frozen to explicit replacement in `TAPROOT_POSTURE.md`.
- full-complete delta:
  - activation/deployment process and rollback rules for the replacement path
  - cross-version compatibility and migration functional suites for the replacement path

### 3. PQ-first CI profile
- v1 state: default CI gates PQ suites; legacy profile is explicit opt-in.
- deferred: complete port of the remaining legacy corpus.
- full-complete delta:
  - either full PQ migration of all legacy suites
  - or permanent dual-profile guarantees with documented compatibility boundaries

### 4. Fixed rc2 wire/profile
- rc2 state: `ALG_ID=0x01`, `PK_script` fixed at 33 bytes, signature fixed at 4480 bytes, and `PK.root` is exact-root bound.
- post-v1 update: `ALG_ID` registry structure and governance rules are frozen.
- post-v1 update: parser compatibility and explicit non-negotiation rules are frozen.
- post-v1 update: neutral `future-0x02` forward-compatible fixture path is frozen and testable while remaining invalid in current releases.
- deferred: activation/interoperability rules for any non-active future profile.

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
2. Taproot replacement posture + deployment path.
3. CI completion (full migration or permanent dual-profile contract).
4. Operational SLO hardening and adversarial throughput validation.
5. Bench instrumentation hardening from fixed-envelope mode to measured accounting.
