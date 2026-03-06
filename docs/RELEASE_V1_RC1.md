# PQBTC v1.0.0-rc1 Release Notes

## Status: TRACKED
## Spec-ID: RELEASE-v1.0.0-rc1
## Frozen-By: rc-prep-20260223
## Consensus-Relevant: NO

## Summary

`v1.0.0-rc1` is the PQ-first release candidate for node/consensus delivery.

## Release Posture Update (2026-03-06)

`v1.0.0` GA on the original profile is held.

Reason:
1. issue `#48` exposed an accepted-set weakness in the old `ALG_ID=0x00` profile.
2. the active release path is now `v1.0.0-rc2`.
3. rc2 retires `ALG_ID=0x00` before GA and introduces the exact public-root profile under `ALG_ID=0x01`.

## Locked v1 Decisions

1. PQSig profile is fixed to `2^40 / 4480B` (`WOTS+C + PORS+FP + hypertree`).
2. `OP_CHECKSIG` and `OP_CHECKMULTISIG` are PQ-only semantics on this chain.
3. Taproot activation remains disabled (`NEVER_ACTIVE`) for v1.
4. Wire formats are fixed for rc1 history:
   - `PK_script = 33 bytes` (`ALG_ID=0x00` + 32-byte core)
   - `SIG = 4480 bytes`
5. Pre-taproot sighash remains fixed `SIGHASH_ALL`.
6. Genesis/network constants are deterministic and frozen.

## Included in RC

1. Deterministic genesis/network identity tooling and committed constants.
2. Full PQSig module with KAT fixtures and strict parsers.
3. Consensus integration for PQ-only `CHECKSIG/CHECKMULTISIG`.
4. Consensus/policy limit updates for large PQ signatures and witness traffic.
5. PQ-first CI gating for functional suites.
6. Bench envelope and deterministic-artifact CI checks.
7. `pqsig_verify` fuzz smoke in CI.

## Tagging Helper

Use `/Users/scott/quantum-proof-bitcoin/contrib/release/cut_v1_rc1.sh` to run RC preflight checks and create the `v1.0.0-rc1` tag.

## Validation Targets

1. Unit: `pqsig_tests`, `pqsig_script_tests`, `script_tests`, `multisig_tests`.
2. Functional: `feature_pqsig_basic`, `feature_pqsig_multisig`, `mempool_pq_limits`, `feature_pq_reorg`, `feature_pq_block_limits`.
3. Bench envelope: `ci/test/check_pqsig_bench.py`.
4. Determinism: `ci/test/check_deterministic_artifacts.py`.
5. Fuzz smoke: `FUZZ=pqsig_verify`.

## Deferred from v1 (Tracked)

See `/Users/scott/quantum-proof-bitcoin/docs/DECISION_DEFERRAL_LEDGER.md` and `/Users/scott/quantum-proof-bitcoin/docs/POST_RC_EPICS.md`.

- Wallet/keypool UX and signing parity.
- Taproot coexistence/replacement design and deployment path.
- Multi-algorithm `ALG_ID` evolution strategy.
- Measured (runtime) bench instrumentation mode.
