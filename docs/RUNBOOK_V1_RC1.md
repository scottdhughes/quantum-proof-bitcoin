# PQBTC v1.0.0-rc1 Operator/Tester Runbook

## Status: TRACKED
## Spec-ID: RUNBOOK-v1.0.0-rc1
## Frozen-By: rc-prep-20260223
## Consensus-Relevant: NO

## Scope

Operational checklist for validating and operating the v1 release candidate.

## Preconditions

1. Build from a clean tree and clean build directory.
2. Ensure deterministic artifacts verify cleanly:
   - `/Users/scott/quantum-proof-bitcoin/ci/test/check_deterministic_artifacts.py`
3. Ensure gatekeeper passes for the merge base:
   - `/Users/scott/quantum-proof-bitcoin/contrib/devtools/gatekeeper.py`

## Startup and Time Posture

The frozen genesis timestamps are future-dated relative to some environments.

1. Functional framework already aligns `-mocktime` on start/restart.
2. Manual regtest invocations should set `-mocktime` at or above genesis time if startup complains about future blocks.

Example:

```bash
build/bin/pqbtcd -regtest -daemon -mocktime=1772086500
```

## Consensus/Semantics Posture

1. `CHECKSIG` and `CHECKMULTISIG` are PQ-only in pre-taproot paths.
2. Taproot is disabled (`NEVER_ACTIVE`) in v1.
3. PQ wire constraints are strict:
   - pubkey script push: 33 bytes
   - signature push: 4480 bytes
   - `ALG_ID=0x00`

## Required Validation Sequence

1. Unit tests:

```bash
build/bin/test_pqbtc --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests
```

2. Functional tests:

```bash
build/test/functional/test_runner.py --jobs=1 \
  feature_pqsig_basic.py \
  feature_pqsig_multisig.py \
  mempool_pq_limits.py \
  mempool_pq_stress.py \
  feature_pq_reorg.py \
  feature_pq_block_limits.py
```

3. Bench + fuzz smoke:

```bash
python3 ci/test/check_pqsig_bench.py --bench build/bin/bench_pqbtc --repeat 3

tmpdir=$(mktemp -d)
FUZZ=pqsig_verify build-fuzz/bin/fuzz "$tmpdir"
rm -rf "$tmpdir"
```

## GA Rollback Triggers (Safety-Only Window)

The GA burn-in window (2026-02-24 through 2026-03-09) uses strict rollback triggers:

1. Any open `priority:P0` or `priority:P1` issue in milestone `v1.0.0-ga` at decision time.
2. Any deterministic artifact drift (`contrib/genesis/generated_constants.json` or `src/test/data/pqsig/kat_v1.json`).
3. Any acceptance widening bug where malformed PQ payloads are accepted in consensus paths.
4. Any crash, assert, hang, or persistent restart/reorg inconsistency under PQ relay/mempool stress.
5. Any required branch-protection context failing on the merge commit.

If any trigger is hit, hold GA and continue on `v1.0.0-rc2` path.

## Failure Handling

1. Signature NULLFAIL rejects on expected-valid spends:
   - clean rebuild (`--clean-first`), rerun failing functional suite.
2. Bench envelope mismatch:
   - capture output baseline and compare against frozen expected constants.
3. Deterministic artifact drift:
   - regenerate and investigate seed/profile drift before merge.
4. Relay/mempool stress instability:
   - capture repro tx set, rollback to last known-good `main`, and track under GA safety issues before proceeding.
5. Consensus acceptance widening:
   - block release, add regression test/fuzz seed, and require merged fix plus clean rerun of full GA sequence.

## Out of Scope for v1 RC

- Wallet keypool and signing UX.
- Taproot coexistence migration.
- Multi-alg version negotiation.
