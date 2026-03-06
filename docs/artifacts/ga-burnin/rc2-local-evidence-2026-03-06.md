# RC2 Local Evidence Snapshot (2026-03-06)

## Scope

Local validation snapshot for the `v1.0.0-rc2` PQSig reprofile under `ALG_ID=0x01`.

## Commands and Outcomes

1. Deterministic artifacts
   - `python3 ci/test/check_deterministic_artifacts.py`
   - result: pass

2. Focused unit/script suites
   - `build/bin/test_pqbtc --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests`
   - result: pass

3. Bench envelope
   - `python3 ci/test/check_pqsig_bench.py --bench build/bin/bench_pqbtc --repeat 3`
   - result: pass

4. Offset-3272 regression probe
   - `python3 contrib/pqsig-ref/repro_offset_3272.py`
   - result: `original_verify=True`, `mutated_verify=False`

5. Seeded fuzz smoke
   - `cp src/test/data/pqsig/fuzz/pqsig_verify/* <tmpdir>/ && rm -f <tmpdir>/README.md && FUZZ=pqsig_verify build-fuzz/bin/fuzz <tmpdir>`
   - result: pass (`pqsig_verify: succeeded against 9 files in 0s.`)

6. PQ functional suite
   - `build/test/functional/test_runner.py --jobs=1 feature_pqsig_basic.py feature_pqsig_multisig.py mempool_pq_limits.py mempool_pq_stress.py feature_pq_reorg.py feature_pq_block_limits.py`
   - result: pass

7. Soak campaign
   - `RUNS=10 JOBS=1 contrib/soak/run_pq_mempool_soak.sh`
   - artifacts: `build/soak-artifacts/pq-mempool-20260306T060015Z`
   - summary: `runs=10`, `passed=10`, `failed=0`

## Remaining Gap

Local evidence is complete for the rc2 branch, but issue `#48` is not ready to close yet.

Required remaining remote evidence:

1. push the rc2 branch
2. open a PR against `main`
3. obtain green required CI and Gatekeeper on the merge-commit candidate
4. record the merge-commit evidence in `docs/GA_BURNIN_LOG.md`
