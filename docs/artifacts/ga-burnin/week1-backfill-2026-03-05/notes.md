# week1-backfill-2026-03-05

- Captured at (UTC): 2026-03-05T20:46:33Z
- Candidate commit: 8bd1e97bda89192cc3a6ddbf4e0e53051b5ef86f
- Candidate short SHA: 8bd1e97bda
- Worktree status:
```text
 M docs/CI.md
 M docs/GA_ACCEPTANCE_CHECKLIST.md
 M docs/GA_BURNIN_LOG.md
 M docs/RUNBOOK_V1_RC1.md
 M src/test/data/pqsig/fuzz/pqsig_verify/README.md
 M src/test/data/pqsig/invalid_vectors.json
 M src/test/fuzz/pqsig_verify.cpp
 M src/test/pqsig_tests.cpp
?? contrib/pqsig-ref/repro_offset_3272.py
?? contrib/soak/capture_ga_burnin_evidence.sh
?? docs/artifacts/
?? src/test/data/pqsig/fuzz/pqsig_verify/seed_count_mismatch.bin
?? src/test/data/pqsig/fuzz/pqsig_verify/seed_kat_structured.bin
?? src/test/data/pqsig/fuzz/pqsig_verify/seed_layer2_wots_offset_3272.bin
?? src/test/data/pqsig/fuzz/pqsig_verify/seed_pk_root_mismatch.bin
?? src/test/data/pqsig/fuzz/pqsig_verify/seed_pk_seed_mismatch.bin
```

## Raw build-log locations

- Deterministic: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/logs/deterministic.txt`
- Bench: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/logs/bench.txt`
- Unit: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/logs/unit.txt`
- Fuzz: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/logs/fuzz.txt`
- Functional: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/logs/functional.txt`
- Offset 3272 repro: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/logs/offset-3272.txt`
- Functional tmpdir prefix: `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/test_runner`
- Soak artifacts: `/Users/scott/quantum-proof-bitcoin/build/soak-artifacts/pq-mempool-20260305T204116Z`

## Notes

- This capture requires a clean host state: no stray `pqbtcd` processes and no listeners on RPC or P2P regtest port ranges.
- The local fuzz smoke copied the tracked corpus from `src/test/data/pqsig/fuzz/pqsig_verify` into `/Users/scott/quantum-proof-bitcoin/build/ga-burnin/week1-backfill-2026-03-05/pqsig_fuzz_smoke` before running.
- The soak batch at `/Users/scott/quantum-proof-bitcoin/build/soak-artifacts/pq-mempool-20260228T184455Z` is excluded from GA evidence because it failed during HTTP server startup and RPC binding, not during PQ relay or mempool execution.
- Remote blocker tracking for the accepted offset-`3272` mutation lives in GitHub issue `#48`.
