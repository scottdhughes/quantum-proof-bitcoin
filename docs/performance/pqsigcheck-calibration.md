# PQSigCheck calibration (ML-DSA-65)

**Scope:** Deterministic, release-mode measurements for ML-DSA verify and QPB sighash. No consensus constants are changed by this document.

## How to run
```
cargo run --release --bin bench_perf -- --iters 2000 --warmup 200
```
- `--iters`: measurement iterations (default 2000)
- `--warmup`: warmup iterations (default 200)

## What it measures
1) **ML-DSA verify (raw pqcrypto)** — Dilithium3 verify directly.
2) **ML-DSA verify (consensus path)** — goes through `verify_pq`, including alg_id parsing and length checks.
3) **QPB sighash** — `qpb_sighash` for a representative P2QPKH tx (1-in, 2-out) with deterministic data.

## Example output (Apple M-series laptop, Rust release build)
```
iters=2000 warmup=200
MLDSA verify (raw pqcrypto): total 0.154s, 76778.6 ns/op (13024.47 ops/sec)
MLDSA verify (consensus path): total 0.141s, 70380.0 ns/op (14208.59 ops/sec)
QPB sighash (P2QPKH 1-in-2-out): total 0.005s, 2304.9 ns/op (433859.05 ops/sec)
Derived (ns/verify = 71840.2): block budget 0.0359 s, tx budget 0.0029 s
sample sighash msg32=d1a5227cb8677ddfb8811c4c50b9222538a6227a1ead0c8094ddf09ba36861ac
```

## Interpreting results
- Let `verify_ms = ns_per_verify / 1e6`.
- To target a block-level PQSigCheck time budget `target_ms`, use:
  `budget = floor(target_ms / verify_ms)`.
- The harness also prints derived times using current consensus budgets:
  - `MAX_PQSIGCHECK_BUDGET * verify_time`
  - `MAX_PQSIGCHECK_PER_TX * verify_time`
- Use multiple machines/runs to build a safety margin before proposing any consensus changes.

## Record your runs
| Machine / CPU | Rust version | iters | verify ns/op (consensus path) | sighash ns/op | Suggested block budget | Notes |
|---------------|--------------|-------|--------------------------------|---------------|------------------------|-------|
| (fill)        | (fill)       | 2000  | (fill)                         | (fill)        | (calc)                 |       |

## Notes
- Consensus limits are **unchanged** by this document; this is guidance + tooling only.
- The harness is deterministic: one keypair, one signature, one sample tx, repeated in tight loops.
- Do not add this bench to CI; run locally in `--release`.
