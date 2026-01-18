# UPSTREAM.md — Gate 0 Baseline

## Bitcoin Core Upstream

| Property | Value |
|----------|-------|
| Tag | `v30.2` |
| Commit | `4d7d5f6b79d4c11c47e7a828d81296918fd11d4d` |
| Imported | 2026-01-18 |

### Verification

```bash
git rev-parse v30.2^{}
# 4d7d5f6b79d4c11c47e7a828d81296918fd11d4d

git show -s --format='%H %D' v30.2
# 4d7d5f6b79d4c11c47e7a828d81296918fd11d4d tag: v30.2
```

## Toolchain

| Tool | Version |
|------|---------|
| cmake | 4.2.1 |
| clang++ | Apple clang 17.0.0 (clang-1700.6.3.2) |
| python3 | 3.9.6 |
| macOS | 26.2 (Build 25C56) |

### Dependencies (Homebrew)

```
boost pkgconf libevent capnp
```

## Build

```bash
cmake -B build -DENABLE_WALLET=ON
cmake --build build -j "$(sysctl -n hw.ncpu)"
```

**Result**: Build completed successfully (100%).

## Test Results

### Unit Tests

```bash
./build/bin/test_bitcoin --run_test=crypto_tests,key_tests,script_tests
```

**Result**: `*** No errors detected`

Suites run:
- `crypto_tests` — 17 test cases
- `key_tests` — 7 test cases
- `script_tests` — 19 test cases

### Functional Tests

```bash
ulimit -n 4096  # Required on macOS
python3 test/functional/test_runner.py wallet_basic.py
```

**Result**: `wallet_basic.py | Passed | 16 s`

### Notes

- macOS requires `ulimit -n 4096` before running functional tests (default FD limit too low)
- Full unit test suite has fixture initialization issues on macOS (AddArg assertion in args.cpp); core crypto/script tests pass

## Preserved Documentation

The following project-specific documentation was preserved from pre-import:

- `docs/Spec.md` — PQSig protocol specification
- `docs/CORE_DIFF_PLAN.md` — Bitcoin Core fork implementation phases
- `docs/README_PQBTC.md` — Project overview (moved from root README.md)

## Safety Artifacts

Created before upstream import:

| Artifact | Purpose |
|----------|---------|
| Tag `pre-core-import-20260118` | Pre-import state snapshot |
| Branch `preimport-docs` | Docs backup before hard reset |

## Next Steps

Proceed to Gate 0.5 (CI Safety Rails + Gatekeeper) as defined in the execution plan.
