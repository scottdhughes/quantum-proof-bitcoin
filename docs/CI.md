# CI/CD Documentation

This document describes the CI infrastructure for PQBTC, including build/test workflows and the Gatekeeper freeze-gate enforcement system.

## Overview

PQBTC uses two GitHub Actions workflows:

| Workflow | Purpose |
|----------|---------|
| `ci.yml` | Multi-platform build + tests + sanitizers (inherited from Bitcoin Core) |
| `gatekeeper.yml` | Freeze-gate enforcement (docs-first) |

## CI Build Matrix

The CI workflow (inherited from Bitcoin Core v30.2) provides comprehensive coverage:

### Core Jobs

| Job | Platform | Compiler | Tests |
|-----|----------|----------|-------|
| macOS native | macOS 14 arm64 | Apple Clang | full suite |
| Windows native | Windows 2022 | MSVC | full suite |
| Linux cross-compile | Ubuntu 24.04 | GCC/Clang | varies by job |

### Sanitizer Jobs

| Job | Sanitizers | Purpose |
|-----|------------|---------|
| ASan + LSan + UBSan | Address, Leak, Undefined | Memory safety |
| TSan | Thread | Data race detection |
| MSan | Memory | Uninitialized memory |

### Fuzz Testing

Fuzz targets are run with ASan/UBSan on both Linux and macOS.

## Gatekeeper (Freeze-Gate Enforcement)

The Gatekeeper enforces the docs-first invariant (I3): **frozen specs must exist on the base branch before consensus-critical code can be modified.**

### How It Works

1. On every PR, Gatekeeper runs `git diff --name-only origin/main...HEAD`
2. Changed files are matched against rule patterns in `contrib/devtools/gatekeeper.yaml`
3. For matching files, Gatekeeper verifies required artifacts exist **on `origin/main`** (not in the PR)
4. Required docs must contain `## Status: FROZEN` header

### Why Check `origin/main`?

Checking the **base branch** (not the PR tree) mechanically enforces docs-first:
- A spec PR must be merged to `main` first
- Only then can a code PR modifying that area pass Gatekeeper
- This prevents "spec + code in same PR" which defeats the safety mechanism

### Gate Rules Summary

| Gate | Protected Paths | Required Artifacts |
|------|-----------------|-------------------|
| 1 | `chainparams*`, `contrib/genesis/**` | `docs/GENESIS.md` *(FROZEN)* |
| 2 | `src/crypto/pqsig/**` | `docs/PQSIG_*.md` *(FROZEN)* + vectors |
| 3 | `src/script/**`, `src/validation.cpp` | 6 frozen specs + vectors |
| 4 | `src/policy/**`, `consensus.h` | `docs/POLICY_LIMITS.md` *(FROZEN)* |
| 4.5 | `src/net*`, `blockencodings.cpp` | `docs/NET_LIMITS.md` *(FROZEN)* |
| 5 | `contrib/pqsign/**` | `docs/PSBT_STRATEGY.md` *(FROZEN)* |
| 6 | `src/wallet/**` | `docs/WALLET.md` *(FROZEN)* |

### STRICT Posture for Script

The Gatekeeper uses a **strict posture** for `src/script/**`:
- No "surface rules only" exception
- ALL 6 Gate 3 prerequisites must exist before any script changes
- This prevents premature consensus drift

## Local Reproduction

### Run Gatekeeper Locally

```bash
# Install dependencies
pip3 install pyyaml

# Run gatekeeper (from repo root)
python3 contrib/devtools/gatekeeper.py \
  --rules contrib/devtools/gatekeeper.yaml \
  --base origin/main \
  --head HEAD
```

### Run Build + Unit Tests

```bash
# macOS
cmake -S . -B build -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_GUI=OFF -DBUILD_BENCH=OFF -DENABLE_WALLET=ON
cmake --build build --parallel $(sysctl -n hw.ncpu)
./build/bin/test_bitcoin --run_test=crypto_tests,key_tests,script_tests

# Linux (Ubuntu 22.04+)
sudo apt-get install -y cmake ninja-build libboost-dev libevent-dev libsqlite3-dev
cmake -S . -B build -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_GUI=OFF -DBUILD_BENCH=OFF -DENABLE_WALLET=ON
cmake --build build --parallel $(nproc)
./build/bin/test_bitcoin
```

### Run Functional Tests

```bash
# Increase file descriptor limit (required on macOS)
ulimit -n 4096

# Run specific test
python3 test/functional/test_runner.py wallet_basic.py

# Run all tests (takes longer)
python3 test/functional/test_runner.py --jobs $(nproc)
```

### Run with Sanitizers

```bash
# ASan + UBSan build
cmake -S . -B build-asan -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -DBUILD_GUI=OFF -DBUILD_BENCH=OFF

cmake --build build-asan --parallel

# Run with sanitizer options
ASAN_OPTIONS="detect_leaks=1:halt_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
./build-asan/bin/test_bitcoin
```

## Frozen Doc Contract

Any document marked `## Status: FROZEN` must include:

```markdown
## Status: FROZEN
## Spec-ID: <stable-identifier>
## Frozen-By: <gate-tag>
## Consensus-Relevant: YES|NO
```

Frozen docs may not contain `TBD` or `TODO` tokens.

### Change Control

- **Errata** (typos, clarifications): allowed, must note in changelog
- **Semantic changes**: treated as hardfork, requires new Spec-ID version

## CI Maintenance Notes

### Test Suite Evolution

As PQBTC diverges from Bitcoin Core (Gate 1+), some upstream functional tests will become irrelevant. Track decisions here:

| Test Category | Status | Notes |
|---------------|--------|-------|
| `crypto_tests` | Must pass | Core cryptography |
| `key_tests` | Evolve | Will need PQ key tests |
| `script_tests` | Evolve | Will need PQ script tests |
| `wallet_basic.py` | Must pass until Gate 6 | Then PQ wallet tests |

### Adding New CI Jobs

When adding PQ-specific CI jobs:
1. Add to `.github/workflows/ci.yml`
2. Document in this file
3. Ensure job names are descriptive

## Related Documentation

- [UPSTREAM.md](UPSTREAM.md) — Bitcoin Core baseline
- [CORE_DIFF_PLAN.md](CORE_DIFF_PLAN.md) — Implementation phases
- Plan file — Gate execution checklist
