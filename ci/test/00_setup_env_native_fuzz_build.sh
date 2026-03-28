#!/usr/bin/env bash
#
# Copyright (c) 2026-present The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

# shellcheck disable=SC1091
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/00_setup_env_native_fuzz.sh"

export RUN_FUZZ_TESTS=false
export RUN_PQSIG_FUZZ_SMOKE=false
export BUILD_BENCH_BINARIES=false
export BUILD_FUZZ_BINARY=true
