#!/usr/bin/env bash
# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying COPYING.
# Contained Linux only. Build the exact approved archive, never system libcrypto.
set -euo pipefail
archive=$1
prefix=$2
expected=a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98
test "$(sha256sum "$archive" | cut -d ' ' -f 1)" = "$expected"
test ! -e "$prefix"
build=$(mktemp -d /tmp/pqbtc-backup-openssl.XXXXXX)
tar -xzf "$archive" -C "$build"
cd "$build/openssl-3.6.5"
./Configure --prefix="$prefix" --openssldir="$prefix/ssl" --libdir=lib no-shared no-tests no-module no-engine > "$build/configure.log"
make -j2 > "$build/make.log" 2>&1
make install_sw > "$build/install.log" 2>&1
"$prefix/bin/openssl" version
printf '%s\n' "$expected" > "$prefix/source-archive.sha256"
sha256sum "$prefix/lib/libcrypto.a"
