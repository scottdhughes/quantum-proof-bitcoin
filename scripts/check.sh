#!/usr/bin/env bash
set -euo pipefail

cargo fmt -- --check
cargo clippy --all-features -- -D warnings
cargo test --all-features
