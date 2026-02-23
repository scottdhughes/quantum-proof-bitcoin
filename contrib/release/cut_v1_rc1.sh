#!/usr/bin/env bash
# Cut PQBTC v1.0.0-rc1 after deterministic + bench preflight checks.

export LC_ALL=C

set -euo pipefail

TAG_NAME="${1:-v1.0.0-rc1}"
TARGET_REF="${2:-HEAD}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

if git rev-parse --verify --quiet "refs/tags/${TAG_NAME}" >/dev/null; then
  echo "Tag already exists: ${TAG_NAME}" >&2
  exit 1
fi

python3 ci/test/check_deterministic_artifacts.py

if [ ! -x "build/bin/bench_pqbtc" ]; then
  echo "Missing build/bin/bench_pqbtc; build benchmarks before cutting RC tag" >&2
  exit 1
fi

python3 ci/test/check_pqsig_bench.py \
  --bench build/bin/bench_pqbtc \
  --repeat 3 \
  --baseline-out /tmp/pqsig_bench_baseline_"${TAG_NAME}".json

git tag -a "${TAG_NAME}" "${TARGET_REF}" -m "PQBTC ${TAG_NAME}"

echo "Created tag ${TAG_NAME} at ${TARGET_REF}"
echo "Release notes: docs/RELEASE_V1_RC1.md"
echo "Runbook: docs/RUNBOOK_V1_RC1.md"
