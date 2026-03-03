#!/usr/bin/env bash
#
# PQBTC GA soak harness for relay/mempool witness-heavy traffic.
# Runs mempool_pq_stress.py repeatedly and emits deterministic artifacts.

export LC_ALL=C

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNS="${RUNS:-10}"
JOBS="${JOBS:-1}"
OUTDIR="${OUTDIR:-${ROOT_DIR}/build/soak-artifacts/pq-mempool-$(date -u +%Y%m%dT%H%M%SZ)}"
TEST_RUNNER="${ROOT_DIR}/build/test/functional/test_runner.py"
TEST_NAME="mempool_pq_stress.py"

if [[ ! -x "${TEST_RUNNER}" ]]; then
  echo "Missing functional test runner: ${TEST_RUNNER}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"
RESULTS_TSV="${OUTDIR}/results.tsv"
SUMMARY_JSON="${OUTDIR}/summary.json"

printf "run\tstatus\tduration_s\tfinished_utc\n" > "${RESULTS_TSV}"

passed=0
failed=0

for run in $(seq 1 "${RUNS}"); do
  started_epoch="$(date -u +%s)"
  finished_utc=""
  log_file="${OUTDIR}/run_${run}.log"
  status="FAIL"

  if "${TEST_RUNNER}" --jobs="${JOBS}" "${TEST_NAME}" >"${log_file}" 2>&1; then
    status="PASS"
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
  fi

  finished_epoch="$(date -u +%s)"
  duration_s="$((finished_epoch - started_epoch))"
  finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "%s\t%s\t%s\t%s\n" "${run}" "${status}" "${duration_s}" "${finished_utc}" >> "${RESULTS_TSV}"
done

cat > "${SUMMARY_JSON}" <<EOF
{
  "runs": ${RUNS},
  "passed": ${passed},
  "failed": ${failed},
  "jobs": ${JOBS},
  "test": "${TEST_NAME}",
  "results_tsv": "$(basename "${RESULTS_TSV}")"
}
EOF

echo "Soak artifacts written to: ${OUTDIR}"
echo "Summary: ${SUMMARY_JSON}"
echo "Results: ${RESULTS_TSV}"

if [[ ${failed} -ne 0 ]]; then
  exit 1
fi
