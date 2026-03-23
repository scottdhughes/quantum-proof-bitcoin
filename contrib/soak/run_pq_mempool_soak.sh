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
SUMMARY_DIR="${OUTDIR}/summaries"

if [[ ! -x "${TEST_RUNNER}" ]]; then
  echo "Missing functional test runner: ${TEST_RUNNER}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"
mkdir -p "${SUMMARY_DIR}"
RESULTS_TSV="${OUTDIR}/results.tsv"
SUMMARY_JSON="${OUTDIR}/summary.json"

printf "run\tstatus\tduration_s\tfinished_utc\n" > "${RESULTS_TSV}"

passed=0
failed=0
started_all_epoch="$(date -u +%s)"

for run in $(seq 1 "${RUNS}"); do
  started_epoch="$(date -u +%s)"
  finished_utc=""
  log_file="${OUTDIR}/run_${run}.log"
  run_summary_file="${SUMMARY_DIR}/run_${run}.json"
  status="FAIL"

  if PQBTC_SLO_SUMMARY_FILE="${run_summary_file}" "${TEST_RUNNER}" --jobs="${JOBS}" "${TEST_NAME}" >"${log_file}" 2>&1; then
    status="PASS"
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    if [[ ! -f "${run_summary_file}" ]]; then
      cat > "${run_summary_file}" <<EOF
{
  "scenario": "mempool_pq_stress",
  "pass": false,
  "duration_s": 0.0,
  "mempool_before_restart": null,
  "mempool_after_restart": null,
  "reorg_result": "not-completed",
  "crash_assert_hang": true,
  "notes": "test runner failed before summary emission"
}
EOF
    fi
  fi

  finished_epoch="$(date -u +%s)"
  duration_s="$((finished_epoch - started_epoch))"
  finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf "%s\t%s\t%s\t%s\n" "${run}" "${status}" "${duration_s}" "${finished_utc}" >> "${RESULTS_TSV}"
done

finished_all_epoch="$(date -u +%s)"
total_duration_s="$((finished_all_epoch - started_all_epoch))"

cat > "${SUMMARY_JSON}" <<EOF
{
  "scenario": "pq_mempool_soak",
  "pass": $( [[ ${failed} -eq 0 ]] && echo true || echo false ),
  "duration_s": ${total_duration_s},
  "mempool_before_restart": null,
  "mempool_after_restart": null,
  "reorg_result": "aggregate-from-run-summaries",
  "crash_assert_hang": $( [[ ${failed} -eq 0 ]] && echo false || echo true ),
  "notes": "per-run summaries live under $(basename "${SUMMARY_DIR}")",
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
