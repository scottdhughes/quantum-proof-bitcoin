#!/usr/bin/env bash
#
# Capture a GA burn-in evidence bundle into tracked docs summaries and untracked build logs.

export LC_ALL=C

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LABEL="${1:?usage: capture_ga_burnin_evidence.sh <label>}"
DATE_TAG="${DATE_TAG:-$(date -u +%F)}"
RUNS="${RUNS:-10}"
JOBS="${JOBS:-1}"

DOC_OUT="${ROOT_DIR}/docs/artifacts/ga-burnin/${LABEL}"
BUILD_OUT="${ROOT_DIR}/build/ga-burnin/${LABEL}"
LOG_OUT="${BUILD_OUT}/logs"
TMP_PREFIX="${BUILD_OUT}/test_runner"
FUZZ_DIR="${BUILD_OUT}/pqsig_fuzz_smoke"
SEED_SRC="${ROOT_DIR}/src/test/data/pqsig/fuzz/pqsig_verify"
SOAK_STAMP="pq-mempool-${DATE_TAG//-/}T$(date -u +%H%M%SZ)"
SOAK_OUT="${ROOT_DIR}/build/soak-artifacts/${SOAK_STAMP}"

FUNCTIONAL_TESTS=(
  feature_pqsig_basic.py
  feature_pqsig_multisig.py
  mempool_pq_limits.py
  mempool_pq_stress.py
  feature_pq_reorg.py
  feature_pq_block_limits.py
)

mkdir -p "${DOC_OUT}" "${LOG_OUT}" "${TMP_PREFIX}"
rm -rf "${FUZZ_DIR}"
mkdir -p "${FUZZ_DIR}"

check_no_pqbtcd() {
  local pids=""
  pids="$(pgrep -x pqbtcd || true)"
  if [[ -n "${pids}" ]]; then
    echo "Stray pqbtcd process detected: ${pids}" >&2
    echo "Terminate stray pqbtcd processes before rerunning this capture." >&2
    exit 1
  fi
}

check_port_range_clear() {
  local range="$1"
  local listeners=""
  listeners="$(lsof -nP -iTCP:"${range}" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "${listeners}" ]]; then
    echo "Listening sockets already occupy TCP range ${range}:" >&2
    echo "${listeners}" >&2
    echo "Clear the listeners before rerunning this capture." >&2
    exit 1
  fi
}

copy_seed_corpus() {
  cp -f "${SEED_SRC}"/* "${FUZZ_DIR}/" >/dev/null 2>&1 || true
  rm -f "${FUZZ_DIR}/README.md"
}

run_and_capture() {
  local summary_out="$1"
  local log_copy=""
  shift
  log_copy="${LOG_OUT}/$(basename "${summary_out}")"
  if [[ "${summary_out}" == "${log_copy}" ]]; then
    "$@" 2>&1 | tee "${summary_out}" >/dev/null
  else
    "$@" 2>&1 | tee "${summary_out}" | tee "${log_copy}" >/dev/null
  fi
}

write_notes() {
  cat > "${DOC_OUT}/notes.md" <<EOF
# ${LABEL}

- Captured at (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Candidate commit: $(git -C "${ROOT_DIR}" rev-parse HEAD)
- Candidate short SHA: $(git -C "${ROOT_DIR}" rev-parse --short HEAD)
- Worktree status:
\`\`\`text
$(git -C "${ROOT_DIR}" status --short || true)
\`\`\`

## Raw build-log locations

- Deterministic: \`${LOG_OUT}/deterministic.txt\`
- Bench: \`${LOG_OUT}/bench.txt\`
- Unit: \`${LOG_OUT}/unit.txt\`
- Fuzz: \`${LOG_OUT}/fuzz.txt\`
- Functional: \`${LOG_OUT}/functional.txt\`
- Offset 3272 repro: \`${LOG_OUT}/offset-3272.txt\`
- Functional tmpdir prefix: \`${TMP_PREFIX}\`
- Soak artifacts: \`${SOAK_OUT}\`

## Notes

- This capture requires a clean host state: no stray \`pqbtcd\` processes and no listeners on RPC or P2P regtest port ranges.
- The local fuzz smoke copied the tracked corpus from \`src/test/data/pqsig/fuzz/pqsig_verify\` into \`${FUZZ_DIR}\` before running.
EOF
}

check_no_pqbtcd
check_port_range_clear "16000-16024"
check_port_range_clear "11000-11024"
copy_seed_corpus

run_and_capture "${DOC_OUT}/deterministic.txt" \
  python3 "${ROOT_DIR}/ci/test/check_deterministic_artifacts.py"

run_and_capture "${DOC_OUT}/bench.txt" \
  python3 "${ROOT_DIR}/ci/test/check_pqsig_bench.py" --bench "${ROOT_DIR}/build/bin/bench_pqbtc" --repeat 3

run_and_capture "${DOC_OUT}/unit.txt" \
  "${ROOT_DIR}/build/bin/test_pqbtc" --run_test=pqsig_tests,pqsig_script_tests,script_tests,multisig_tests

run_and_capture "${DOC_OUT}/fuzz.txt" \
  env FUZZ=pqsig_verify "${ROOT_DIR}/build-fuzz/bin/fuzz" "${FUZZ_DIR}"

run_and_capture "${DOC_OUT}/functional.txt" \
  "${ROOT_DIR}/build/test/functional/test_runner.py" --jobs=1 --tmpdirprefix "${TMP_PREFIX}" "${FUNCTIONAL_TESTS[@]}"

run_and_capture "${LOG_OUT}/soak.txt" \
  env RUNS="${RUNS}" JOBS="${JOBS}" OUTDIR="${SOAK_OUT}" "${ROOT_DIR}/contrib/soak/run_pq_mempool_soak.sh"

cp "${SOAK_OUT}/summary.json" "${DOC_OUT}/soak-summary.json"
cp "${SOAK_OUT}/results.tsv" "${DOC_OUT}/results.tsv"

run_and_capture "${LOG_OUT}/offset-3272.txt" \
  python3 "${ROOT_DIR}/contrib/pqsig-ref/repro_offset_3272.py"

write_notes
