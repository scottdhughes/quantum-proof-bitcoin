#!/usr/bin/env bash
#
# Capture post-v1 ops/SLO evidence into tracked docs artifacts.

export LC_ALL=C

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAMP="${STAMP:-$(date -u +%Y-%m-%d)}"
DOC_OUT="${DOC_OUT:-${ROOT_DIR}/docs/artifacts/ops-slo/${STAMP}}"
RAW_OUT="${RAW_OUT:-${ROOT_DIR}/build/ops-slo/${STAMP}}"
TEST_RUNNER="${ROOT_DIR}/build/test/functional/test_runner.py"
SOAK_OUT="${RAW_OUT}/soak"
SOAK_RUNS="${SOAK_RUNS:-10}"
SPEC_ID="OPS-SLO-v1"

mkdir -p "${DOC_OUT}" "${RAW_OUT}"

run_summary_test() {
  local test_name="$1"
  local summary_name="$2"
  local log_name="$3"

  PQBTC_SLO_SUMMARY_FILE="${DOC_OUT}/${summary_name}" \
    "${TEST_RUNNER}" --jobs=1 "${test_name}" > "${RAW_OUT}/${log_name}" 2>&1
}

run_summary_test "mempool_pq_limits.py" "mempool-pq-limits-summary.json" "mempool-pq-limits.log"
run_summary_test "mempool_pq_stress.py" "mempool-pq-stress-summary.json" "mempool-pq-stress.log"
run_summary_test "feature_pq_reorg.py" "feature-pq-reorg-summary.json" "feature-pq-reorg.log"

OUTDIR="${SOAK_OUT}" RUNS="${SOAK_RUNS}" JOBS=1 "${ROOT_DIR}/contrib/soak/run_pq_mempool_soak.sh" > "${RAW_OUT}/pq-mempool-soak.log" 2>&1

cp "${SOAK_OUT}/summary.json" "${DOC_OUT}/pq-mempool-soak-summary.json"
cp "${SOAK_OUT}/results.tsv" "${DOC_OUT}/pq-mempool-soak-results.tsv"
if compgen -G "${SOAK_OUT}/summaries/*.json" > /dev/null; then
  mkdir -p "${DOC_OUT}/soak-summaries"
  cp "${SOAK_OUT}/summaries/"*.json "${DOC_OUT}/soak-summaries/"
fi

cat > "${DOC_OUT}/manifest.json" <<EOF
{
  "spec_id": "${SPEC_ID}",
  "stamp": "${STAMP}",
  "capture_script": "contrib/soak/capture_ops_slo_evidence.sh",
  "soak_runs": ${SOAK_RUNS},
  "artifacts": [
    "README.md",
    "mempool-pq-limits-summary.json",
    "mempool-pq-stress-summary.json",
    "feature-pq-reorg-summary.json",
    "pq-mempool-soak-summary.json",
    "pq-mempool-soak-results.tsv"
  ]
}
EOF

cat > "${DOC_OUT}/README.md" <<EOF
# PQBTC Ops/SLO Evidence (${STAMP})

- Spec: \`${SPEC_ID}\`
- Capture script: \`contrib/soak/capture_ops_slo_evidence.sh\`
- Validator: \`contrib/soak/validate_ops_slo_evidence.py --signoff <bundle-root>\`
- Raw logs: \`build/ops-slo/${STAMP}\`

## Artifacts

- \`README.md\`
- \`manifest.json\`
- \`mempool-pq-limits-summary.json\`
- \`mempool-pq-stress-summary.json\`
- \`feature-pq-reorg-summary.json\`
- \`pq-mempool-soak-summary.json\`
- \`pq-mempool-soak-results.tsv\`

## Optional Supplemental Artifacts

- \`soak-summaries/\`
EOF

echo "Ops/SLO evidence written to: ${DOC_OUT}"
echo "Raw logs written to: ${RAW_OUT}"
