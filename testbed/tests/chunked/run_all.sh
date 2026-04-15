#!/usr/bin/env bash
# Run every script in testbed/tests/chunked/ that isn't run_all.sh
# itself. Used by CI and by the testbed Docker image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT="${RESULTS_DIR}/chunked-${TIMESTAMP}.txt"

mkdir -p "${RESULTS_DIR}"

PASS=0
FAIL=0

run_script() {
  local script="$1"
  local label
  label=$(basename "${script}" .sh)
  echo "── ${label} ──" | tee -a "${REPORT}"
  if bash "${script}" 2>&1 | tee -a "${REPORT}"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
  echo | tee -a "${REPORT}"
}

run_script "${SCRIPT_DIR}/roundtrip.sh"
run_script "${SCRIPT_DIR}/partial_fetch.sh"
run_script "${SCRIPT_DIR}/cc_sweep.sh"

echo "" | tee -a "${REPORT}"
echo "chunked tests: ${PASS} script(s) passed, ${FAIL} failed" | tee -a "${REPORT}"

[ "${FAIL}" -eq 0 ]
