#!/usr/bin/env bash
# Run the full compliance suite against all three forwarders.
# Exit code: 0 = all pass, non-zero = failures.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT="${RESULTS_DIR}/compliance-${TIMESTAMP}.txt"

mkdir -p "${RESULTS_DIR}"

PASS=0
FAIL=0

run_suite() {
  local label="$1"
  local script="$2"
  local fwd_host="$3"
  local fwd_port="${4:-6363}"

  echo ""
  echo "══════════════════════════════════════════════════════"
  echo "  ${label}  (${fwd_host}:${fwd_port})"
  echo "══════════════════════════════════════════════════════"

  if FWD_HOST="${fwd_host}" FWD_PORT="${fwd_port}" FWD_LABEL="${label}" \
       bash "${SCRIPT_DIR}/${script}" 2>&1 | tee -a "${REPORT}"; then
    echo "  PASS: ${script}"
    (( PASS++ ))
  else
    echo "  FAIL: ${script}"
    (( FAIL++ ))
  fi
}

for script in basic_forwarding.sh pit_aggregation.sh cs_behavior.sh mgmt_protocol.sh; do
  for fwd in "ndn-fwd:172.30.0.10:6363" "nfd:172.30.0.11:6363" "yanfd:172.30.0.12:6363"; do
    IFS=: read -r label host port <<< "${fwd}"
    run_suite "${label}" "${script}" "${host}" "${port}"
  done
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "  Report : ${REPORT}"
echo "══════════════════════════════════════════════════════"

[ "${FAIL}" -eq 0 ]
