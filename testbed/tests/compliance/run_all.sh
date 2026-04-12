#!/usr/bin/env bash
# Run the full compliance suite against all three forwarders.
# Exit code: 0 = all pass, non-zero = failures.
#
# Connects to each forwarder via its shared Unix socket (mounted as a named
# Docker volume into testclient) using --face-socket / --no-shm.
#
# Socket paths inside testclient:
#   ndn-fwd : /run/ndn-fwd/ndn-fwd.sock
#   nfd     : /run/nfd/nfd.sock
#   yanfd   : /run/yanfd/nfd.sock
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
  local fwd_sock="$3"

  echo ""
  echo "══════════════════════════════════════════════════════"
  echo "  ${label}  (${fwd_sock})"
  echo "══════════════════════════════════════════════════════"

  if FWD_SOCK="${fwd_sock}" FWD_LABEL="${label}" \
       bash "${SCRIPT_DIR}/${script}" 2>&1 | tee -a "${REPORT}"; then
    echo "  PASS: ${script}"
    (( PASS++ ))
  else
    echo "  FAIL: ${script}"
    (( FAIL++ ))
  fi
}

declare -A FWD_SOCKS=(
  ["ndn-fwd"]="/run/ndn-fwd/ndn-fwd.sock"
  ["nfd"]="/run/nfd/nfd.sock"
  ["yanfd"]="/run/yanfd/nfd.sock"
)

for script in basic_forwarding.sh pit_aggregation.sh cs_behavior.sh mgmt_protocol.sh; do
  for label in ndn-fwd nfd yanfd; do
    run_suite "${label}" "${script}" "${FWD_SOCKS[$label]}"
  done
done

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "  Report : ${REPORT}"
echo "══════════════════════════════════════════════════════"

[ "${FAIL}" -eq 0 ]
