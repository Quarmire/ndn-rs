#!/usr/bin/env bash
# Run the full benchmark suite and write a markdown summary.
#
# NOTE on SHM face:
#   ndn-fwd supports a shared-memory face (shm://) for in-process producers,
#   which removes socket overhead and gives the lowest possible latency.
#   NFD and yanfd do NOT support SHM — they use UDP faces in this testbed.
#   The benchmark report clearly labels which transport is used for each result
#   so numbers are not naively compared across forwarders.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT="${RESULTS_DIR}/bench-${TIMESTAMP}.md"

mkdir -p "${RESULTS_DIR}"

echo "# NDN Forwarder Benchmark — ${TIMESTAMP}" > "${REPORT}"
echo "" >> "${REPORT}"
echo "| Forwarder | Transport | Metric | Value |" >> "${REPORT}"
echo "|-----------|-----------|--------|-------|" >> "${REPORT}"

run_bench() {
  local label="$1"
  local host="$2"
  local port="$3"
  local transport="$4"
  local script="$5"

  echo ""
  echo "── ${label} (${transport}) ──────────────────────────"
  FWD_HOST="${host}" FWD_PORT="${port}" FWD_LABEL="${label}" \
  FWD_TRANSPORT="${transport}" REPORT="${REPORT}" \
    bash "${SCRIPT_DIR}/${script}"
}

# Internal throughput — ndn-fwd only, Unix socket (no network stack overhead).
# This isolates raw forwarder pipeline cost from OS networking.
echo ""
echo "── ndn-fwd (unix/internal) ──────────────────────────────────"
FWD_LABEL="ndn-fwd-internal" \
UNIX_SOCK="/run/ndn-fwd/mgmt.sock" \
REPORT="${REPORT}" \
  bash "${SCRIPT_DIR}/internal_throughput.sh"

# Throughput — all forwarders via UDP
run_bench "ndn-fwd" "172.30.0.10" "6363" "udp" throughput.sh
run_bench "nfd"     "172.30.0.11" "6363" "udp" throughput.sh
run_bench "yanfd"   "172.30.0.12" "6363" "udp" throughput.sh

# Latency — all forwarders via UDP
run_bench "ndn-fwd" "172.30.0.10" "6363" "udp" latency.sh
run_bench "nfd"     "172.30.0.11" "6363" "udp" latency.sh
run_bench "yanfd"   "172.30.0.12" "6363" "udp" latency.sh

echo ""
echo "Report written to: ${REPORT}"
cat "${REPORT}"
