#!/usr/bin/env bash
# Run the full benchmark suite and write a markdown summary.
#
# Tools connect to each forwarder via its shared Unix socket (--face-socket,
# --no-shm), making benchmarks independent of IP stack overhead for the
# control plane.  All three forwarders are reachable from testclient because
# their socket directories are mounted as named Docker volumes.
#
# Socket paths inside testclient:
#   ndn-fwd : /run/ndn-fwd/ndn-fwd.sock
#   nfd     : /run/nfd/nfd.sock
#   yanfd   : /run/yanfd/nfd.sock
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
  local sock="$2"
  local script="$3"

  echo ""
  echo "── ${label} (unix) ──────────────────────────"
  FWD_SOCK="${sock}" FWD_LABEL="${label}" \
  FWD_TRANSPORT="unix" REPORT="${REPORT}" \
    bash "${SCRIPT_DIR}/${script}"
}

# Internal throughput — ndn-fwd only, Unix socket (no network stack overhead).
# This isolates raw forwarder pipeline cost from OS networking.
echo ""
echo "── ndn-fwd (unix/internal) ──────────────────────────────────"
FWD_LABEL="ndn-fwd-internal" \
FWD_SOCK="/run/ndn-fwd/ndn-fwd.sock" \
REPORT="${REPORT}" \
  bash "${SCRIPT_DIR}/internal_throughput.sh"

# Throughput — all forwarders via Unix socket
run_bench "ndn-fwd" "/run/ndn-fwd/ndn-fwd.sock" throughput.sh
run_bench "nfd"     "/run/nfd/nfd.sock"           throughput.sh
run_bench "yanfd"   "/run/yanfd/nfd.sock"          throughput.sh

# Latency — all forwarders via Unix socket
run_bench "ndn-fwd" "/run/ndn-fwd/ndn-fwd.sock" latency.sh
run_bench "nfd"     "/run/nfd/nfd.sock"           latency.sh
run_bench "yanfd"   "/run/yanfd/nfd.sock"          latency.sh

echo ""
echo "Report written to: ${REPORT}"
cat "${REPORT}"
