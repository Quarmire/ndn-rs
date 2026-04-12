#!/usr/bin/env bash
# Benchmark: round-trip latency via ndn-ping.
#
# Sends 200 pings and reports p50 / p95 / p99 RTT in microseconds.
set -euo pipefail

SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
LABEL="${FWD_LABEL:-fwd}"
TRANSPORT="${FWD_TRANSPORT:-unix}"
COUNT=200
PREFIX="/testbed/bench/latency/${LABEL}"
REPORT="${REPORT:-/dev/stdout}"

echo "[${LABEL}/${TRANSPORT}] latency: starting ping server on ${PREFIX}"
ndn-ping server \
  --face-socket "${SOCK}" --no-shm \
  --prefix "${PREFIX}" &
SRV_PID=$!
sleep 0.5

echo "[${LABEL}/${TRANSPORT}] latency: sending ${COUNT} pings"
OUTPUT=$(ndn-ping client \
  --face-socket "${SOCK}" --no-shm \
  --prefix "${PREFIX}" \
  --count "${COUNT}" \
  --interval 10 \
  2>&1)

kill "${SRV_PID}" 2>/dev/null || true
wait "${SRV_PID}" 2>/dev/null || true

echo "${OUTPUT}"

# Parse ndn-ping summary: "rtt min/avg/max/p50/p99/stddev = MIN/AVG/MAX/P50/P99/STDDEV µs"
# Values use format_rtt units (e.g. "4.24ms", "100µs", "1.2s").
SUMMARY=$(echo "${OUTPUT}" | grep 'rtt min/avg' || true)
if [ -n "${SUMMARY}" ]; then
  VALS=$(echo "${SUMMARY}" | sed 's/.*= //' | tr '/' '\n')
  P50=$(echo "${VALS}" | sed -n '4p')
  P99=$(echo "${VALS}" | sed -n '5p')
  P95="n/a"   # ndn-ping reports p50 and p99, not p95
else
  P50="n/a"; P95="n/a"; P99="n/a"
fi

echo "| ${LABEL} | ${TRANSPORT} | latency p50/p99 | ${P50} / ${P99} |" >> "${REPORT}"
echo "[${LABEL}/${TRANSPORT}] latency result: p50=${P50}  p99=${P99}"
