#!/usr/bin/env bash
# Benchmark: round-trip latency via ndn-ping.
#
# Sends 200 pings and reports p50 / p95 / p99 RTT in microseconds.
set -euo pipefail

HOST="${FWD_HOST:-172.30.0.10}"
PORT="${FWD_PORT:-6363}"
LABEL="${FWD_LABEL:-fwd}"
TRANSPORT="${FWD_TRANSPORT:-udp}"
COUNT=200
PREFIX="/testbed/bench/latency/${LABEL}"
REPORT="${REPORT:-/dev/stdout}"

FACE="udp://${HOST}:${PORT}"

echo "[${LABEL}/${TRANSPORT}] latency: starting ping server on ${PREFIX}"
# ndn-ping server registers the prefix and echoes Interests as Data.
ndn-ping server \
  --prefix "${PREFIX}" \
  --face "${FACE}" \
  --quiet &
SRV_PID=$!
sleep 0.5

echo "[${LABEL}/${TRANSPORT}] latency: sending ${COUNT} pings"
OUTPUT=$(ndn-ping client \
  --prefix "${PREFIX}" \
  --face "${FACE}" \
  --count "${COUNT}" \
  --interval 10 \
  2>&1)

kill "${SRV_PID}" 2>/dev/null || true
wait "${SRV_PID}" 2>/dev/null || true

echo "${OUTPUT}"

# Parse RTT lines: extract all RTT values and compute percentiles.
RTTS=$(echo "${OUTPUT}" | grep -oE 'rtt=[0-9]+' | sed 's/rtt=//')
if [ -z "${RTTS}" ]; then
  # Alternative format: "RTT: X us"
  RTTS=$(echo "${OUTPUT}" | grep -oE '[0-9]+ us' | awk '{print $1}')
fi

if [ -z "${RTTS}" ]; then
  P50="n/a"; P95="n/a"; P99="n/a"
else
  SORTED=$(echo "${RTTS}" | sort -n)
  COUNT_ACTUAL=$(echo "${SORTED}" | wc -l | tr -d ' ')
  P50_IDX=$(( COUNT_ACTUAL * 50 / 100 ))
  P95_IDX=$(( COUNT_ACTUAL * 95 / 100 ))
  P99_IDX=$(( COUNT_ACTUAL * 99 / 100 ))
  [ "${P50_IDX}" -lt 1 ] && P50_IDX=1
  [ "${P95_IDX}" -lt 1 ] && P95_IDX=1
  [ "${P99_IDX}" -lt 1 ] && P99_IDX=1
  P50=$(echo "${SORTED}" | sed -n "${P50_IDX}p")
  P95=$(echo "${SORTED}" | sed -n "${P95_IDX}p")
  P99=$(echo "${SORTED}" | sed -n "${P99_IDX}p")
  P50="${P50} µs"; P95="${P95} µs"; P99="${P99} µs"
fi

echo "| ${LABEL} | ${TRANSPORT} | latency p50/p95/p99 | ${P50} / ${P95} / ${P99} |" >> "${REPORT}"
echo "[${LABEL}/${TRANSPORT}] latency result: p50=${P50}  p95=${P95}  p99=${P99}"
