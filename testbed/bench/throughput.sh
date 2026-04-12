#!/usr/bin/env bash
# Benchmark: sustained Interest/Data throughput via ndn-iperf.
#
# Runs an iperf server on the forwarder, then a 10-second client window
# and reports average throughput in Mbps and Interests/sec.
#
# Connects via the forwarder's Unix socket (shared into testclient as a
# named Docker volume) using --face-socket / --no-shm.
set -euo pipefail

SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
LABEL="${FWD_LABEL:-fwd}"
TRANSPORT="${FWD_TRANSPORT:-unix}"
DURATION=10
WINDOW=64
PREFIX="/testbed/bench/throughput/${LABEL}"
REPORT="${REPORT:-/dev/stdout}"

echo "[${LABEL}/${TRANSPORT}] throughput: starting iperf server"
ndn-iperf server \
  --face-socket "${SOCK}" --no-shm \
  --prefix "${PREFIX}" \
  --quiet &
SRV_PID=$!
sleep 1

echo "[${LABEL}/${TRANSPORT}] throughput: running ${DURATION}s client"
OUTPUT=$(ndn-iperf client \
  --face-socket "${SOCK}" --no-shm \
  --prefix "${PREFIX}" \
  --duration "${DURATION}" \
  --window "${WINDOW}" \
  2>&1)

kill "${SRV_PID}" 2>/dev/null || true
wait "${SRV_PID}" 2>/dev/null || true

echo "${OUTPUT}"

# Extract from summary: "  throughput:  3.43 Gbps" (unit varies: Gbps/Mbps/Kbps)
MBPS=$(echo "${OUTPUT}" | grep 'throughput:' | grep -oE '[0-9]+\.[0-9]+ [A-Za-z]+ps' | head -1) || true
# Extract max pkt/s from interval lines: "52515 pkt/s"
INTS=$(echo "${OUTPUT}" | grep -oE '[0-9]+ pkt/s' | awk '{print $1}' | sort -n | tail -1) || true

[ -z "${MBPS}" ] && MBPS="n/a"
[ -z "${INTS}" ] && INTS="n/a"

echo "| ${LABEL} | ${TRANSPORT} | throughput | ${MBPS} Mbps / ${INTS} Int/s |" >> "${REPORT}"
echo "[${LABEL}/${TRANSPORT}] throughput result: ${MBPS} Mbps  ${INTS} Int/s"
