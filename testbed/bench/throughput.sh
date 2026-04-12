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

# Extract summary line: "Summary: X.XX Mbps, Y Interests/s"
MBPS=$(echo "${OUTPUT}"  | grep -oE '[0-9]+\.[0-9]+ Mbps'      | tail -1 | awk '{print $1}')
INTS=$(echo "${OUTPUT}"  | grep -oE '[0-9]+ Interests/s'        | tail -1 | awk '{print $1}')

[ -z "${MBPS}" ] && MBPS="n/a"
[ -z "${INTS}" ] && INTS="n/a"

echo "| ${LABEL} | ${TRANSPORT} | throughput | ${MBPS} Mbps / ${INTS} Int/s |" >> "${REPORT}"
echo "[${LABEL}/${TRANSPORT}] throughput result: ${MBPS} Mbps  ${INTS} Int/s"
