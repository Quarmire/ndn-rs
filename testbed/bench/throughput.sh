#!/usr/bin/env bash
# Benchmark: sustained Interest/Data throughput via ndn-iperf.
#
# Runs an iperf server on the forwarder, then a 10-second client window
# and reports average throughput in Mbps and Interests/sec.
#
# SHM note: Only ndn-fwd supports shm:// face transport.  When
# FWD_TRANSPORT=shm the server runs in-process using the local SHM socket.
# For NFD and yanfd FWD_TRANSPORT is always udp.
set -euo pipefail

HOST="${FWD_HOST:-172.30.0.10}"
PORT="${FWD_PORT:-6363}"
LABEL="${FWD_LABEL:-fwd}"
TRANSPORT="${FWD_TRANSPORT:-udp}"
DURATION=10
WINDOW=64
PREFIX="/testbed/bench/throughput/${LABEL}"
REPORT="${REPORT:-/dev/stdout}"

if [ "${TRANSPORT}" = "shm" ]; then
  FACE="shm://${HOST}"
else
  FACE="udp://${HOST}:${PORT}"
fi

echo "[${LABEL}/${TRANSPORT}] throughput: starting iperf server"
ndn-iperf server \
  --prefix "${PREFIX}" \
  --face "${FACE}" \
  --duration "$(( DURATION + 5 ))" \
  --quiet &
SRV_PID=$!
sleep 1

echo "[${LABEL}/${TRANSPORT}] throughput: running ${DURATION}s client"
OUTPUT=$(ndn-iperf client \
  --prefix "${PREFIX}" \
  --face "${FACE}" \
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
