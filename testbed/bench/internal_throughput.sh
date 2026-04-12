#!/usr/bin/env bash
# Benchmark: raw internal forwarder throughput via Unix socket (loopback).
#
# This measures the forwarder's packet-processing capacity without IP stack
# overhead.  Both the iperf server (producer) and client (consumer) connect
# to the same ndn-fwd instance over its Unix domain socket, so packets
# traverse the complete forwarding pipeline — PIT, CS, strategy — but skip
# the kernel network stack entirely.
#
# Transport comparison:
#   internal (Unix socket) ≈ forwarder throughput
#   unix (cross-container) ≈ forwarder + volume mount overhead
set -euo pipefail

LABEL="${FWD_LABEL:-ndn-fwd-internal}"
SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
DURATION=10
WINDOW=64
PREFIX="/testbed/bench/internal/${LABEL}"
REPORT="${REPORT:-/dev/stdout}"

echo "[${LABEL}/unix] internal throughput: starting iperf server"
ndn-iperf server \
  --face-socket "${SOCK}" --no-shm \
  --prefix "${PREFIX}" \
  --quiet &
SRV_PID=$!
sleep 1

echo "[${LABEL}/unix] internal throughput: running ${DURATION}s client"
OUTPUT=$(ndn-iperf client \
  --face-socket "${SOCK}" --no-shm \
  --prefix "${PREFIX}" \
  --duration "${DURATION}" \
  --window "${WINDOW}" \
  2>&1)

kill "${SRV_PID}" 2>/dev/null || true
wait "${SRV_PID}" 2>/dev/null || true

echo "${OUTPUT}"

MBPS=$(echo "${OUTPUT}" | grep 'throughput:' | grep -oE '[0-9]+\.[0-9]+ [A-Za-z]+ps' | head -1) || true
INTS=$(echo "${OUTPUT}" | grep -oE '[0-9]+ pkt/s' | awk '{print $1}' | sort -n | tail -1) || true

[ -z "${MBPS}" ] && MBPS="n/a"
[ -z "${INTS}" ] && INTS="n/a"

echo "| ${LABEL} | unix | internal-throughput | ${MBPS} Mbps / ${INTS} Int/s |" >> "${REPORT}"
echo "[${LABEL}/unix] internal result: ${MBPS} Mbps  ${INTS} Int/s"
