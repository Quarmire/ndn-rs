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
#   udp (loopback)         ≈ forwarder + OS network stack
#   udp (cross-host)       ≈ forwarder + OS + physical NIC
set -euo pipefail

LABEL="${FWD_LABEL:-ndn-fwd-internal}"
UNIX_SOCK="${UNIX_SOCK:-/run/ndn-fwd/mgmt.sock}"
FACE="unix://${UNIX_SOCK}"
DURATION=10
WINDOW=64
PREFIX="/testbed/bench/internal/${LABEL}"
REPORT="${REPORT:-/dev/stdout}"

echo "[${LABEL}/unix] internal throughput: starting iperf server"
ndn-iperf server \
  --prefix "${PREFIX}" \
  --face "${FACE}" \
  --duration "$(( DURATION + 5 ))" \
  --quiet &
SRV_PID=$!
sleep 1

echo "[${LABEL}/unix] internal throughput: running ${DURATION}s client"
OUTPUT=$(ndn-iperf client \
  --prefix "${PREFIX}" \
  --face "${FACE}" \
  --duration "${DURATION}" \
  --window "${WINDOW}" \
  2>&1)

kill "${SRV_PID}" 2>/dev/null || true
wait "${SRV_PID}" 2>/dev/null || true

echo "${OUTPUT}"

MBPS=$(echo "${OUTPUT}" | grep -oE '[0-9]+\.[0-9]+ Mbps'   | tail -1 | awk '{print $1}')
INTS=$(echo "${OUTPUT}" | grep -oE '[0-9]+ Interests/s'     | tail -1 | awk '{print $1}')

[ -z "${MBPS}" ] && MBPS="n/a"
[ -z "${INTS}" ] && INTS="n/a"

echo "| ${LABEL} | unix | internal-throughput | ${MBPS} Mbps / ${INTS} Int/s |" >> "${REPORT}"
echo "[${LABEL}/unix] internal result: ${MBPS} Mbps  ${INTS} Int/s"
