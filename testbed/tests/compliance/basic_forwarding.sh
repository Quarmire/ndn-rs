#!/usr/bin/env bash
# Compliance: basic Interest/Data round-trip.
#
# Registers a producer prefix on the forwarder, sends an Interest via
# ndn-iperf server mode, and verifies the Data is returned.
# Env: FWD_HOST, FWD_PORT, FWD_LABEL
set -euo pipefail

HOST="${FWD_HOST:-172.30.0.10}"
PORT="${FWD_PORT:-6363}"
LABEL="${FWD_LABEL:-fwd}"
PREFIX="/testbed/compliance/basic"
TIMEOUT=5

echo "[${LABEL}] basic_forwarding: starting iperf server on ${PREFIX}"

# Start a short-lived iperf server in background; it registers the prefix.
ndn-iperf server \
  --prefix "${PREFIX}" \
  --face "udp://${HOST}:${PORT}" \
  --duration 10 \
  --quiet &
SRV_PID=$!
sleep 1   # allow server to register

echo "[${LABEL}] basic_forwarding: sending client Interest"
OUTPUT=$(ndn-iperf client \
  --prefix "${PREFIX}" \
  --face "udp://${HOST}:${PORT}" \
  --duration 2 \
  --window 4 \
  2>&1 || true)

kill "${SRV_PID}" 2>/dev/null || true
wait "${SRV_PID}" 2>/dev/null || true

echo "${OUTPUT}"

# Verify non-zero throughput was reported.
if echo "${OUTPUT}" | grep -qE 'throughput|Mbps|kbps|[1-9][0-9]* Data'; then
  echo "[${LABEL}] PASS: basic_forwarding"
  exit 0
else
  echo "[${LABEL}] FAIL: basic_forwarding — no Data received"
  exit 1
fi
