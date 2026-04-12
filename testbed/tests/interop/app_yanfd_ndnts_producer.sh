#!/usr/bin/env bash
# Interop: ndn-rs consumer → yanfd → NDNts producer.
set -euo pipefail

YANFD_HOST="${YANFD_HOST:-yanfd}"
YANFD_UDP="udp://${YANFD_HOST}:6363"
PREFIX="/interop/app-yanfd-ndnts"

ndnts-serve \
  --uplink "udp://${YANFD_HOST}:6363" \
  --prefix "${PREFIX}" \
  --payload "hello-from-ndnts-via-yanfd" &
SRV_PID=$!
sleep 1

RESULT=$(ndn-peek \
  --face "${YANFD_UDP}" \
  --name "${PREFIX}/test" \
  --timeout 4 2>&1)

kill "${SRV_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndnts-via-yanfd"
