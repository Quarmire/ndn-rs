#!/usr/bin/env bash
# Interop: NDNts consumer → yanfd → ndn-rs producer.
set -euo pipefail

YANFD_HOST="${YANFD_HOST:-yanfd}"
YANFD_UDP="udp://${YANFD_HOST}:6363"
PREFIX="/interop/app-yanfd-rs"

ndn-put \
  --face "${YANFD_UDP}" \
  --prefix "${PREFIX}" \
  --content "hello-from-ndn-rs-via-yanfd" \
  --ttl 5 \
  --sign &
PUT_PID=$!
sleep 0.5

RESULT=$(ndnts-fetch \
  --uplink "udp://${YANFD_HOST}:6363" \
  "${PREFIX}/test" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndn-rs-via-yanfd"
