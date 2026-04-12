#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → NDNts producer.
set -euo pipefail

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_UDP="udp://${FWD_HOST}:6363"
PREFIX="/interop/ndnts-producer"

# NDNts producer.
ndnts-serve \
  --uplink "udp://${FWD_HOST}:6363" \
  --prefix "${PREFIX}" \
  --payload "hello-from-ndnts" &
SRV_PID=$!
sleep 1

# ndn-rs consumer.
RESULT=$(ndn-peek \
  --face "${FWD_UDP}" \
  --name "${PREFIX}/test" \
  --timeout 4 2>&1)

kill "${SRV_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndnts"
