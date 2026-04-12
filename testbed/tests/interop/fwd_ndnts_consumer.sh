#!/usr/bin/env bash
# Interop: NDNts consumer ← ndn-fwd → ndn-rs producer.
#
# 1. ndn-rs producer serves /interop/ndnts-consumer/test.
# 2. NDNts ndnts-fetch fetches it via ndn-fwd.
set -euo pipefail

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_UDP="udp://${FWD_HOST}:6363"
PREFIX="/interop/ndnts-consumer"

ndn-put \
  --face "${FWD_UDP}" \
  --prefix "${PREFIX}" \
  --content "hello-from-ndn-rs" \
  --ttl 5 \
  --sign &
PUT_PID=$!
sleep 0.5

# NDNts CLI fetch (ndnts-cli package).
RESULT=$(ndnts-fetch \
  --uplink "udp://${FWD_HOST}:6363" \
  "${PREFIX}/test" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndn-rs"
