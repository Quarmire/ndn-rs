#!/usr/bin/env bash
# Interop: ndn-cxx consumer → NFD → ndn-rs producer.
#
# Validates that ndn-cxx's ndnpeek can retrieve Data produced by ndn-rs
# (verifying the Data arrives intact through NFD).
set -euo pipefail

NFD_HOST="${NFD_HOST:-nfd}"
NFD_UDP="udp://${NFD_HOST}:6363"
PREFIX="/interop/app-nfd-rs"

ndn-put \
  --face "${NFD_UDP}" \
  --prefix "${PREFIX}" \
  --content "hello-from-ndn-rs-via-nfd" \
  --ttl 5 \
  --sign &
PUT_PID=$!
sleep 0.5

RESULT=$(ndnpeek --timeout 4000 "${PREFIX}/test" \
  --face "${NFD_UDP}" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndn-rs-via-nfd"
