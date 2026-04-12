#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → ndn-cxx producer.
#
# 1. ndnpoke (ndn-cxx) registers /interop/cxx-producer and serves one Data.
# 2. ndn-rs ndn-peek fetches it and validates the DigestSha256 signature.
set -euo pipefail

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_UDP="udp://${FWD_HOST}:6363"
PREFIX="/interop/cxx-producer"

# ndn-cxx producer.
echo -n "hello-from-ndn-cxx" | ndnpoke \
  --freshness 5000 \
  --face "${FWD_UDP}" \
  "${PREFIX}/test" &
POKE_PID=$!
sleep 0.5

# ndn-rs consumer.
RESULT=$(ndn-peek \
  --face "${FWD_UDP}" \
  --name "${PREFIX}/test" \
  --timeout 4 2>&1)

kill "${POKE_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndn-cxx"
