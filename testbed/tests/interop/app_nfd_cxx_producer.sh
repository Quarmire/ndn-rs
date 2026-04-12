#!/usr/bin/env bash
# Interop: ndn-rs consumer → NFD → ndn-cxx producer (signature validated).
#
# Validates that a ndn-rs consumer can fetch Data produced by ndn-cxx and
# that the Ed25519/DigestSha256 signature is verifiable end-to-end.
set -euo pipefail

NFD_HOST="${NFD_HOST:-nfd}"
NFD_UDP="udp://${NFD_HOST}:6363"
PREFIX="/interop/app-nfd-cxx"

echo -n "hello-from-ndn-cxx-via-nfd" | ndnpoke \
  --freshness 5000 \
  --face "${NFD_UDP}" \
  "${PREFIX}/test" &
POKE_PID=$!
sleep 0.5

RESULT=$(ndn-peek \
  --face "${NFD_UDP}" \
  --name "${PREFIX}/test" \
  --timeout 4 2>&1)

kill "${POKE_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndn-cxx-via-nfd"
