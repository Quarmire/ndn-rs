#!/usr/bin/env bash
# Interop: ndn-rs consumer → NFD → ndn-cxx producer.
#
# Both parties connect to NFD. ndn-cxx ndnpoke registers and serves Data via the NFD socket.
# ndn-rs ndn-peek fetches it via the same NFD socket.
set -euo pipefail

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
PREFIX="/interop/app-nfd-cxx"
CONTENT="hello-from-ndn-cxx-via-nfd"

echo -n "${CONTENT}" | NDN_CLIENT_TRANSPORT="unix://${NFD_SOCK}" \
  ndnpoke --freshness 5000 "${PREFIX}/test" &
POKE_PID=$!
sleep 0.5

RESULT=$(ndn-peek "${PREFIX}/test" \
  --face-socket "${NFD_SOCK}" --no-shm \
  --lifetime 4000 2>&1)

kill "${POKE_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
