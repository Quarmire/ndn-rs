#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → ndn-cxx producer.
#
# 1. ndnpoke (ndn-cxx) registers /interop/cxx-producer on ndn-fwd via UDP and serves one Data.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket.
set -euo pipefail

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/cxx-producer"
CONTENT="hello-from-ndn-cxx"

echo -n "${CONTENT}" | NDN_CLIENT_TRANSPORT="udp4://${FWD_HOST}:6363" \
  ndnpoke --freshness 5000 "${PREFIX}/test" &
POKE_PID=$!
sleep 0.5

RESULT=$(ndn-peek "${PREFIX}/test" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --lifetime 4000 2>&1)

kill "${POKE_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
