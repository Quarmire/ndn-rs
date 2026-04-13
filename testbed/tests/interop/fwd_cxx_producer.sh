#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → ndn-cxx producer.
#
# 1. ndnpoke (ndn-cxx) registers /interop/cxx-producer on ndn-fwd via Unix socket and serves one Data.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket.
set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/cxx-producer"
CONTENT="hello-from-ndn-cxx"

echo -n "${CONTENT}" | NDN_CLIENT_TRANSPORT="unix://${FWD_SOCK}" \
  ndnpoke --freshness 5000 "${PREFIX}/test" &
POKE_PID=$!
sleep 0.5

RESULT=$(ndn-peek "${PREFIX}/test" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --lifetime 4000) || {
  echo "ndn-peek failed (exit $?)." >&2
  kill "${POKE_PID}" 2>/dev/null || true
  exit 1
}

kill "${POKE_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
