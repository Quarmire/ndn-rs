#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → NDNts producer.
#
# 1. NDNts ndnts-serve registers /interop/ndnts-producer on ndn-fwd and serves Data.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket.
set -euo pipefail

if ! command -v ndnts-serve > /dev/null 2>&1; then
  echo "ERROR: ndnts-serve is not available; install @ndn/tools from the NDNts package" >&2
  exit 1
fi

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/ndnts-producer"
CONTENT="hello-from-ndnts"

ndnts-serve \
  --uplink "udp4://${FWD_HOST}:6363" \
  --prefix "${PREFIX}" \
  --payload "${CONTENT}" &
SRV_PID=$!
sleep 1

RESULT=$(ndn-peek "${PREFIX}/test" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --lifetime 4000 2>&1)

kill "${SRV_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
