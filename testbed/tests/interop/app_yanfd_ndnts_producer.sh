#!/usr/bin/env bash
# Interop: ndn-rs consumer → yanfd → NDNts producer.
#
# NDNts ndnts-serve registers on yanfd via UDP and serves Data.
# ndn-rs ndn-peek fetches it via the yanfd Unix socket.
set -euo pipefail

if ! command -v ndnts-serve > /dev/null 2>&1; then
  echo "SKIP: ndnts-serve not available" >&2
  exit 2
fi

YANFD_HOST="${YANFD_HOST:-yanfd}"
YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="/interop/app-yanfd-ndnts"
CONTENT="hello-from-ndnts-via-yanfd"

ndnts-serve \
  --uplink "udp4://${YANFD_HOST}:6363" \
  --prefix "${PREFIX}" \
  --payload "${CONTENT}" &
SRV_PID=$!
sleep 1

RESULT=$(ndn-peek "${PREFIX}/test" \
  --face-socket "${YANFD_SOCK}" --no-shm \
  --lifetime 4000 2>&1)

kill "${SRV_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
