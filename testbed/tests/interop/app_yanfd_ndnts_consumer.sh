#!/usr/bin/env bash
# Interop: NDNts consumer → yanfd → ndn-rs producer.
#
# ndn-rs producer registers on the yanfd Unix socket and serves Data.
# NDNts ndnts-fetch fetches it via yanfd.
set -euo pipefail

if ! command -v ndnts-fetch > /dev/null 2>&1; then
  echo "ERROR: ndnts-fetch is not available; install @ndn/tools from the NDNts package" >&2
  exit 1
fi

YANFD_HOST="${YANFD_HOST:-yanfd}"
YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="/interop/app-yanfd-rs"
CONTENT="hello-from-ndn-rs-via-yanfd"

TMP=$(mktemp)
echo -n "${CONTENT}" > "${TMP}"
ndn-put "${PREFIX}" "${TMP}" \
  --face-socket "${YANFD_SOCK}" --no-shm \
  --freshness 5000 --timeout 10 &
PUT_PID=$!
rm -f "${TMP}"
sleep 0.5

RESULT=$(ndnts-fetch \
  --uplink "udp4://${YANFD_HOST}:6363" \
  "${PREFIX}/test" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
