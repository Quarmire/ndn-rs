#!/usr/bin/env bash
# Interop: NDNts consumer → yanfd → ndn-rs producer.
#
# ndn-rs producer registers on the yanfd Unix socket and serves Data.
# NDNts ndncat fetches it via the yanfd Unix socket with CanBePrefix discovery.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="/interop/app-yanfd-rs"
CONTENT="hello-from-ndn-rs-via-yanfd"

TMP=$(mktemp)
echo -n "${CONTENT}" > "${TMP}"
ndn-put "${PREFIX}" "${TMP}" \
  --face-socket "${YANFD_SOCK}" --no-shm \
  --freshness 5000 --timeout 10 &
PUT_PID=$!
sleep 0.5

# --ver=cbp: send CanBePrefix Interest to discover ndn-put's versioned name.
RESULT=$(NDNTS_UPLINK="unix://${YANFD_SOCK}" \
  ndncat get-segmented --ver=cbp "${PREFIX}")

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
