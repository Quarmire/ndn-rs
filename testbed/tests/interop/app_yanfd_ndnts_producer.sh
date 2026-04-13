#!/usr/bin/env bash
# Interop: ndn-rs consumer → yanfd → NDNts producer.
#
# NDNts ndncat registers on yanfd via Unix socket and serves Data.
# ndn-rs ndn-peek fetches it via the yanfd Unix socket using segmented fetch.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="/interop/app-yanfd-ndnts"
CONTENT="hello-from-ndnts-via-yanfd"

# ndncat put-segmented reads payload from stdin, inserts a version component,
# registers the prefix, and serves segment Interests reactively.
echo -n "${CONTENT}" | NDNTS_UPLINK="unix://${YANFD_SOCK}" \
  ndncat put-segmented "${PREFIX}" &
SRV_PID=$!
sleep 1  # allow registration

# --pipeline 1: segmented fetch mode; sends CanBePrefix to discover the version
# component produced by ndncat, then fetches seg=0.
RESULT=$(ndn-peek --pipeline 1 "${PREFIX}" \
  --face-socket "${YANFD_SOCK}" --no-shm \
  --lifetime 4000 2>&1)

kill "${SRV_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
