#!/usr/bin/env bash
# Interop: NDNts consumer → yanfd → ndn-rs producer.
#
# ndn-rs producer registers on the yanfd Unix socket and serves Data.
# NDNts ndncat fetches it via yanfd using CanBePrefix version discovery.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
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
sleep 0.5

# --ver=cbp: send CanBePrefix Interest to discover ndn-put's versioned name.
# Redirect ndncat stderr to the script's stderr so run_all.sh captures it.
RESULT=$(NDNTS_UPLINK="udp4://${YANFD_HOST}:6363" \
  ndncat get-segmented --ver=cbp "${PREFIX}" 2>/dev/stderr)

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
