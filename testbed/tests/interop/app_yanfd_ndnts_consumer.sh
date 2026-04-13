#!/usr/bin/env bash
# Interop: NDNts consumer → yanfd → ndn-rs producer.
#
# ndn-rs producer registers on the yanfd Unix socket and serves Data.
# NDNts ndncat fetches it via the yanfd Unix socket with CanBePrefix discovery.
#
# Note: sleep 1 — yanfd has a separate RIB manager; 0.5s is not enough for
# rib/register → FIB propagation before NDNts sends its Interest.
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
sleep 1  # allow ndn-put to register with yanfd and RIB → FIB propagation

# --ver=cbp: send CanBePrefix Interest to discover ndn-put's versioned name.
RESULT=$(NDNTS_UPLINK="unix://${YANFD_SOCK}" \
  ndncat get-segmented --ver=cbp "${PREFIX}") || {
  echo "ndncat get-segmented failed (exit $?)." >&2
  kill "${PUT_PID}" 2>/dev/null || true
  rm -f "${TMP}"
  exit 1
}

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
