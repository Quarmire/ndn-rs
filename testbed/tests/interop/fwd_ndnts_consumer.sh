#!/usr/bin/env bash
# Interop: NDNts consumer ← ndn-fwd → ndn-rs producer.
#
# 1. ndn-rs producer registers /interop/ndnts-consumer on ndn-fwd and serves Data.
# 2. NDNts ndncat fetches it via the ndn-fwd Unix socket with CanBePrefix discovery.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/ndnts-consumer"
CONTENT="hello-from-ndn-rs"

TMP=$(mktemp)
echo -n "${CONTENT}" > "${TMP}"
ndn-put "${PREFIX}" "${TMP}" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --freshness 5000 --timeout 10 &
PUT_PID=$!
sleep 0.5

# --ver=cbp: send CanBePrefix Interest to discover ndn-put's versioned name.
RESULT=$(NDNTS_UPLINK="unix://${FWD_SOCK}" \
  ndncat get-segmented --ver=cbp "${PREFIX}")

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
