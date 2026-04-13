#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → NDNts producer.
#
# 1. NDNts ndncat registers /interop/ndnts-producer on ndn-fwd via Unix socket.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket using segmented fetch
#    (CanBePrefix discovery → version component → seg=0).
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/ndnts-producer"
CONTENT="hello-from-ndnts"

# ndncat put-segmented reads payload from stdin, inserts a version component,
# registers the prefix, and serves segment Interests reactively.
echo -n "${CONTENT}" | NDNTS_UPLINK="unix://${FWD_SOCK}" \
  ndncat put-segmented "${PREFIX}" &
SRV_PID=$!
sleep 1  # allow registration

# --pipeline 1: segmented fetch mode; sends CanBePrefix to discover the version
# component produced by ndncat, then fetches seg=0.
RESULT=$(ndn-peek --pipeline 1 "${PREFIX}" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --lifetime 4000 2>&1)

kill "${SRV_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
