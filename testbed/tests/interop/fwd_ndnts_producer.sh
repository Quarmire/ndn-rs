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

# Capture ndncat stderr separately so we can diagnose registration failures.
NDNTS_ERR=$(mktemp)
# ndncat put-segmented reads payload from stdin, inserts a version component,
# registers the prefix, and serves segment Interests reactively.
echo -n "${CONTENT}" | NDNTS_UPLINK="unix://${FWD_SOCK}" \
  ndncat put-segmented "${PREFIX}" 2>"${NDNTS_ERR}" &
SRV_PID=$!
sleep 1  # allow registration

# Check whether ndncat exited prematurely (registration failure).
if ! kill -0 "${SRV_PID}" 2>/dev/null; then
  echo "ndncat put-segmented exited before ndn-peek could run:" >&2
  cat "${NDNTS_ERR}" >&2
  rm -f "${NDNTS_ERR}"
  exit 1
fi

# --pipeline 1: segmented fetch mode; sends CanBePrefix to discover the version
# component produced by ndncat, then fetches seg=0.
RESULT=$(ndn-peek --pipeline 1 "${PREFIX}" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --lifetime 4000) || {
  echo "ndn-peek failed (exit $?):" >&2
  echo "  ndncat stderr:" >&2
  cat "${NDNTS_ERR}" >&2
  kill "${SRV_PID}" 2>/dev/null || true
  rm -f "${NDNTS_ERR}"
  exit 1
}

kill "${SRV_PID}" 2>/dev/null || true
rm -f "${NDNTS_ERR}"
echo "${RESULT}" | grep -q "${CONTENT}"
