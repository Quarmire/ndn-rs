#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → NDNts producer.
#
# 1. NDNts ndncat registers /interop/ndnts-producer on ndn-fwd via Unix socket.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket using segmented fetch
#    (CanBePrefix discovery → version component → seg=0).
#
# Route detection strategy:
#   (a) After the sleep, query the FIB (ndn-ctl route list).  If the prefix is
#       already there, NDNts self-registered — no manual step needed.
#   (b) If not, fall back to manual registration: enumerate ALL active connection
#       faces (faceid < 0xFFFF_0000, excluding the reserved management face) and
#       pick the lowest-numbered one.  NDNts connected before this query, so its
#       face has the smallest ID.
#
# This replaces the old PRE/POST face-list diff which was broken by face-ID
# recycling: ndn-ctl allocates a face, exits, and that ID is recycled to ndncat,
# so ndncat's face cancels out of the diff and the wrong (transient) face gets
# selected for manual route registration.
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
sleep 2  # allow NDNts (Node.js) startup + rib/register + FIB propagation

# Check whether ndncat exited prematurely (registration failure).
if ! kill -0 "${SRV_PID}" 2>/dev/null; then
  echo "ndncat put-segmented exited before ndn-peek could run:" >&2
  cat "${NDNTS_ERR}" >&2
  rm -f "${NDNTS_ERR}"
  exit 1
fi

# Query the FIB to check whether NDNts self-registered via rib/register.
echo "  ndn-fwd route list:" >&2
ROUTE_LIST=$(ndn-ctl --socket "${FWD_SOCK}" route list 2>/dev/null || true)
echo "${ROUTE_LIST}" | grep -E "${PREFIX}|error|Error" >&2 || \
  echo "  (route list unavailable or prefix not found)" >&2

# Extract the face ID from the FIB entry if the prefix is already registered.
NDNTS_FACE=$(echo "${ROUTE_LIST}" | grep "${PREFIX}" \
  | grep -oE 'faceid=[0-9]+' | sed 's/faceid=//' | head -1)

if [ -n "${NDNTS_FACE}" ]; then
  echo "  NDNts self-registered on face ${NDNTS_FACE}; no manual registration needed." >&2
else
  echo "  NDNts did not self-register; finding face and registering manually." >&2
  # Enumerate all active connection faces: face IDs below 0xFFFF_0000 (4294901760)
  # exclude the reserved management face (0xFFFF_0001 = 4294901761).
  # NDNts connected before this ndn-ctl query, so it has the lowest numeric face ID.
  NDNTS_FACE=$(
    ndn-ctl --socket "${FWD_SOCK}" face list 2>/dev/null \
      | grep -oE 'faceid=[0-9]+' | sed 's/faceid=//' \
      | awk '$1 < 4294901760' | sort -n | head -1 || true
  )
  if [ -n "${NDNTS_FACE}" ]; then
    echo "  Detected NDNts face: ${NDNTS_FACE}; registering route manually." >&2
    ndn-ctl --socket "${FWD_SOCK}" route add "${PREFIX}" --face "${NDNTS_FACE}" >&2 || \
      echo "  (route add returned error — NDNts may have self-registered)" >&2
  else
    echo "  No connection faces found; cannot register route manually." >&2
  fi
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
