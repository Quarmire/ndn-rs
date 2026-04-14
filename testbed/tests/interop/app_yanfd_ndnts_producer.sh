#!/usr/bin/env bash
# Interop: ndn-rs consumer → yanfd → NDNts producer.
#
# NDNts ndncat registers on yanfd via Unix socket and serves Data.
# ndn-rs ndn-peek fetches it via the yanfd Unix socket using segmented fetch.
#
# Route detection strategy (mirrors fwd_ndnts_producer.sh):
#   (a) After the sleep, query the FIB (ndn-ctl route list).  If the prefix is
#       already there, NDNts self-registered via rib/register — no manual step
#       needed.  Sending a spurious route add when NDNts already registered
#       causes ndncat to immediately disconnect.
#   (b) If not, fall back to manual registration: enumerate ALL active connection
#       faces (faceid < 0xFFFF_0000, excluding the reserved management face) and
#       pick the lowest-numbered one.  NDNts connected before this query, so its
#       face has the smallest ID.
#
# The old PRE/POST face-list diff was broken: it found ndncat's face even when
# NDNts had already self-registered, then ran "ndn-ctl route add" on that face,
# which caused ndncat to disconnect immediately.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="/interop/app-yanfd-ndnts"
CONTENT="hello-from-ndnts-via-yanfd"

# Capture ndncat stderr separately so we can diagnose registration failures.
NDNTS_ERR=$(mktemp)
# ndncat put-segmented reads payload from stdin, inserts a version component,
# registers the prefix, and serves segment Interests reactively.
echo -n "${CONTENT}" | NDNTS_UPLINK="unix://${YANFD_SOCK}" \
  ndncat put-segmented "${PREFIX}" 2>"${NDNTS_ERR}" &
SRV_PID=$!
sleep 2  # allow NDNts (Node.js) startup + rib/register + yanfd RIB→FIB propagation

# Check whether ndncat exited prematurely (registration failure).
if ! kill -0 "${SRV_PID}" 2>/dev/null; then
  echo "ndncat put-segmented exited before ndn-peek could run:" >&2
  cat "${NDNTS_ERR}" >&2
  rm -f "${NDNTS_ERR}"
  exit 1
fi

# Query the RIB to check whether NDNts self-registered via rib/register.
# yanfd may not support the route-list dataset command — if it returns nothing,
# treat that as "unavailable" and trust NDNts self-registration rather than
# falling back to manual route add (which kills the NDNts face immediately).
echo "  yanfd route list:" >&2
ROUTE_LIST=$(ndn-ctl --socket "${YANFD_SOCK}" route list 2>/dev/null || true)

if [ -z "${ROUTE_LIST}" ]; then
  # route list returned nothing → command not supported by this yanfd version.
  # yanfd reliably propagates NDNts's own rib/register; skip manual registration.
  echo "  (route list unavailable — trusting NDNts self-registration)" >&2
else
  echo "${ROUTE_LIST}" | grep -E "${PREFIX}|error|Error" >&2 || \
    echo "  (prefix not yet in route list)" >&2

  # Detect self-registration by presence of the prefix in the route list.
  # The output format is "Prefix  FaceID  Cost" columns — if the prefix
  # appears, NDNts completed rib/register and no manual route add is needed.
  if echo "${ROUTE_LIST}" | grep -q "${PREFIX}"; then
    echo "  NDNts self-registered; no manual registration needed." >&2
  else
    # route list returned output but the prefix is absent — NDNts did not
    # self-register.  Find the connection face and register manually.
    echo "  NDNts did not self-register; finding face and registering manually." >&2
    # Enumerate all active connection faces: face IDs below 0xFFFF_0000 (4294901760)
    # exclude the reserved management face (0xFFFF_0001 = 4294901761).
    NDNTS_FACE=$(
      ndn-ctl --socket "${YANFD_SOCK}" face list 2>/dev/null \
        | grep -oE 'faceid=[0-9]+' | sed 's/faceid=//' \
        | awk '$1 < 4294901760' | sort -n | head -1 || true
    )
    if [ -n "${NDNTS_FACE}" ]; then
      echo "  Detected NDNts face: ${NDNTS_FACE}; registering route manually." >&2
      ndn-ctl --socket "${YANFD_SOCK}" route add "${PREFIX}" --face "${NDNTS_FACE}" >&2 || \
        echo "  (route add returned error — NDNts may have self-registered)" >&2
    else
      echo "  No connection faces found; cannot register route manually." >&2
    fi
  fi
fi

# --pipeline 1: segmented fetch mode; sends CanBePrefix to discover the version
# component produced by ndncat, then fetches seg=0.
RESULT=$(ndn-peek --pipeline 1 "${PREFIX}" \
  --face-socket "${YANFD_SOCK}" --no-shm \
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
