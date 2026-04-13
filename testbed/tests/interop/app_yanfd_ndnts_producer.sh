#!/usr/bin/env bash
# Interop: ndn-rs consumer → yanfd → NDNts producer.
#
# NDNts ndncat registers on yanfd via Unix socket and serves Data.
# ndn-rs ndn-peek fetches it via the yanfd Unix socket using segmented fetch.
#
# If NDNts's automatic rib/register fails, the script detects the new face that
# ndncat created (via nfdc face list, which sends unsigned queries yanfd accepts)
# and registers the route manually via ndn-ctl.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

YANFD_SOCK="${YANFD_SOCK:-/run/yanfd/nfd.sock}"
PREFIX="/interop/app-yanfd-ndnts"
CONTENT="hello-from-ndnts-via-yanfd"

# Helper: get all face IDs known to yanfd using nfdc (sends unsigned dataset
# queries that yanfd/NFD require; ndn-ctl always signs and yanfd rejects that
# for dataset queries).
yanfd_face_ids() {
  NDN_CLIENT_TRANSPORT="unix://${YANFD_SOCK}" \
    nfdc face list 2>/dev/null \
    | grep -oE 'faceid=[0-9]+' | sed 's/faceid=//' | sort -n || true
}

# Snapshot face IDs before ndncat connects.
PRE_FACES=$(yanfd_face_ids)

# Capture ndncat stderr separately so we can diagnose registration failures.
NDNTS_ERR=$(mktemp)
# ndncat put-segmented reads payload from stdin, inserts a version component,
# registers the prefix, and serves segment Interests reactively.
echo -n "${CONTENT}" | NDNTS_UPLINK="unix://${YANFD_SOCK}" \
  ndncat put-segmented "${PREFIX}" 2>"${NDNTS_ERR}" &
SRV_PID=$!
sleep 2  # allow registration + yanfd RIB propagation

# Check whether ndncat exited prematurely (registration failure).
if ! kill -0 "${SRV_PID}" 2>/dev/null; then
  echo "ndncat put-segmented exited before ndn-peek could run:" >&2
  cat "${NDNTS_ERR}" >&2
  rm -f "${NDNTS_ERR}"
  exit 1
fi

# Diagnostic: show yanfd's RIB to confirm NDNts registered the prefix.
echo "  yanfd route list (via nfdc):" >&2
NDN_CLIENT_TRANSPORT="unix://${YANFD_SOCK}" \
  nfdc route list 2>&1 | grep -E "${PREFIX}|error|Error" >&2 || \
  echo "  (route list unavailable or prefix not found)" >&2

# If NDNts's automatic rib/register didn't land in yanfd's FIB, find the new
# face that ndncat opened and register the route manually.
POST_FACES=$(yanfd_face_ids)
NDNTS_FACE=$(
  # Lines present in POST but not in PRE are new faces created by ndncat.
  comm -13 \
    <(echo "${PRE_FACES}") \
    <(echo "${POST_FACES}") \
  | sort -n | tail -1
)

if [ -n "${NDNTS_FACE}" ]; then
  echo "  Detected NDNts face: ${NDNTS_FACE}; registering route manually." >&2
  # ndn-ctl sends signed rib/register which yanfd accepts for command verbs.
  ndn-ctl --socket "${YANFD_SOCK}" route add "${PREFIX}" --face "${NDNTS_FACE}" >&2 || \
    echo "  (route add returned error — NDNts may have self-registered)" >&2
else
  echo "  No new face found; relying on NDNts self-registration." >&2
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
