#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → NDNts producer.
#
# 1. NDNts ndncat registers /interop/ndnts-producer on ndn-fwd via Unix socket.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket using segmented fetch
#    (CanBePrefix discovery → version component → seg=0).
#
# If NDNts's automatic rib/register fails, the script detects the new face that
# ndncat created and registers the route manually via ndn-ctl.
set -euo pipefail

if ! command -v ndncat > /dev/null 2>&1; then
  echo "SKIP: ndncat not available" >&2
  exit 2
fi

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/ndnts-producer"
CONTENT="hello-from-ndnts"

# Helper: get all face IDs known to ndn-fwd (numerically sorted).
fwd_face_ids() {
  ndn-ctl --socket "${FWD_SOCK}" face list 2>/dev/null \
    | grep -oE 'faceid=[0-9]+' | sed 's/faceid=//' | sort -n || true
}

# Snapshot face IDs before ndncat connects.
PRE_FACES=$(fwd_face_ids)

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

# Diagnostic: show ndn-fwd's RIB to confirm NDNts registered the prefix.
echo "  ndn-fwd route list:" >&2
ndn-ctl --socket "${FWD_SOCK}" route list 2>&1 | grep -E "${PREFIX}|error|Error" >&2 || \
  echo "  (route list unavailable or prefix not found)" >&2

# If NDNts's automatic rib/register didn't land in ndn-fwd's FIB, find the new
# face that ndncat opened and register the route manually.
POST_FACES=$(fwd_face_ids)
NDNTS_FACE=$(
  # Lines present in POST but not in PRE are new faces created by ndncat.
  comm -13 \
    <(echo "${PRE_FACES}") \
    <(echo "${POST_FACES}") \
  | sort -n | tail -1
)

if [ -n "${NDNTS_FACE}" ]; then
  echo "  Detected NDNts face: ${NDNTS_FACE}; registering route manually." >&2
  ndn-ctl --socket "${FWD_SOCK}" route add "${PREFIX}" --face "${NDNTS_FACE}" >&2 || \
    echo "  (route add returned error — NDNts may have self-registered)" >&2
else
  echo "  No new face found; relying on NDNts self-registration." >&2
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
