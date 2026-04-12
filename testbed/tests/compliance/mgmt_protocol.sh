#!/usr/bin/env bash
# Compliance: NFD management protocol — face add, route register/unregister,
# and general status query.  Tests that the forwarder's management API is
# compatible with the NFD command/dataset format.
set -euo pipefail

HOST="${FWD_HOST:-172.30.0.10}"
PORT="${FWD_PORT:-6363}"
LABEL="${FWD_LABEL:-fwd}"
FACE="udp://${HOST}:${PORT}"

PASS=0
FAIL=0

check() {
  local desc="$1"
  local cmd="$2"
  local expect="$3"

  OUTPUT=$(eval "${cmd}" 2>&1 || true)
  if echo "${OUTPUT}" | grep -qE "${expect}"; then
    echo "  PASS: ${desc}"
    (( PASS++ ))
  else
    echo "  FAIL: ${desc}"
    echo "        cmd:    ${cmd}"
    echo "        output: ${OUTPUT}"
    echo "        expect: ${expect}"
    (( FAIL++ ))
  fi
}

echo "[${LABEL}] mgmt_protocol: testing management protocol"

# General status
check "status/general" \
  "ndn-ctl --face '${FACE}' status" \
  "uptime|version|startTime"

# Face list
check "faces/list" \
  "ndn-ctl --face '${FACE}' face list" \
  "faceId|face"

# Route registration
check "rib/register" \
  "ndn-ctl --face '${FACE}' route add /testbed/mgmt-test" \
  "200|Created|registered"

# Route appears in FIB list
check "fib/list after register" \
  "ndn-ctl --face '${FACE}' route list" \
  "/testbed/mgmt-test"

# Route unregister
check "rib/unregister" \
  "ndn-ctl --face '${FACE}' route remove /testbed/mgmt-test" \
  "200|OK|removed"

echo ""
echo "[${LABEL}] mgmt_protocol: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
