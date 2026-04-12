#!/usr/bin/env bash
# Compliance: NFD management protocol — face add, route register/unregister,
# and general status query.  Tests that the forwarder's management API is
# compatible with the NFD command/dataset format.
# Env: FWD_SOCK, FWD_LABEL
set -euo pipefail

SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
LABEL="${FWD_LABEL:-fwd}"

PASS=0
FAIL=0

check() {
  local desc="$1"
  local cmd="$2"
  local expect="$3"

  OUTPUT=$(eval "${cmd}" 2>&1 || true)
  if echo "${OUTPUT}" | grep -qE "${expect}"; then
    echo "  PASS: ${desc}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${desc}"
    echo "        cmd:    ${cmd}"
    echo "        output: ${OUTPUT}"
    echo "        expect: ${expect}"
    FAIL=$((FAIL + 1))
  fi
}

echo "[${LABEL}] mgmt_protocol: testing management protocol"

# General status
check "status/general" \
  "ndn-ctl --socket '${SOCK}' status" \
  "uptime|version|startTime|200"

# Face list
check "faces/list" \
  "ndn-ctl --socket '${SOCK}' face list" \
  "faceId|face|200"

# Route registration
check "rib/register" \
  "ndn-ctl --socket '${SOCK}' route add /testbed/mgmt-test --face 1" \
  "200|Created|registered|FaceId"

# Route appears in route list
check "route/list after register" \
  "ndn-ctl --socket '${SOCK}' route list" \
  "/testbed/mgmt-test|200"

# Route unregister
check "rib/unregister" \
  "ndn-ctl --socket '${SOCK}' route remove /testbed/mgmt-test --face 1" \
  "200|OK|removed|FaceId"

echo ""
echo "[${LABEL}] mgmt_protocol: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
