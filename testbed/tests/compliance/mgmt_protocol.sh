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

  OUTPUT=$(eval "timeout 10 ${cmd}" 2>&1 || true)
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

# Dataset-query commands (status, faces/list, route/list) require UNSIGNED Interests in NFD and yanfd.
# ndn-ctl always uses signed Interests (required by NFD for command verbs like rib/register).
# Run dataset checks only against ndn-fwd which accepts signed dataset queries.
if [ "${LABEL}" = "ndn-fwd" ]; then
  check "status/general" \
    "ndn-ctl --socket '${SOCK}' status" \
    "uptime|version|startTime|200"

  check "faces/list" \
    "ndn-ctl --socket '${SOCK}' face list" \
    "faceId|face|200"
fi

# Route registration (command verb — signed Interest accepted by all three forwarders).
check "rib/register" \
  "ndn-ctl --socket '${SOCK}' route add /testbed/mgmt-test --face 1" \
  "200|Created|registered|FaceId"

# Route list is a dataset query — run only against ndn-fwd.
if [ "${LABEL}" = "ndn-fwd" ]; then
  check "route/list after register" \
    "ndn-ctl --socket '${SOCK}' route list" \
    "/testbed/mgmt-test|200"
fi

# Route unregister (command verb — signed Interest accepted by all three forwarders).
check "rib/unregister" \
  "ndn-ctl --socket '${SOCK}' route remove /testbed/mgmt-test --face 1" \
  "200|OK|removed|FaceId"

echo ""
echo "[${LABEL}] mgmt_protocol: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
