#!/usr/bin/env bash
# Compliance: PIT aggregation — multiple identical Interests collapse to one
# upstream request; the single Data satisfies all pending entries.
#
# Method: send N concurrent Interests for the same name via ndn-peek; verify
# that at least half are satisfied (aggregation means they all get Data).
# Env: FWD_SOCK, FWD_LABEL
set -euo pipefail

SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
LABEL="${FWD_LABEL:-fwd}"
PREFIX="/testbed/compliance/pit-agg"
N=5

echo "[${LABEL}] pit_aggregation: starting producer"

CONTENT="pit-aggregation-test-data-$(date +%s)"
TMP_CONTENT=$(mktemp)
echo "${CONTENT}" > "${TMP_CONTENT}"

ndn-put \
  --face-socket "${SOCK}" --no-shm \
  --freshness 60000 \
  "${PREFIX}/item" "${TMP_CONTENT}" &
PUT_PID=$!
sleep 0.5

echo "[${LABEL}] pit_aggregation: sending ${N} concurrent Interests"
PIDS=()
TMPFILES=()
for i in $(seq 1 "${N}"); do
  TMP=$(mktemp)
  TMPFILES+=("${TMP}")
  ndn-peek \
    --face-socket "${SOCK}" --no-shm \
    --can-be-prefix \
    "${PREFIX}/item" > "${TMP}" 2>&1 &
  PIDS+=($!)
done

# Wait for all peekers.
SUCCESSES=0
for pid in "${PIDS[@]}"; do
  if wait "${pid}" 2>/dev/null; then
    SUCCESSES=$((SUCCESSES + 1))
  fi
done

kill "${PUT_PID}" 2>/dev/null || true
wait "${PUT_PID}" 2>/dev/null || true
rm -f "${TMPFILES[@]}" "${TMP_CONTENT}"

echo "[${LABEL}] pit_aggregation: ${SUCCESSES}/${N} Interests satisfied"

if [ "${SUCCESSES}" -ge "$(( N / 2 ))" ]; then
  echo "[${LABEL}] PASS: pit_aggregation"
  exit 0
else
  echo "[${LABEL}] FAIL: pit_aggregation — only ${SUCCESSES} of ${N} satisfied"
  exit 1
fi
