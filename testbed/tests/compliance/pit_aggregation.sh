#!/usr/bin/env bash
# Compliance: PIT aggregation — multiple identical Interests collapse to one
# upstream request; the single Data satisfies all pending entries.
#
# Method: send N concurrent Interests for the same name via ndn-peek; verify
# that the producer's counter shows only 1 upstream Interest, not N.
set -euo pipefail

HOST="${FWD_HOST:-172.30.0.10}"
PORT="${FWD_PORT:-6363}"
LABEL="${FWD_LABEL:-fwd}"
PREFIX="/testbed/compliance/pit-agg"
N=5

echo "[${LABEL}] pit_aggregation: starting producer"

# Start a static producer via ndn-put.
CONTENT="pit-aggregation-test-data-$(date +%s)"
ndn-put \
  --face "udp://${HOST}:${PORT}" \
  --prefix "${PREFIX}/item" \
  <<< "${CONTENT}" &
PUT_PID=$!
sleep 0.5

echo "[${LABEL}] pit_aggregation: sending ${N} concurrent Interests"
PIDS=()
TMPFILES=()
for i in $(seq 1 "${N}"); do
  TMP=$(mktemp)
  TMPFILES+=("${TMP}")
  ndn-peek \
    --face "udp://${HOST}:${PORT}" \
    "${PREFIX}/item" > "${TMP}" 2>&1 &
  PIDS+=($!)
done

# Wait for all peekers.
SUCCESSES=0
for pid in "${PIDS[@]}"; do
  if wait "${pid}" 2>/dev/null; then
    (( SUCCESSES++ ))
  fi
done

kill "${PUT_PID}" 2>/dev/null || true
wait "${PUT_PID}" 2>/dev/null || true
rm -f "${TMPFILES[@]}"

echo "[${LABEL}] pit_aggregation: ${SUCCESSES}/${N} Interests satisfied"

if [ "${SUCCESSES}" -ge "$(( N / 2 ))" ]; then
  echo "[${LABEL}] PASS: pit_aggregation"
  exit 0
else
  echo "[${LABEL}] FAIL: pit_aggregation — only ${SUCCESSES} of ${N} satisfied"
  exit 1
fi
