#!/usr/bin/env bash
# Compliance: Content Store — second Interest for the same name is satisfied
# from cache without reaching the producer.
set -euo pipefail

HOST="${FWD_HOST:-172.30.0.10}"
PORT="${FWD_PORT:-6363}"
LABEL="${FWD_LABEL:-fwd}"
PREFIX="/testbed/compliance/cs-test"

echo "[${LABEL}] cs_behavior: producing one Data packet"

CONTENT="cs-test-$(date +%s)"
ndn-put \
  --face "udp://${HOST}:${PORT}" \
  --prefix "${PREFIX}/obj" \
  <<< "${CONTENT}" &
PUT_PID=$!
sleep 0.3

echo "[${LABEL}] cs_behavior: first fetch (populates CS)"
OUT1=$(ndn-peek --face "udp://${HOST}:${PORT}" "${PREFIX}/obj" 2>&1 || echo "FAIL")

echo "[${LABEL}] cs_behavior: killing producer"
kill "${PUT_PID}" 2>/dev/null || true
wait "${PUT_PID}" 2>/dev/null || true
sleep 0.2

echo "[${LABEL}] cs_behavior: second fetch (must come from CS)"
OUT2=$(ndn-peek --face "udp://${HOST}:${PORT}" "${PREFIX}/obj" 2>&1 || echo "FAIL_CS")

if echo "${OUT1}" | grep -qF "${CONTENT}" && echo "${OUT2}" | grep -qF "${CONTENT}"; then
  echo "[${LABEL}] PASS: cs_behavior — both fetches succeeded (second from CS)"
  exit 0
else
  echo "[${LABEL}] FAIL: cs_behavior"
  echo "  First fetch:  ${OUT1}"
  echo "  Second fetch: ${OUT2}"
  exit 1
fi
