#!/usr/bin/env bash
# Interop: NDNts consumer ← ndn-fwd → ndn-rs producer.
#
# 1. ndn-rs producer registers /interop/ndnts-consumer on ndn-fwd and serves Data.
# 2. NDNts ndnts-fetch fetches it via ndn-fwd.
set -euo pipefail

if ! command -v ndnts-fetch > /dev/null 2>&1; then
  echo "SKIP: ndnts-fetch not available" >&2
  exit 2
fi

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/ndnts-consumer"
CONTENT="hello-from-ndn-rs"

TMP=$(mktemp)
echo -n "${CONTENT}" > "${TMP}"
ndn-put "${PREFIX}" "${TMP}" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --freshness 5000 --timeout 10 &
PUT_PID=$!
sleep 0.5

RESULT=$(ndnts-fetch \
  --uplink "udp4://${FWD_HOST}:6363" \
  "${PREFIX}/test" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
