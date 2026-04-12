#!/usr/bin/env bash
# Interop: NDNts consumer ← ndn-fwd → ndn-rs producer.
#
# 1. ndn-rs producer registers /interop/ndnts-consumer on ndn-fwd and serves Data.
# 2. NDNts ndnts-fetch fetches it via ndn-fwd.
set -euo pipefail

if ! command -v ndnts-fetch > /dev/null 2>&1; then
  echo "ERROR: ndnts-fetch is not available; install @ndn/tools from the NDNts package" >&2
  exit 1
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
rm -f "${TMP}"
sleep 0.5

RESULT=$(ndnts-fetch \
  --uplink "udp4://${FWD_HOST}:6363" \
  "${PREFIX}/test" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true
echo "${RESULT}" | grep -q "${CONTENT}"
