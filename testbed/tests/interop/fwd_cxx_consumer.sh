#!/usr/bin/env bash
# Interop: ndn-cxx consumer ← ndn-fwd → ndn-rs producer.
#
# 1. ndn-rs producer registers /interop/cxx-consumer on ndn-fwd and serves Data.
# 2. ndn-cxx ndnpeek fetches via the ndn-fwd Unix socket with CanBePrefix.
set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/cxx-consumer"
CONTENT="hello-from-ndn-rs"

TMP=$(mktemp)
echo -n "${CONTENT}" > "${TMP}"
ndn-put "${PREFIX}" "${TMP}" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --freshness 5000 --timeout 10 &
PUT_PID=$!
sleep 0.5

RESULT=$(NDN_CLIENT_TRANSPORT="unix://${FWD_SOCK}" \
  ndnpeek --prefix --timeout 4000 "${PREFIX}") || {
  echo "ndnpeek failed (exit $?)." >&2
  kill "${PUT_PID}" 2>/dev/null || true
  rm -f "${TMP}"
  exit 1
}

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
