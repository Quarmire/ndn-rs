#!/usr/bin/env bash
# Interop: ndn-cxx consumer → NFD → ndn-rs producer.
#
# Both parties connect to NFD. ndn-rs registers on the NFD socket and serves Data.
# ndn-cxx ndnpeek fetches it via the same NFD socket.
set -euo pipefail

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
PREFIX="/interop/app-nfd-rs"
CONTENT="hello-from-ndn-rs-via-nfd"

TMP=$(mktemp)
echo -n "${CONTENT}" > "${TMP}"
ndn-put "${PREFIX}" "${TMP}" \
  --face-socket "${NFD_SOCK}" --no-shm \
  --freshness 5000 --timeout 10 &
PUT_PID=$!
sleep 0.5

RESULT=$(NDN_CLIENT_TRANSPORT="unix://${NFD_SOCK}" \
  ndnpeek --prefix --timeout 4000 "${PREFIX}") || {
  echo "ndnpeek failed (exit $?)." >&2
  kill "${PUT_PID}" 2>/dev/null || true
  rm -f "${TMP}"
  exit 1
}

kill "${PUT_PID}" 2>/dev/null || true
rm -f "${TMP}"
echo "${RESULT}" | grep -q "${CONTENT}"
