#!/usr/bin/env bash
# Interop: ndn-rs consumer ← ndn-fwd → ndn-cxx producer.
#
# 1. ndnpoke (ndn-cxx) registers /interop/cxx-producer on ndn-fwd via Unix socket and serves one Data.
# 2. ndn-rs ndn-peek fetches it via the ndn-fwd Unix socket.
set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
PREFIX="/interop/cxx-producer"
CONTENT="hello-from-ndn-cxx"

echo -n "${CONTENT}" | NDN_CLIENT_TRANSPORT="unix://${FWD_SOCK}" \
  ndnpoke --freshness 5000 "${PREFIX}/test" &
POKE_PID=$!
sleep 1   # ndnpoke startup + rib/register propagation

# Retry the fetch: ndnpoke startup time varies under CI load; 0.5s was too
# tight and caused flakiness.  Three attempts with 2s back-off absorbs the
# variance without significantly slowing the happy path.
SUCCESS=0
for attempt in 1 2 3; do
  RESULT=$(ndn-peek "${PREFIX}/test" \
    --face-socket "${FWD_SOCK}" --no-shm \
    --lifetime 4000 2>/dev/null) || RESULT=""
  if echo "${RESULT}" | grep -q "${CONTENT}"; then
    SUCCESS=1
    break
  fi
  [ "${attempt}" -lt 3 ] && sleep 2
done

kill "${POKE_PID}" 2>/dev/null || true
if [ "${SUCCESS}" -ne 1 ]; then
  echo "ndn-peek did not return expected content after 3 retries" >&2
  echo "  last RESULT: ${RESULT}" >&2
  exit 1
fi
