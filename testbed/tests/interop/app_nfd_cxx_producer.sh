#!/usr/bin/env bash
# Interop: ndn-rs consumer → NFD → ndn-cxx producer.
#
# Both parties connect to NFD. ndn-cxx ndnpoke registers and serves Data via the NFD socket.
# ndn-rs ndn-peek fetches it via the same NFD socket.
#
# Note: sleep 1 (not 0.5) — NFD's RIB → FIB propagation is slower than ndn-fwd's
# in CI environments, causing flaky NoRoute Nacks with a shorter delay.
set -euo pipefail

NFD_SOCK="${NFD_SOCK:-/run/nfd/nfd.sock}"
PREFIX="/interop/app-nfd-cxx"
CONTENT="hello-from-ndn-cxx-via-nfd"

echo -n "${CONTENT}" | NDN_CLIENT_TRANSPORT="unix://${NFD_SOCK}" \
  ndnpoke --freshness 5000 "${PREFIX}/test" &
POKE_PID=$!
sleep 1  # allow ndnpoke to register with NFD and FIB propagation to complete

# Retry the fetch: NFD RIB→FIB propagation timing varies under CI load.
SUCCESS=0
for attempt in 1 2 3; do
  RESULT=$(ndn-peek "${PREFIX}/test" \
    --face-socket "${NFD_SOCK}" --no-shm \
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
