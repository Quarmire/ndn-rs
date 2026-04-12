#!/usr/bin/env bash
# Interop: ndn-cxx consumer ← ndn-fwd → ndn-rs producer.
#
# 1. ndn-rs producer registers /interop/cxx-consumer on ndn-fwd and serves Data
#    signed with an Ed25519 key.
# 2. ndn-cxx ndnpeek fetches /interop/cxx-consumer/test and verifies the Data
#    arrives (content check only — ndn-cxx trust schema validation is opt-in).
set -euo pipefail

FWD_HOST="${FWD_HOST:-ndn-fwd}"
FWD_UDP="udp://${FWD_HOST}:6363"
PREFIX="/interop/cxx-consumer"

# ndn-rs producer: serve one Interest and exit.
ndn-put \
  --face "${FWD_UDP}" \
  --prefix "${PREFIX}" \
  --content "hello-from-ndn-rs" \
  --ttl 5 \
  --sign &
PUT_PID=$!
sleep 0.5

# ndn-cxx consumer: fetch the Data.
RESULT=$(ndnpeek --timeout 4000 "${PREFIX}/test" \
  --face "${FWD_UDP}" 2>&1)

kill "${PUT_PID}" 2>/dev/null || true

echo "${RESULT}" | grep -q "hello-from-ndn-rs"
