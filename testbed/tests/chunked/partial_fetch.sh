#!/usr/bin/env bash
# Partial-fetch correctness for Merkle-signed segmented Data.
#
# Publishes a 16-segment file, then fetches segments [4..12) only
# via `--start 4 --count 8`. Asserts the consumer receives exactly
# the bytes `payload[4*chunk .. 12*chunk]`.
#
# This is the user-visible test for the partial-fetch path that
# the Merkle work was designed to enable. With per-segment Ed25519
# the same range fetch would cost K asymmetric verifies; with
# Merkle it's one manifest verify + K cheap hash walks.
set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/nfd/nfd.sock}"
CHUNK=1024
SEGS=16

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

PAYLOAD="${TMP_DIR}/payload.bin"
dd if=/dev/urandom of="${PAYLOAD}" bs="${CHUNK}" count="${SEGS}" status=none

# Slice out the expected partial range bytes.
EXPECTED="${TMP_DIR}/expected.bin"
dd if="${PAYLOAD}" of="${EXPECTED}" bs="${CHUNK}" skip=4 count=8 status=none
EXPECTED_SHA=$(shasum -a 256 "${EXPECTED}" | awk '{print $1}')

PREFIX="/test/chunked/partial-merkle"

ndn-put "${PREFIX}" "${PAYLOAD}" \
  --face-socket "${FWD_SOCK}" --no-shm \
  --sign merkle --hash sha256 \
  --chunk-size "${CHUNK}" \
  --freshness 5000 --timeout 30 --quiet &
PUT_PID=$!
sleep 0.3

OUT="${TMP_DIR}/fetched.bin"
if ! ndn-peek "${PREFIX}" \
      --face-socket "${FWD_SOCK}" --no-shm \
      --pipeline 4 \
      --verify merkle \
      --start 4 --count 8 \
      --metrics \
      --output "${OUT}" 2>"${TMP_DIR}/peek.log"; then
  echo "FAIL: partial-fetch peek error" >&2
  cat "${TMP_DIR}/peek.log" >&2
  kill "${PUT_PID}" 2>/dev/null || true
  exit 1
fi

ACTUAL_SHA=$(shasum -a 256 "${OUT}" | awk '{print $1}')
kill "${PUT_PID}" 2>/dev/null || true
wait "${PUT_PID}" 2>/dev/null || true

if [ "${ACTUAL_SHA}" != "${EXPECTED_SHA}" ]; then
  echo "FAIL: partial-fetch byte mismatch (expected ${EXPECTED_SHA}, got ${ACTUAL_SHA})" >&2
  exit 1
fi

grep -h '^metrics:' "${TMP_DIR}/peek.log" || true
echo "PASS: merkle partial-fetch [4..12) of 16 segments"
