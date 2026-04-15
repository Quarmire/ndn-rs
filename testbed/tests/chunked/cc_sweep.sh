#!/usr/bin/env bash
# Congestion control sweep: fetch the same 1 MB file with each of
# `--cc fixed`, `--cc aimd`, and `--cc cubic`, asserting bytes
# round-trip in every case and emitting the metrics line so the
# results table can compare throughput.
#
# Throughput numbers are not asserted (they're machine-dependent and
# the test runner sees a quiet network); the goal is to confirm the
# CC code path runs without errors on each algorithm.
set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
SIZE="${SIZE:-1048576}"
CHUNK="${CHUNK:-4096}"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

PAYLOAD="${TMP_DIR}/payload.bin"
dd if=/dev/urandom of="${PAYLOAD}" bs=1024 count=$((SIZE / 1024)) status=none
EXPECTED_SHA=$(shasum -a 256 "${PAYLOAD}" | awk '{print $1}')

PASS=0
FAIL=0

run_cc() {
  local cc="$1"
  local prefix="/test/chunked/cc-${cc}"
  local out="${TMP_DIR}/cc-${cc}.fetched"

  ndn-put "${prefix}" "${PAYLOAD}" \
    --face-socket "${FWD_SOCK}" --no-shm \
    --sign digest --chunk-size "${CHUNK}" \
    --freshness 5000 --timeout 30 --quiet &
  local pid=$!
  sleep 0.3

  if ndn-peek "${prefix}" \
      --face-socket "${FWD_SOCK}" --no-shm \
      --pipeline 16 \
      --cc "${cc}" \
      --verify digest-sha256 \
      --metrics \
      --output "${out}" 2>"${TMP_DIR}/cc-${cc}.log"; then
    local actual
    actual=$(shasum -a 256 "${out}" | awk '{print $1}')
    if [ "${actual}" = "${EXPECTED_SHA}" ]; then
      echo "[cc-${cc}] PASS"
      grep -h '^metrics:' "${TMP_DIR}/cc-${cc}.log" || true
      PASS=$((PASS + 1))
    else
      echo "[cc-${cc}] FAIL: byte mismatch"
      FAIL=$((FAIL + 1))
    fi
  else
    echo "[cc-${cc}] FAIL: peek error"
    cat "${TMP_DIR}/cc-${cc}.log" >&2 || true
    FAIL=$((FAIL + 1))
  fi
  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

run_cc fixed
run_cc aimd
run_cc cubic

echo
echo "cc sweep: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
