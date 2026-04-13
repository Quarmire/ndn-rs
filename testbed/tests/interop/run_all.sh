#!/usr/bin/env bash
# Run the full interoperability test suite and write a results summary.
#
# Scenario matrix:
#
#   ndn-fwd AS FORWARDER (ndn-fwd in the middle):
#     1. ndn-cxx consumer  → ndn-fwd → ndn-rs producer
#     2. ndn-rs  consumer  → ndn-fwd → ndn-cxx producer
#     3. NDNts   consumer  → ndn-fwd → ndn-rs producer
#     4. ndn-rs  consumer  → ndn-fwd → NDNts producer
#
#   ndn-rs AS APPLICATION (external forwarder):
#     5. ndn-rs  consumer  → NFD     → ndn-cxx producer
#     6. ndn-cxx consumer  → NFD     → ndn-rs producer
#     7. ndn-rs  consumer  → yanfd   → NDNts producer
#     8. NDNts   consumer  → yanfd   → ndn-rs producer
#
# Each test writes a line:
#   [<scenario>] PASS: <description>
#   [<scenario>] FAIL: <description>  (<error>)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/results}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT="${RESULTS_DIR}/interop-${TIMESTAMP}.txt"

mkdir -p "${RESULTS_DIR}"

PASS=0
FAIL=0
SKIP=0

run_test() {
  local scenario="$1"
  local desc="$2"
  local script="$3"
  shift 3

  local EXIT=0
  bash "${SCRIPT_DIR}/${script}" "$@" 2>/tmp/interop-err || EXIT=$?
  if [ "${EXIT}" -eq 0 ]; then
    echo "[${scenario}] PASS: ${desc}" | tee -a "${REPORT}"
    PASS=$(( PASS + 1 ))
  elif [ "${EXIT}" -eq 2 ]; then
    ERR=$(tail -5 /tmp/interop-err | tr '\n' '|')
    echo "[${scenario}] SKIP: ${desc}  (${ERR})" | tee -a "${REPORT}"
    SKIP=$(( SKIP + 1 ))
  else
    ERR=$(tail -5 /tmp/interop-err | tr '\n' '|')
    echo "[${scenario}] FAIL: ${desc}  (${ERR})" | tee -a "${REPORT}"
    FAIL=$(( FAIL + 1 ))
  fi
}

echo "# NDN Interoperability Test Results — ${TIMESTAMP}" | tee "${REPORT}"
echo "" | tee -a "${REPORT}"

# ── ndn-fwd as forwarder ──────────────────────────────────────────────────────

echo "## ndn-fwd as Forwarder" | tee -a "${REPORT}"

run_test "fwd/cxx-consumer" \
  "ndn-cxx consumer ← ndn-fwd → ndn-rs producer" \
  "fwd_cxx_consumer.sh"

run_test "fwd/cxx-producer" \
  "ndn-rs consumer ← ndn-fwd → ndn-cxx producer" \
  "fwd_cxx_producer.sh"

run_test "fwd/ndnts-consumer" \
  "NDNts consumer ← ndn-fwd → ndn-rs producer" \
  "fwd_ndnts_consumer.sh"

run_test "fwd/ndnts-producer" \
  "ndn-rs consumer ← ndn-fwd → NDNts producer" \
  "fwd_ndnts_producer.sh"

# ── ndn-rs as application ──────────────────────────────────────────────────────

echo "" | tee -a "${REPORT}"
echo "## ndn-rs as Application Library" | tee -a "${REPORT}"

run_test "app/nfd-cxx-producer" \
  "ndn-rs consumer → NFD → ndn-cxx producer (with signature validation)" \
  "app_nfd_cxx_producer.sh"

run_test "app/nfd-cxx-consumer" \
  "ndn-cxx consumer → NFD → ndn-rs producer (ndn-cxx validates signature)" \
  "app_nfd_cxx_consumer.sh"

run_test "app/yanfd-ndnts-producer" \
  "ndn-rs consumer → yanfd → NDNts producer" \
  "app_yanfd_ndnts_producer.sh"

run_test "app/yanfd-ndnts-consumer" \
  "NDNts consumer → yanfd → ndn-rs producer" \
  "app_yanfd_ndnts_consumer.sh"

# ── Summary ──────────────────────────────────────────────────────────────────

echo "" | tee -a "${REPORT}"
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped" | tee -a "${REPORT}"

if [ "${FAIL}" -gt 0 ]; then
  exit 1
fi
