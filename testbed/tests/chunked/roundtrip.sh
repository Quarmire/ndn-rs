#!/usr/bin/env bash
# Chunked file transfer roundtrip across all ndn-put / ndn-peek
# signing modes, with a real ndn-fwd in the loop.
#
# For each (sign, hash, verify) combination, the script:
#   1. Writes a random ~1 MB payload to a temp file.
#   2. Spawns `ndn-put` against ndn-fwd's face socket with the
#      requested signing mode.
#   3. Runs `ndn-peek` against the same socket with `--pipeline 16`,
#      `--metrics`, and the matching `--verify` mode.
#   4. Diffs the fetched bytes against the original.
#
# Sign / verify pairs:
#
#   digest        / digest-sha256
#   blake3digest  / digest-blake3
#   ed25519       / ed25519       (with --batch-verify)
#   merkle/sha256 / merkle
#   merkle/blake3 / merkle
#   hmac          / none           (no consumer key)
#   blake3keyed   / none           (no consumer key)
#
# Outputs the metrics JSON line for each successful run so the
# results table can compare wall-clock and per-segment verify times
# across schemes.
set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/ndn-fwd/ndn-fwd.sock}"
SIZE="${SIZE:-1048576}"           # 1 MB
CHUNK="${CHUNK:-4096}"
PREFIX_BASE="${PREFIX_BASE:-/test/chunked}"

PASS=0
FAIL=0

# ── Generate a deterministic payload once and reuse across runs ─────────────
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT
PAYLOAD="${TMP_DIR}/payload.bin"
# Deterministic pseudo-random 1 MB blob.
dd if=/dev/urandom of="${PAYLOAD}" bs=1024 count=$((SIZE / 1024)) status=none

# Compute the expected sha256 once for the diff step; comparing
# hashes is faster than diffing megabytes of binary data.
EXPECTED_SHA=$(shasum -a 256 "${PAYLOAD}" | awk '{print $1}')

# ── Per-case driver ────────────────────────────────────────────────────────
# $1: case label
# $2: --sign value
# $3: --hash value
# $4: --verify value
# $5: extra ndn-peek args (e.g. --batch-verify)
run_case() {
  local label="$1"
  local sign="$2"
  local hash="$3"
  local verify="$4"
  local extra="${5-}"
  local prefix="${PREFIX_BASE}/${label}"
  local out="${TMP_DIR}/${label}.fetched"

  ndn-put "${prefix}" "${PAYLOAD}" \
    --face-socket "${FWD_SOCK}" --no-shm \
    --sign "${sign}" --hash "${hash}" \
    --chunk-size "${CHUNK}" \
    --freshness 5000 --timeout 30 --quiet &
  local put_pid=$!
  sleep 0.3

  # shellcheck disable=SC2086
  if ndn-peek "${prefix}" \
      --face-socket "${FWD_SOCK}" --no-shm \
      --pipeline 16 \
      --verify "${verify}" \
      --metrics \
      ${extra} \
      --output "${out}" 2>"${TMP_DIR}/${label}.peek.log"; then
    local actual
    actual=$(shasum -a 256 "${out}" | awk '{print $1}')
    if [ "${actual}" = "${EXPECTED_SHA}" ]; then
      echo "[${label}] PASS"
      grep -h '^metrics:' "${TMP_DIR}/${label}.peek.log" || true
      PASS=$((PASS + 1))
    else
      echo "[${label}] FAIL: byte mismatch"
      FAIL=$((FAIL + 1))
    fi
  else
    echo "[${label}] FAIL: peek error"
    cat "${TMP_DIR}/${label}.peek.log" >&2 || true
    FAIL=$((FAIL + 1))
  fi
  kill "${put_pid}" 2>/dev/null || true
  wait "${put_pid}" 2>/dev/null || true
}

# ── The matrix ─────────────────────────────────────────────────────────────
run_case "digest"       digest        sha256 digest-sha256
run_case "blake3digest" blake3digest  sha256 digest-blake3
run_case "merkle-sha"   merkle        sha256 merkle
run_case "merkle-blake" merkle        blake3 merkle
run_case "hmac"         hmac          sha256 none
run_case "blake3keyed"  blake3keyed   sha256 none

# Note: ed25519 is omitted from the script-level test because it
# requires the producer's public key to flow out-of-band to the
# consumer (`--pubkey` flag), which the chunked roundtrip script
# can't easily synthesise. The Rust integration tests for the
# Ed25519 mode live in the engine-level merkle_e2e bench instead.

echo
echo "chunked roundtrip: ${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
