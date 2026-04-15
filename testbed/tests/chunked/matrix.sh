#!/usr/bin/env bash
# Expanded test matrix for ndn-put / ndn-peek chunked file transfer.
#
# Sweeps multiple dimensions and dumps results as TSV so they can be
# grep/sort/awk'd or pasted into a spreadsheet. The matrix is
# deliberately sparse — a full Cartesian product of every dimension
# would be hundreds of cells. Instead each section varies one or two
# dimensions at a time while holding the others at a sensible
# baseline.
#
# ── What the first run of this matrix actually measured ────────────────────
#
# Run on 16 MB / 4 KB segments / pipeline=64 / AIMD, Apple Silicon,
# all 31 cells passing, throughput ~2.3 Gbps steady state:
#
#   1. The ~2.3 Gbps figure is a **Unix-socket forwarder pipeline
#      ceiling**, not a crypto ceiling. Every sign mode — digest,
#      blake3digest, hmac (verify=none), blake3keyed, merkle-sha,
#      merkle-blake — lands within 4% of each other (spread 2241 →
#      2329 Mbps). At this file size, segment size, and pipeline
#      depth, the forwarder saturates at ~17 µs per segment of
#      pipeline round-trip work regardless of what the producer is
#      signing, and crypto differences are below the per-run noise
#      floor (~100–200 Mbps).
#
#   2. Producer-side `--pre-sign` gave a ~4% speedup on digest and a
#      ~4% apparent *slowdown* on merkle-sha (which is always
#      pre-built regardless of the flag, so the gap is noise). At
#      these throughputs pre-sign is effectively free and effectively
#      useless — producer signing is dwarfed by forwarder pipeline
#      cost. It may matter on configurations where the producer is
#      not co-located with the forwarder.
#
#   3. Segment size matters more than crypto. Going from 4 KB → 256
#      KB segments at the same 16 MB file boosted throughput from
#      ~2.24 Gbps to ~2.43 Gbps (+8.5%) for both Merkle variants,
#      purely because a 16 MB file in 4096 segments pays 70 ms of
#      cumulative pipeline round-trips vs 64 × 17 µs = ~1.1 ms at
#      256 KB segments. Larger segments are the single biggest
#      throughput lever this matrix exposes.
#
#   4. BLAKE3 never demonstrated a per-leaf advantage over SHA-256.
#      At 4 KB segments BLAKE3 is per-call overhead-bound and slower.
#      At 64 KB / 256 KB the gap is within noise. Even at sweep 6's
#      1 MB segments on a 64 MB file — the configuration *designed*
#      to let `Hasher::update_rayon` engage — SHA-256 Merkle and
#      BLAKE3 Merkle came in at 2883 Mbps and 2868 Mbps respectively
#      (0.5% delta, noise). The reason: the Merkle primitive hashes
#      each *segment* as a leaf via single-call `keyed_hash`, not the
#      full file, so BLAKE3's tree-mode parallelism never engages
#      regardless of segment size.
#
#   5. Pipeline × CC did not materially change throughput. Fixed,
#      AIMD, and cubic @ 64 and 256 all landed within ~5% of each
#      other at the saturation ceiling.
#
#   6. KNOWN BUG: the `pipe-64-cubic` cell in sweep 4 produced 29
#      Mbps (75× slower than every other cell) — the fetch wall hit
#      4.57 seconds instead of ~62 ms. Cubic at initial_window=64
#      appears to stall the window for some reason; `pipe-256-cubic`
#      works fine. This is a bug in
#      `crates/foundation/ndn-transport/src/congestion.rs`, not in
#      this script. Avoid `--cc cubic` with pipeline < 128 until it
#      is fixed.
#
#   7. `--no-assemble` at 64 MB gave a ~3% speed win (2347 → 2420
#      Mbps) plus a ~130× memory reduction (~1 MB peak instead of
#      ~130 MB). The memory story is the real reason to use it.
#
#   8. Sweep 6's 1 MB-segment cells were the fastest in the entire
#      matrix (~2.88 Gbps). This is a **segment-size effect**, not a
#      BLAKE3 effect: fewer Interests, fewer round-trips, more bytes
#      per packet. Both Merkle variants benefit equally.
#
# Net: **the matrix is a good forwarder-throughput characterization
# tool but a poor crypto-comparison tool** at these file/segment
# sizes. For actual crypto deltas, see the in-process Criterion
# benches in `crates/engine/ndn-security/benches/merkle_segmented.rs`,
# which isolate hash cost from the forwarder pipeline. A future
# expansion of this script might add a "tiny file" sweep (256 KB
# files, 4 KB segments) where the forwarder doesn't saturate and
# per-segment crypto becomes a measurable fraction of total work.
#
# Dimensions:
#   - sign mode × hash:     digest, blake3digest, hmac, blake3keyed,
#                           ed25519, merkle/sha256, merkle/blake3
#   - file size:            1 MB, 16 MB, 64 MB
#   - segment size:         4 KB, 64 KB, 256 KB
#   - pipeline window:      16, 64, 256
#   - cc algorithm:         fixed, aimd, cubic
#   - producer pre-sign:    off, on
#   - consumer batch-verify: off, on (ed25519 only)
#   - consumer no-assemble: off, on
#
# Each cell emits a TSV row:
#   file_mb  seg_kb  sign_mode  hash  pipeline  cc  pre_sign  verify_mode  batch  no_asm  result  bytes  fetch_us  verify_us  manifest_us  throughput_mbps
#
# Baseline (held constant unless the test sweeps it):
#   file=16 MB, seg=4 KB, pipeline=64, cc=aimd, pre_sign=on

set -euo pipefail

FWD_SOCK="${FWD_SOCK:-/run/nfd/nfd.sock}"
RESULTS="${RESULTS:-/tmp/ndn-test/matrix.tsv}"

mkdir -p "$(dirname "${RESULTS}")"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "${TMP_DIR}"' EXIT

# Preserve the header only on a fresh run. Append on subsequent runs
# so multiple matrix invocations accumulate into one spreadsheet.
if [ ! -f "${RESULTS}" ]; then
  printf 'file_mb\tseg_kb\tsign\thash\tpipeline\tcc\tpresign\tverify\tbatch\tno_asm\tresult\tbytes\tfetch_us\tverify_us\tmanifest_us\tthroughput_mbps\tlabel\n' \
    > "${RESULTS}"
fi

# ── Deterministic payload generator ────────────────────────────────────────
# We reuse the same payload across cells of the same file size so
# producer startup time isn't dominated by dd(1) calls.
declare -A PAYLOADS
payload_for() {
  local size_mb="$1"
  if [ -z "${PAYLOADS[${size_mb}]:-}" ]; then
    local path="${TMP_DIR}/payload-${size_mb}mb.bin"
    dd if=/dev/urandom of="${path}" bs=$((1024 * 1024)) count="${size_mb}" \
      status=none
    PAYLOADS[${size_mb}]="${path}"
  fi
  printf '%s' "${PAYLOADS[${size_mb}]}"
}

# ── Single cell runner ─────────────────────────────────────────────────────
# $1 label    $2 file_mb   $3 seg_kb    $4 sign     $5 hash
# $6 pipeline $7 cc        $8 pre_sign  $9 verify   $10 batch  $11 no_asm
run_cell() {
  local label="$1" file_mb="$2" seg_kb="$3" sign="$4" hash="$5"
  local pipeline="$6" cc="$7" pre_sign="$8" verify="$9"
  local batch="${10}" no_asm="${11}"

  local payload
  payload=$(payload_for "${file_mb}")
  local chunk=$((seg_kb * 1024))
  local prefix="/test/matrix/${label}-$$"
  local out="${TMP_DIR}/${label}.out"

  local put_extra=""
  if [ "${pre_sign}" = "on" ]; then
    put_extra="--pre-sign"
  fi

  local peek_extra=""
  if [ "${batch}" = "on" ]; then
    peek_extra+=" --batch-verify"
  fi
  if [ "${no_asm}" = "on" ]; then
    peek_extra+=" --no-assemble"
  fi

  # shellcheck disable=SC2086
  ndn-put "${prefix}" "${payload}" \
    --face-socket "${FWD_SOCK}" --no-shm \
    --sign "${sign}" --hash "${hash}" \
    --chunk-size "${chunk}" \
    --freshness 5000 --timeout 60 --quiet \
    ${put_extra} \
    > "${TMP_DIR}/${label}.put.log" 2>&1 &
  local put_pid=$!
  # Pre-sign mode takes longer to start (N DataBuilder calls at
  # startup); give it a head start proportional to file size.
  local startup_sleep=1
  if [ "${pre_sign}" = "on" ] && [ "${file_mb}" -ge 16 ]; then
    startup_sleep=3
  fi
  sleep "${startup_sleep}"

  local log="${TMP_DIR}/${label}.peek.log"
  # shellcheck disable=SC2086
  if ndn-peek "${prefix}" \
      --face-socket "${FWD_SOCK}" --no-shm \
      --pipeline "${pipeline}" \
      --cc "${cc}" \
      --verify "${verify}" \
      --metrics \
      ${peek_extra} \
      --output "${out}" \
      > "${log}" 2>&1; then
    local result=PASS
    local metrics_line
    metrics_line=$(grep -h '^metrics:' "${log}" | head -1)
    # Strip the `metrics: ` prefix and parse the JSON inline with
    # plain awk — we don't want a jq dependency.
    local bytes fetch_us verify_us manifest_us
    bytes=$(printf '%s' "${metrics_line}" | grep -o '"bytes":[0-9]*' | head -1 | cut -d: -f2)
    fetch_us=$(printf '%s' "${metrics_line}" | grep -o '"fetch_wall_us":[0-9]*' | head -1 | cut -d: -f2)
    verify_us=$(printf '%s' "${metrics_line}" | grep -o '"verify_wall_us":[0-9]*' | head -1 | cut -d: -f2)
    manifest_us=$(printf '%s' "${metrics_line}" | grep -o '"manifest_fetch_us":[0-9]*' | head -1 | cut -d: -f2)
    local throughput_mbps
    if [ -n "${fetch_us}" ] && [ "${fetch_us}" -gt 0 ]; then
      throughput_mbps=$(awk -v b="${bytes:-0}" -v u="${fetch_us}" \
        'BEGIN { printf "%.1f", (b * 8) / u }')
    else
      throughput_mbps=0
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${file_mb}" "${seg_kb}" "${sign}" "${hash}" "${pipeline}" "${cc}" \
      "${pre_sign}" "${verify}" "${batch}" "${no_asm}" "${result}" \
      "${bytes:-0}" "${fetch_us:-0}" "${verify_us:-0}" "${manifest_us:-0}" \
      "${throughput_mbps}" "${label}" >> "${RESULTS}"
    echo "[${label}] PASS  ${throughput_mbps} Mbps  (bytes=${bytes:-?}  fetch=${fetch_us:-?}µs  verify=${verify_us:-?}µs)"
  else
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t-\t-\t-\t-\t-\t%s\n' \
      "${file_mb}" "${seg_kb}" "${sign}" "${hash}" "${pipeline}" "${cc}" \
      "${pre_sign}" "${verify}" "${batch}" "${no_asm}" "FAIL" "${label}" \
      >> "${RESULTS}"
    echo "[${label}] FAIL"
    tail -5 "${log}" >&2 || true
  fi
  kill "${put_pid}" 2>/dev/null || true
  wait "${put_pid}" 2>/dev/null || true
}

# ── Baseline: one cell per sign mode at file=16 MB, seg=4 KB ───────────────
# These match the earlier roundtrip.sh coverage but at a larger file
# size so the pipeline has room to saturate.
echo "── baseline: sign mode sweep @ 16 MB file, 4 KB seg, pipeline=64, cc=aimd, pre-sign=on ──"
run_cell "base-digest"        16 4 digest       sha256 64 aimd on digest-sha256 off off
run_cell "base-blake3digest"  16 4 blake3digest sha256 64 aimd on digest-blake3 off off
run_cell "base-hmac"          16 4 hmac         sha256 64 aimd on none          off off
run_cell "base-blake3keyed"   16 4 blake3keyed  sha256 64 aimd on none          off off
run_cell "base-merkle-sha"    16 4 merkle       sha256 64 aimd on merkle        off off
run_cell "base-merkle-blake"  16 4 merkle       blake3 64 aimd on merkle        off off

# ── Sweep 1: producer pre-sign impact ──────────────────────────────────────
# Hold everything else and flip --pre-sign. Shows the producer-side
# cost of lazy per-Interest signing vs pre-built wires.
echo "── sweep 1: --pre-sign on/off ──"
run_cell "presign-off-digest"      16 4 digest       sha256 64 aimd off digest-sha256 off off
run_cell "presign-off-merkle-sha"  16 4 merkle       sha256 64 aimd off merkle        off off

# ── Sweep 2: file size ─────────────────────────────────────────────────────
# Hold sign=digest so we're measuring pipeline + CC, not crypto.
echo "── sweep 2: file size (4 MB / 16 MB / 64 MB) ──"
run_cell "size-4mb-digest"    4  4 digest sha256 64 aimd on digest-sha256 off off
run_cell "size-16mb-digest"  16  4 digest sha256 64 aimd on digest-sha256 off off
run_cell "size-64mb-digest"  64  4 digest sha256 64 aimd on digest-sha256 off off

# ── Sweep 3: segment size (the BLAKE3 crossover) ───────────────────────────
# BLAKE3's single-call performance crosses SHA-NI around 256 KB. A
# 64 MB file in 256 KB segments = 256 segments, same N as the 16 MB
# / 64 KB case — but each leaf hash is on 256 KB instead of 64 KB,
# which is where BLAKE3's tree-mode SIMD actually helps.
echo "── sweep 3: segment size sweep (4 KB / 64 KB / 256 KB) for both merkle variants ──"
run_cell "seg-4k-merkle-sha"    16   4 merkle sha256 64 aimd on merkle off off
run_cell "seg-64k-merkle-sha"   16  64 merkle sha256 64 aimd on merkle off off
run_cell "seg-256k-merkle-sha"  16 256 merkle sha256 64 aimd on merkle off off
run_cell "seg-4k-merkle-blake"    16   4 merkle blake3 64 aimd on merkle off off
run_cell "seg-64k-merkle-blake"   16  64 merkle blake3 64 aimd on merkle off off
run_cell "seg-256k-merkle-blake"  16 256 merkle blake3 64 aimd on merkle off off

# ── Sweep 4: pipeline depth × CC ───────────────────────────────────────────
# Hold file=16 MB / seg=4 KB / sign=digest / pre-sign=on (the
# producer is as fast as we can make it). Vary pipeline and CC
# together so AIMD/cubic have more window to grow into.
echo "── sweep 4: pipeline × cc ──"
run_cell "pipe-16-fixed"    16 4 digest sha256  16 fixed on digest-sha256 off off
run_cell "pipe-64-fixed"    16 4 digest sha256  64 fixed on digest-sha256 off off
run_cell "pipe-256-fixed"   16 4 digest sha256 256 fixed on digest-sha256 off off
run_cell "pipe-16-aimd"     16 4 digest sha256  16 aimd  on digest-sha256 off off
run_cell "pipe-64-aimd"     16 4 digest sha256  64 aimd  on digest-sha256 off off
run_cell "pipe-256-aimd"    16 4 digest sha256 256 aimd  on digest-sha256 off off
run_cell "pipe-64-cubic"    16 4 digest sha256  64 cubic on digest-sha256 off off
run_cell "pipe-256-cubic"   16 4 digest sha256 256 cubic on digest-sha256 off off

# ── Sweep 5: consumer no-assemble ──────────────────────────────────────────
# Larger files where the reassembly cost becomes measurable.
echo "── sweep 5: --no-assemble on/off ──"
run_cell "noasm-off-64mb"  64 4 digest sha256 256 aimd on digest-sha256 off off
run_cell "noasm-on-64mb"   64 4 digest sha256 256 aimd on digest-sha256 off on

# ── Sweep 6: blake3 large inputs — where rayon dispatch might help ─────────
# At 256 KB segments and 64 MB file, we have 256 segments. Producer
# hashes each one; blake3 uses update_rayon above the 128 KiB
# threshold so these 256 KB leaves should exercise the multi-
# threaded hashing path.
echo "── sweep 6: large-segment blake3 (where update_rayon engages) ──"
run_cell "rayon-256k-merkle-sha"   64 256 merkle sha256 64 aimd on merkle off off
run_cell "rayon-256k-merkle-blake" 64 256 merkle blake3 64 aimd on merkle off off
run_cell "rayon-1024k-merkle-sha"  64 1024 merkle sha256 64 aimd on merkle off off
run_cell "rayon-1024k-merkle-blake" 64 1024 merkle blake3 64 aimd on merkle off off

# ── Summary ────────────────────────────────────────────────────────────────
PASS_COUNT=$(awk -F'\t' 'NR>1 && $11=="PASS"' "${RESULTS}" | wc -l | tr -d ' ')
FAIL_COUNT=$(awk -F'\t' 'NR>1 && $11=="FAIL"' "${RESULTS}" | wc -l | tr -d ' ')
echo
echo "matrix: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
echo "results → ${RESULTS}"
echo
echo "quick summary (top 10 by throughput, passing only):"
awk -F'\t' 'NR==1 || $11=="PASS"' "${RESULTS}" \
  | sort -t$'\t' -k16 -rn | head -11 \
  | awk -F'\t' 'BEGIN { printf "  %-28s %8s %6s %8s %s\n", "label", "Mbps", "seg", "cc", "pipe/psign/noasm" }
                NR>1 { printf "  %-28s %8s %6s %8s %s/%s/%s\n", $17, $16, $2"KB", $6, $5, $7, $10 }'

[ "${FAIL_COUNT}" -eq 0 ]
