#!/usr/bin/env bash
# Regression guard: SHM + DigestSha256 internal throughput, shared vs
# partitioned(N=1) data plane.
#
# The forwarding core sustains 20+ Gbps over shared memory with a cheap
# DigestSha256 "signature" (the data structures are not the bottleneck there —
# see .claude/notes/partitioned-fwd-design-2026-05-24.md). Before Phase 2 adds
# the NDT + N workers, this pins that the partitioned RUNTIME (decode-in-RX →
# worker → forward_decoded) does not regress the single-worker path: the extra
# RX→worker channel hop must be ~free.
#
# It starts its own ndn-fwd in each mode (own app socket, no network faces, no
# signed mgmt), runs an internal ndn-iperf consumer/producer pair over SHM, and
# compares Gbps. Exits non-zero if partitioned drops below REGRESS_PCT of
# shared.
#
# Env knobs:
#   DURATION=10  WINDOW=256  REGRESS_PCT=90  SIGN=digest_sha256  SIZE=8192
#   BUILD=1                 # force `cargo build --release` of the binaries
#   FWD=<path> IPERF=<path> # use prebuilt binaries instead of building
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$(pwd)"

DURATION="${DURATION:-10}"
WINDOW="${WINDOW:-256}"        # ≥256 → throughput-bound, not RTT-bound
ITERS="${ITERS:-3}"           # client runs per mode; the max (peak) is reported
WORKERS="${WORKERS:-1}"       # partitioned worker count (1 = isolate seam overhead)
VALIDATE="${VALIDATE:-0}"     # 1 = force forwarder Data validation on the SHM
                              #     (Local) faces. NOTE: ndn-iperf's control
                              #     exchange stalls under forced validation; for
                              #     a clean crypto-stress shared-vs-partitioned
                              #     comparison use the in-process harness
                              #     `cargo test -p ndn-engine --features
                              #     partitioned-fwd --release --test
                              #     partition_throughput -- --ignored` (VALIDATE=1).
REGRESS_PCT="${REGRESS_PCT:-90}"
SIGN="${SIGN:-digest_sha256}"
SIZE="${SIZE:-8192}"
PREFIX="/bench/dataplane"

# ── binaries ────────────────────────────────────────────────────────────────
FWD="${FWD:-$ROOT/target/release/ndn-fwd}"
IPERF="${IPERF:-$ROOT/target/release/ndn-iperf}"
if [ "${BUILD:-0}" = "1" ] || [ ! -x "$FWD" ] || [ ! -x "$IPERF" ]; then
  echo "[build] cargo build --release -p ndn-fwd --features partitioned-fwd; ndn-iperf"
  cargo build --release -p ndn-fwd --features partitioned-fwd
  cargo build --release -p ndn-tools --bin ndn-iperf
fi
[ -x "$FWD" ]   || { echo "ndn-fwd not found at $FWD" >&2; exit 2; }
[ -x "$IPERF" ] || { echo "ndn-iperf not found at $IPERF" >&2; exit 2; }

# Normalise "X.XX Gbps|Mbps|Kbps" → Gbps float.
to_gbps() {
  awk '{
    v=$1; u=$2;
    if (u ~ /^Gbps/) print v;
    else if (u ~ /^Mbps/) print v/1000;
    else if (u ~ /^Kbps/) print v/1000000;
    else print 0;
  }'
}

run_mode() {
  local mode="$1"
  local tmp; tmp="$(mktemp -d)"
  local sock="$tmp/ndn-fwd.sock"
  local cfg="$tmp/config.toml"

  local engine_validate="" security_block="[security.mgmt]
require_signed_commands = false"
  if [ "$VALIDATE" = "1" ]; then
    # Force the forwarder to verify every Data even on the Local SHM faces,
    # against an accept-all validator (DigestSha256 self-validates).
    engine_validate="require_local_validation = true"
    security_block="[security]
validator_enabled = true
profile = \"default\"

[security.mgmt]
require_signed_commands = false"
  fi
  cat > "$cfg" <<EOF
[engine]
data_plane = "$mode"
workers    = $WORKERS
$engine_validate

[management]
face_socket = "$sock"

$security_block
EOF

  "$FWD" -c "$cfg" >"$tmp/fwd.log" 2>&1 &
  local fwd_pid=$!
  # shellcheck disable=SC2064
  trap "kill $fwd_pid 2>/dev/null || true; wait $fwd_pid 2>/dev/null || true; rm -rf '$tmp'" RETURN

  # Wait for the app socket.
  for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done
  [ -S "$sock" ] || { echo "[$mode] forwarder socket never appeared" >&2; sed 's/^/  fwd| /' "$tmp/fwd.log" >&2; return 3; }

  # Server output must not pollute this function's stdout (it is captured by
  # the caller); send it to a log.
  "$IPERF" server --face-socket "$sock" --prefix "$PREFIX" --size "$SIZE" --quiet \
    >"$tmp/srv.log" 2>&1 &
  local srv_pid=$!
  sleep 1

  local best=0 i out tput g
  for i in $(seq 1 "$ITERS"); do
    out="$("$IPERF" client --face-socket "$sock" --prefix "$PREFIX" \
          --duration "$DURATION" --window "$WINDOW" --sign-mode "$SIGN" 2>"$tmp/cli.err")"
    tput="$(echo "$out" | grep -i 'throughput:' | grep -oE '[0-9]+\.[0-9]+ [A-Za-z]+ps' | head -1)"
    [ -n "$tput" ] || continue
    g="$(echo "$tput" | to_gbps)"
    best="$(awk -v a="$best" -v b="$g" 'BEGIN{ print (b>a)?b:a }')"
  done

  kill "$srv_pid" 2>/dev/null || true
  wait "$srv_pid" 2>/dev/null || true

  awk -v b="$best" 'BEGIN{ exit (b>0)?0:1 }' \
    || { echo "[$mode] no throughput parsed over $ITERS runs" >&2; cat "$tmp/cli.err" >&2; return 4; }
  echo "$best"
}

echo "=== data-plane: SHM + $SIGN, validate=$VALIDATE, workers=$WORKERS, ${DURATION}s × ${ITERS} (peak), window ${WINDOW}, size ${SIZE}B ==="
SHARED_G="$(run_mode shared)"
echo "  shared       : ${SHARED_G} Gbps (peak of ${ITERS})"
PART_G="$(run_mode partitioned)"
echo "  partitioned  : ${PART_G} Gbps (N=1, peak of ${ITERS})"

VERDICT="$(awk -v s="$SHARED_G" -v p="$PART_G" -v pct="$REGRESS_PCT" 'BEGIN{
  if (s<=0) { print "ERR"; exit }
  ratio = 100*p/s;
  printf "%.1f", ratio;
}')"
echo "  partitioned/shared = ${VERDICT}% (floor ${REGRESS_PCT}%)"

awk -v r="$VERDICT" -v pct="$REGRESS_PCT" 'BEGIN{ exit (r+0 >= pct+0) ? 0 : 1 }' || {
  echo "REGRESSION: partitioned(N=1) below ${REGRESS_PCT}% of shared" >&2
  exit 1
}
echo "OK: partitioned(N=1) within ${REGRESS_PCT}% of shared"
