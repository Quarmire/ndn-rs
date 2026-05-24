#!/usr/bin/env bash
# Multi-flow wire-face throughput benchmark.
#
# Stresses the UDP *listener* RX path (the inbound wire path) under N
# concurrent flows from distinct source endpoints — the workload that
# exposes single-core RX bottlenecks and benefits from SO_REUSEPORT sharding.
#
# Topology (all on loopback, one machine):
#
#     consumer fwd C_0  --udp-->\
#     consumer fwd C_1  --udp--> producer fwd P (UDP listener :$PPORT)
#     ...                      /   + N ndn-iperf servers (/iperf/i)
#     consumer fwd C_{N-1} ---/
#
# Each C_i dials P from its own ephemeral UDP src port (a distinct 4-tuple,
# so the kernel can hash it onto a different RX socket), routes /iperf -> P,
# and runs one ndn-iperf client fetching /iperf/i. We sum the N clients'
# goodput = aggregate wire throughput the forwarder's listener sustains.
#
# Env: FLOWS (default 4), DURATION (10), WINDOW (256), SIZE (8192),
#      PPORT (18000), NDN_FWD, NDN_IPERF (paths to release binaries).
#
# Usage:  FLOWS=8 bash testbed/bench/multiflow_wire.sh
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

FLOWS="${FLOWS:-4}"
DURATION="${DURATION:-10}"
WINDOW="${WINDOW:-256}"
SIZE="${SIZE:-8192}"
PPORT="${PPORT:-18000}"
NDN_FWD="${NDN_FWD:-./target/release/ndn-fwd}"
NDN_IPERF="${NDN_IPERF:-./target/release/ndn-iperf}"
DIR=/tmp/mfw
PIDS=()

cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT

[ -x "$NDN_FWD" ] || { echo "missing $NDN_FWD (cargo build --release -p ndn-fwd)"; exit 1; }
[ -x "$NDN_IPERF" ] || { echo "missing $NDN_IPERF (cargo build --release -p ndn-tools --bin ndn-iperf)"; exit 1; }

rm -rf "$DIR"; mkdir -p "$DIR"

# ---- producer forwarder P ----
cat > "$DIR/p.toml" <<EOF
[management]
face_socket = "$DIR/p.sock"
[security.mgmt]
require_signed_commands = false
[log]
filter = "error"
[face_system.udp]
rx_sockets = ${RX_SOCKETS:-1}
[[face]]
kind = "udp"
bind = "127.0.0.1:$PPORT"
EOF
$NDN_FWD -c "$DIR/p.toml" >"$DIR/p.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 80); do [ -S "$DIR/p.sock" ] && break; sleep 0.1; done
[ -S "$DIR/p.sock" ] || { echo "producer failed:"; tail -5 "$DIR/p.log"; exit 1; }

# ---- N iperf servers on P (one prefix each) ----
for i in $(seq 0 $((FLOWS-1))); do
  $NDN_IPERF server --face-socket "$DIR/p.sock" --no-shm --prefix "/iperf/$i" --size "$SIZE" --quiet >"$DIR/srv$i.log" 2>&1 & PIDS+=($!)
done

# ---- N consumer forwarders, each dialing P over UDP ----
for i in $(seq 0 $((FLOWS-1))); do
  cat > "$DIR/c$i.toml" <<EOF
[management]
face_socket = "$DIR/c$i.sock"
[security.mgmt]
require_signed_commands = false
[log]
filter = "error"
[[face]]
kind = "udp"
remote = "127.0.0.1:$PPORT"
[[route]]
prefix = "/iperf"
face = 0
EOF
  $NDN_FWD -c "$DIR/c$i.toml" >"$DIR/c$i.log" 2>&1 & PIDS+=($!)
done
for i in $(seq 0 $((FLOWS-1))); do
  for t in $(seq 1 80); do [ -S "$DIR/c$i.sock" ] && break; sleep 0.1; done
done
sleep 2

echo "=== multi-flow wire: $FLOWS flows, size=$SIZE win=$WINDOW dur=${DURATION}s ==="
# ---- N parallel iperf clients ----
for i in $(seq 0 $((FLOWS-1))); do
  ( $NDN_IPERF client --face-socket "$DIR/c$i.sock" --no-shm --prefix "/iperf/$i" --duration "$DURATION" --window "$WINDOW" 2>&1 \
      | grep -iE "throughput:" | tail -1 > "$DIR/res$i.txt" ) & PIDS+=($!)
done
wait $(jobs -p | tail -n "$FLOWS") 2>/dev/null
sleep 0.5

# ---- aggregate (normalize to Mbps) ----
total=0
for i in $(seq 0 $((FLOWS-1))); do
  line=$(cat "$DIR/res$i.txt" 2>/dev/null)
  val=$(echo "$line" | grep -oE '[0-9.]+ *[GMK]?bps' | head -1)
  num=$(echo "$val" | grep -oE '[0-9.]+'); unit=$(echo "$val" | grep -oE '[GMK]?bps')
  case "$unit" in
    Gbps) mbps=$(echo "$num * 1000" | bc -l) ;;
    Mbps) mbps=$num ;;
    Kbps) mbps=$(echo "$num / 1000" | bc -l) ;;
    *) mbps=0 ;;
  esac
  printf "  flow %d: %s\n" "$i" "${val:-<none>}"
  total=$(echo "$total + ${mbps:-0}" | bc -l)
done
printf "=== AGGREGATE: %.0f Mbps (%.2f Gbps) across %d flows ===\n" "$total" "$(echo "$total/1000" | bc -l)" "$FLOWS"
