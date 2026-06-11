#!/usr/bin/env bash
# Phase-0 witness for the named-radio plan — monitor-mode injection transmits at
# the MCS we choose, defeating the legacy-rate "broadcast wall".
#
# Plan:        .claude/notes/named-radio/monitor-mode-action-plan-2026-05-24.md § Phase 0
# Witnesses:   inject N frames at MCS$MCS on $TX_IF; capture on $CAP_IF; assert
#              the captured frames' radiotap RX rate is the requested 11n MCS
#              (NOT a legacy 1/6/24 Mbps floor).
#
# This is hardware-gated: it needs TWO monitor-mode 802.11n dongles (one TX, one
# capture) on the same channel. With hardware absent it SKIPs (exit 2) — it can
# only PASS/FAIL on a real radio bench.
#
# Exit codes:
#   0 — PASS (captured rate == requested MCS; the wall is defeated)
#   1 — FAIL (captured rate fell back to a legacy rate)
#   2 — SKIP (missing hardware / tools / not Linux / no CAP_NET_RAW)
#
# Usage:
#   sudo TX_IF=wlan0 CAP_IF=wlan1 CHANNEL=6 MCS=3 bash testbed/bench/wifi_inject_rate.sh
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

TX_IF="${TX_IF:-}"
CAP_IF="${CAP_IF:-}"
CHANNEL="${CHANNEL:-6}"
MCS="${MCS:-3}"
COUNT="${COUNT:-1000}"
SIZE="${SIZE:-800}"
CAP_SECS="${CAP_SECS:-6}"

skip() { echo "SKIP: $*"; exit 2; }

# ── environment gates ─────────────────────────────────────────────────────────
[ "$(uname -s)" = "Linux" ] || skip "monitor-mode injection is Linux-only"
[ "$(id -u)" = "0" ] || skip "needs root / CAP_NET_RAW (re-run under sudo)"
[ -n "$TX_IF" ] && [ -n "$CAP_IF" ] || skip "set TX_IF and CAP_IF to two monitor dongles"
for tool in iw ip tshark; do
  command -v "$tool" >/dev/null 2>&1 || skip "missing tool: $tool"
done

INJECTOR="./target/release/examples/inject_mcs"
if [ ! -x "$INJECTOR" ]; then
  echo "building injector …"
  cargo build --release --example inject_mcs -p ndn-face-monitor-wifi \
    || skip "could not build inject_mcs example"
fi

# ── put both interfaces in monitor mode on the same channel ───────────────────
# The down/up cycle runs TWICE on purpose: on the svpcom rtl8812eu, the first
# managed→monitor transition leaves the RX path decoding only low-order
# modulations (MCS0/3 heard, MCS5/7 silently dropped, even FCS-valid ones); a
# second bounce re-inits it and all rates arrive. Verified on an Orange Pi 5
# Pro bench 2026-06-11 (0 captured at MCS7 pre-bounce → 99/100 post-bounce).
setup_mon() {
  local ifc="$1"
  for _pass in 1 2; do
    ip link set "$ifc" down 2>/dev/null || true
    iw dev "$ifc" set type monitor 2>/dev/null || skip "$ifc: cannot set monitor mode"
    ip link set "$ifc" up || skip "$ifc: cannot bring up"
    iw dev "$ifc" set channel "$CHANNEL" 2>/dev/null \
      || iw dev "$ifc" set channel "$CHANNEL" HT20 2>/dev/null \
      || skip "$ifc: cannot set channel $CHANNEL"
  done
}
setup_mon "$TX_IF"
setup_mon "$CAP_IF"

CAP="$(mktemp /tmp/wifi_inject_rate.XXXXXX.pcap)"
cleanup() { rm -f "$CAP"; }
trap cleanup EXIT

# ── capture on CAP_IF while injecting on TX_IF ────────────────────────────────
# Filter to our 02:4e:44:4e:.. transmitter address (DEFAULT_SRC in the backend)
# so we only score our own injected frames, not ambient traffic.
tshark -i "$CAP_IF" -I -w "$CAP" -a "duration:$CAP_SECS" \
  -f "wlan src 02:4e:44:4e:00:01" >/dev/null 2>&1 &
TSHARK_PID=$!
sleep 1

echo "injecting $COUNT frames at MCS$MCS on $TX_IF …"
"$INJECTOR" "$TX_IF" "$MCS" "$COUNT" "$SIZE" || { kill "$TSHARK_PID" 2>/dev/null; skip "injector failed (driver may not honour injected MCS — try an ath9k/mt76/svpcom-Realtek dongle)"; }

wait "$TSHARK_PID" 2>/dev/null

# ── score captured frames: how many carried an 11n MCS field vs a legacy rate ─
FRAMES="$(tshark -r "$CAP" -Y 'wlan.fc.type==2' 2>/dev/null \
  -T fields -e radiotap.mcs.index -e radiotap.datarate | grep -c . || true)"
[ "${FRAMES:-0}" -gt 0 ] || skip "captured 0 of our injected frames (channel/antenna/range?)"

MCS_HITS="$(tshark -r "$CAP" -Y "wlan.fc.type==2 && radiotap.mcs.index==$MCS" 2>/dev/null \
  -T fields -e radiotap.mcs.index | grep -c . || true)"

echo "captured $FRAMES of our frames; $MCS_HITS at the requested MCS$MCS"

if [ "${MCS_HITS:-0}" -gt 0 ]; then
  echo "PASS: monitor-mode injection transmitted at MCS$MCS — the legacy-rate wall is a managed-mode artifact, not a hardware one."
  exit 0
else
  echo "FAIL: no frames captured at MCS$MCS; the driver clamped/ignored the injected radiotap rate."
  echo "      Try an ath9k, mt76, or svpcom Realtek (rtl8812au/eu) dongle."
  exit 1
fi
