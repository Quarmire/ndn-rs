#!/usr/bin/env bash
# Witness — NDNLPv2 LpReliability recovers loss on a real UDP link.
#
# Finding class: per-face options that are stored/reported but inert. The
#   reliability consolidation (.claude/notes/per-face-option-wiring-triage-
#   2026-05-23.md) moved the LpReliability state machine into the per-face
#   ReliabilityFeature and made the sender pump frame through it when the
#   LpReliability flag is set. `reliability_loss_recovery.rs` pins the contract
#   in-process; THIS witness proves it end-to-end over a real lossy UDP link
#   between two forwarders — the interop dimension the unit test cannot cover.
#
# Topology (loss isolated to the A<->B link; clients use the local Unix socket):
#
#   ndn-ping client ─unix─ ndn-fwd-rel-a ═══UDP (netem loss)═══ ndn-fwd-rel-b ─unix─ ndn-ping server
#                          172.30.0.50                          172.30.0.51        (/rel)
#
# Both forwarders run from the testclient image (bundles ndn-fwd + ndn-ctl +
# ndn-ping + iproute2). cap_add NET_ADMIN lets each shape its own eth0.
#
# What it asserts after enabling LpReliability on both ends of the A<->B face
# and applying ${LOSS}% loss in each direction:
#   1. the ping burst still returns >= ${MIN_RECV}/${PINGS} responses. Without
#      retransmission a round trip survives with prob ~(1-loss)^2 ≈ 49%
#      (~20/40); LpReliability lifts that to ~34/40, so the 28/40 threshold
#      sits cleanly between the two with margin for per-run variance.
#   2. face A's link toward B reports `resent=` > 0 — retransmissions fired.
#
# Reverify: bash testbed/tests/audit/x07_reliability_udp_loss.sh
#   (set DOCKER_HOST / `docker context use` for a remote daemon, as for g04).
# Baseline (the "before" leg): NO_RELIABILITY=1 skips the faces/update enable
#   step, so the same loss leaves the burst at ~(1-loss)^2 survival and the
#   counter at resent=0 — the script then exits 1, proving it tests the
#   reliability mechanism and not mere connectivity.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP (docker not available)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE="docker compose -f testbed/docker-compose.yml --profile reliability"
A="ndn-fwd-rel-a"
B="ndn-fwd-rel-b"
A_IP="172.30.0.50"
B_IP="172.30.0.51"
SOCK="/run/ndn-fwd/ndn-fwd.sock"
LOSS=30          # percent, applied per direction
PINGS=40
MIN_RECV=28      # 70%; between the ~49% no-retransmission rate and the ~85% with it
TRANSCRIPT_DIR="testbed/tests/audit/transcripts"
TXT_FILE="$TRANSCRIPT_DIR/x07_reliability_udp_loss_after.txt"

if ! command -v docker &>/dev/null; then
    echo "SKIP: docker not available"
    exit 2
fi
mkdir -p "$TRANSCRIPT_DIR"

cleanup() {
    echo "--- cleanup ---"
    $COMPOSE exec -T "$A" tc qdisc del dev eth0 root 2>/dev/null || true
    $COMPOSE exec -T "$B" tc qdisc del dev eth0 root 2>/dev/null || true
    $COMPOSE stop "$A" "$B" 2>/dev/null || true
    $COMPOSE rm -f "$A" "$B" 2>/dev/null || true
}
trap cleanup EXIT

ctl_a() { $COMPOSE exec -T "$A" ndn-ctl --socket "$SOCK" "$@"; }
ctl_b() { $COMPOSE exec -T "$B" ndn-ctl --socket "$SOCK" "$@"; }

# ── Bring up the two forwarders ───────────────────────────────────────────────
echo "=== standing up $A and $B ==="
$COMPOSE up -d "$A" "$B"

echo "--- waiting for management sockets ---"
for svc in "$A" "$B"; do
    ok=""
    for _ in $(seq 1 30); do
        if $COMPOSE exec -T "$svc" test -S "$SOCK" 2>/dev/null; then ok=1; break; fi
        sleep 1
    done
    [ -n "$ok" ] || { echo "FAIL: $svc management socket never appeared" >&2; exit 1; }
done

# ── Producer: ndn-ping server on B for /rel ───────────────────────────────────
echo "=== starting ndn-ping server on $B for /rel ==="
$COMPOSE exec -dT "$B" ndn-ping server --face-socket "$SOCK" --no-shm --prefix /rel
sleep 2

# ── Wire A -> B and seed the bidirectional face (lossless warmup) ─────────────
echo "=== creating UDP face A($A_IP) -> B($B_IP):6363 ==="
F_AB=$(ctl_a face create "udp4://$B_IP:6363" | awk '/face-id:/ {print $2}')
[ -n "$F_AB" ] || { echo "FAIL: could not create/parse A->B face" >&2; exit 1; }
echo "    F_AB = $F_AB"
ctl_a route add /rel --face "$F_AB" >/dev/null

echo "--- warmup ping (lossless) to seed B's on-demand return face ---"
ctl_a >/dev/null 2>&1 face list || true
WARMUP_OUT=""
warmup_ok=0
for attempt in 1 2 3; do
    WARMUP_OUT=$($COMPOSE exec -T "$A" ndn-ping client --face-socket "$SOCK" --no-shm \
        --prefix /rel -c 3 -i 200 --lifetime 2500 2>&1 || true)
    printf '%s\n' "$WARMUP_OUT" >&2
    if printf '%s\n' "$WARMUP_OUT" | grep -qE '3 transmitted, [1-3] received'; then
        warmup_ok=1
        break
    fi
    echo "--- warmup attempt $attempt did not produce statistics; retrying ---" >&2
    sleep 1
done
if [ "$warmup_ok" -ne 1 ]; then
    echo "FAIL: warmup ping produced no statistics — baseline path is broken" >&2
    exit 1
fi

# ── Enable LpReliability (flag bit 1) on both ends of the A<->B link ───────────
if [ "${NO_RELIABILITY:-0}" = "1" ]; then
    echo "=== NO_RELIABILITY=1: skipping faces/update — baseline (before) leg ==="
else
    echo "=== enabling LpReliability on F_AB ($A) and B's return face ==="
    ctl_a face update "$F_AB" --flags 0x2 >/dev/null
    F_BA=$(ctl_b face list | awk -v ip="$A_IP" '/^faceid=/{id=$1} $0 ~ ("remote:.*" ip){sub(/faceid=/,"",id); print id; exit}')
    [ -n "$F_BA" ] || { echo "FAIL: could not find B's on-demand face toward $A_IP" >&2; ctl_b face list >&2; exit 1; }
    echo "    F_BA = $F_BA"
    ctl_b face update "$F_BA" --flags 0x2 >/dev/null

    # Confirm the flag is actually set (stored *and* reported).
    if ! ctl_a face list | awk -v f="faceid=$F_AB" '$1==f{p=1} p&&/flags:/{print; exit}' | grep -qi "reliab"; then
        echo "FAIL: F_AB does not report the LpReliability flag after faces/update" >&2
        ctl_a face list >&2
        exit 1
    fi
fi

# ── Inject loss on the A<->B link ─────────────────────────────────────────────
echo "=== applying ${LOSS}% netem loss on both eth0 (A and B) ==="
$COMPOSE exec -T "$A" tc qdisc add dev eth0 root netem loss "${LOSS}%"
$COMPOSE exec -T "$B" tc qdisc add dev eth0 root netem loss "${LOSS}%"

# ── Measured burst under loss, reliability ON ─────────────────────────────────
echo "=== ${PINGS} pings under loss (reliability ON) ==="
PING_OUT=$($COMPOSE exec -T "$A" ndn-ping client --face-socket "$SOCK" --no-shm \
            --prefix /rel -c "$PINGS" -i 150 --lifetime 4000 2>&1 || true)
echo "$PING_OUT"

RECV=$(echo "$PING_OUT" | awk -F'[, ]+' '/transmitted/ {print $3}')
RECV=${RECV:-0}

RESENT_LINE=$(ctl_a face list | awk -v f="faceid=$F_AB" '$1==f{p=1} p&&/reliability:/{print; exit}')
RESENT=$(echo "$RESENT_LINE" | grep -o 'resent=[0-9]*' | cut -d= -f2)
RESENT=${RESENT:-0}

# ── Transcript ────────────────────────────────────────────────────────────────
{
    echo "x07 reliability over lossy UDP — $(date -u +%FT%TZ)"
    echo "loss=${LOSS}% per direction  pings=${PINGS}  min_recv=${MIN_RECV}"
    echo
    echo "$PING_OUT"
    echo
    echo "A face F_AB=$F_AB reliability line: $RESENT_LINE"
} >"$TXT_FILE"

# ── Verdict ───────────────────────────────────────────────────────────────────
echo "=== received=$RECV/$PINGS  resent=$RESENT ==="
fail=0
if [ "$RECV" -lt "$MIN_RECV" ]; then
    echo "FAIL: only $RECV/$PINGS responses under ${LOSS}% loss (need >= $MIN_RECV) — reliability did not recover" >&2
    fail=1
fi
if [ "$RESENT" -lt 1 ]; then
    echo "FAIL: F_AB reports resent=$RESENT — no LP retransmissions fired" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: LpReliability recovered ${LOSS}% loss over UDP ($RECV/$PINGS, resent=$RESENT)"
fi
exit "$fail"
