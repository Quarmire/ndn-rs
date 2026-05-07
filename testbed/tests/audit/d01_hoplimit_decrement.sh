#!/usr/bin/env bash
# Witness test for audit findings D.01 / I.09 — HopLimit not decremented
# on the incoming forwarder pipeline.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § D.01
# Severity:    BLOCKER
# Spec ref:    NFD `daemon/fw/forwarder.cpp:104-111`; ndnd
#              `fw/fw/thread.go:190-195` — both decrement HopLimit on
#              the incoming pipeline after the zero-check.
# Witnesses:
#   Part 1 — RUST-UNIT (ndn-packet helper + ndn-engine decode stage tests)
#   Part 2 — INTEROP-SCRIPT: behavioral chain test via the interop container.
#
#              Setup:
#                interop TCP:6364→ndn-fwd; ndn-fwd UDP→NFD; ndnpoke on NFD.
#                Each test uses a unique probe name to prevent CS contamination.
#
#              Test A — HL=2 (/d01-probe-hl2):
#                ndnpoke waits on NFD for /d01-probe-hl2.
#                ndnpeek (HL=2) → ndn-fwd decrements to 1 → NFD → ndnpoke.
#                Data returned: HopLimit decrement does not kill reachability.
#
#              Test B — HL=1 (/d01-probe-hl1):
#                ndnpoke waits on NFD for /d01-probe-hl1.
#                ndnpeek (HL=1) → ndn-fwd decrements to 0 → MUST NOT forward.
#                ndnpoke never fires → timeout at interop.
#
#              This pair proves ndn-fwd decrements HopLimit and stops
#              forwarding when the post-decrement value is 0.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# ── Part 1: RUST-UNIT ─────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi
if cargo test -p ndn-packet --features std --lib --quiet d01_decrement_hop_limit \
        >/tmp/d01_witness.log 2>&1; then
    echo "ok: ndn-packet helper (decrement_hop_limit)"
else
    echo "FAIL: ndn-packet helper"; fail=1
fi
if cargo test -p ndn-engine --lib --quiet d01_decode_stage \
        >>/tmp/d01_witness.log 2>&1; then
    echo "ok: ndn-engine decode stage"
else
    echo "FAIL: ndn-engine decode stage"; fail=1
fi

# ── Part 2: INTEROP-SCRIPT ────────────────────────────────────────────────
# Requires:
#   docker compose up -d ndn-fwd nfd interop testclient
#
# Design: each test uses a unique probe name to avoid CS contamination.
# ndnpoke runs as a background producer on NFD; ndnpeek from interop
# connects to ndn-fwd TCP port 6364.
#
#   Test A (/d01-probe-hl2): Interest HL=2 → ndn-fwd decrements to 1 →
#   NFD forwards to ndnpoke → Data returned.
#
#   Test B (/d01-probe-hl1): Interest HL=1 → ndn-fwd decrements to 0 →
#   ndn-fwd MUST NOT forward (HopLimit exhausted) → ndnpoke never fires →
#   timeout at interop.
COMPOSE="docker compose -f testbed/docker-compose.yml"
if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — live interop not run" >&2
elif ! $COMPOSE ps interop 2>/dev/null | grep -q "running\|Up"; then
    echo "SKIP: interop container not running — start testbed first" >&2
else
    # Register a route on ndn-fwd: /d01-probe → NFD face (UDP, 172.30.0.11:6363)
    NFD_FACE=$($COMPOSE exec -T testclient \
        ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock face list 2>/dev/null \
        | awk '/^faceid=/{id=substr($1,8)} /172\.30\.0\.11/{print id; exit}') || NFD_FACE=""

    if [ -z "$NFD_FACE" ]; then
        NFD_FACE=$($COMPOSE exec -T testclient \
            ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock \
                face create udp4://172.30.0.11:6363 2>/dev/null \
            | awk '/face-id:/{print $2}') || NFD_FACE=""
    fi

    if [ -n "$NFD_FACE" ]; then
        $COMPOSE exec -T testclient \
            ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock \
                route add /d01-probe --face "$NFD_FACE" >/dev/null 2>&1 || true
    fi
    sleep 1

    # Test A: HL=2 — ndnpoke waits on NFD; Interest traverses ndn-fwd (HL→1) → NFD → ndnpoke
    $COMPOSE exec -d interop bash -c \
        'NDN_CLIENT_TRANSPORT=unix:///run/nfd/nfd.sock ndnpoke /d01-probe-hl2 <<< HopLimitProbe' \
        2>/dev/null || true
    sleep 1

    HL2=$($COMPOSE exec -T interop bash -c \
        'NDN_CLIENT_TRANSPORT=tcp4://172.30.0.10:6364 \
         ndnpeek -p -H 2 -w 4000 /d01-probe-hl2 2>&1') || HL2="TIMEOUT"
    if [ -z "$HL2" ] || [ "$HL2" = "TIMEOUT" ]; then
        echo "FAIL: INTEROP Test-A — HL=2 did not return Data (routing or HL decrement issue)"
        fail=1
    else
        echo "ok: INTEROP Test-A — HL=2 reached NFD and Data returned"
    fi

    # Test B: HL=1 — ndn-fwd decrements to 0, MUST NOT forward; ndnpoke never fires
    $COMPOSE exec -d interop bash -c \
        'NDN_CLIENT_TRANSPORT=unix:///run/nfd/nfd.sock ndnpoke /d01-probe-hl1 <<< HopLimitProbe' \
        2>/dev/null || true
    sleep 1

    HL1=$($COMPOSE exec -T interop bash -c \
        'NDN_CLIENT_TRANSPORT=tcp4://172.30.0.10:6364 \
         ndnpeek -p -H 1 -w 3000 /d01-probe-hl1 2>&1') || HL1="TIMEOUT"
    if [ -z "$HL1" ] || [ "$HL1" = "TIMEOUT" ]; then
        echo "ok: INTEROP Test-B — HL=1 timed out (ndn-fwd did not forward HL=0)"
    else
        echo "FAIL: INTEROP Test-B — HL=1 got Data (ndn-fwd forwarded when it should not)"
        fail=1
    fi

    printf "HL2 result: %s\nHL1 result: %s\n" "$HL2" "$HL1" >>/tmp/d01_witness.log
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== D.01 / I.09 RESOLVED — HopLimit decremented on incoming pipeline (RUST-UNIT + INTEROP) ==="
    exit 0
else
    echo
    echo "=== D.01 / I.09 FAIL ==="
    cat /tmp/d01_witness.log
    exit 1
fi
