#!/usr/bin/env bash
# Witness test for audit findings D.02 / I.11 — `/localhop` scope
# unenforced.
#
# Finding:     testbed/EXPECTED_FAILURES.md § D.02
# Severity:    MAJOR
# Spec ref:    NFD `daemon/fw/scope-prefix.hpp:46-58` (LOCALHOP);
#              `daemon/fw/algorithm.cpp:45-49` wouldViolateScope rule.
# Witnesses:
#   Part 1 — RUST-UNIT (localhop scope helper and decode-stage behavior)
#   Part 2 — INTEROP-SCRIPT: face-scope split test via testbed
#
#     Setup: ndn-fwd has a route /localhop and the witness generates a unique
#       probe prefix per run to avoid stale Content Store or producer state.
#
#     Test A — Remote face (TCP from interop container, FaceScope::NonLocal):
#       ndnpeek via TCP to ndn-fwd:6363 → /localhop/<unique-probe>
#       Expected: timeout (ndn-fwd drops at decode stage, scope violation)
#
#     Test B — Local face (Unix socket from testclient, FaceScope::Local):
#       ndn-peek via /run/ndn-fwd/ndn-fwd.sock → /localhop/<unique-probe>
#       Expected: Data returned from NFD's CS (scope NOT violated)
#
#     Unix socket faces are classified FaceScope::Local in ndn-rs
#     (ndn-transport/src/face.rs: FaceKind::Unix → scope() = Local).
#     TCP faces are FaceScope::NonLocal.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
interop_skipped=0

# ── Part 1: RUST-UNIT ─────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

if cargo test -p ndn-engine --lib --quiet d02_ \
        >/tmp/d02_witness.log 2>&1; then
    echo "ok: RUST-UNIT — /localhop scope behavior"
else
    echo "FAIL: RUST-UNIT"
    cat /tmp/d02_witness.log
    fail=1
fi

# ── Part 2: INTEROP-SCRIPT ────────────────────────────────────────────────
#
# Test design: serve a unique /localhop/d02-* prefix directly from ndn-fwd via a
# local producer (ndn-put from testclient unix socket).  This avoids
# forwarding the /localhop Interest to NFD where NFD's own scope check
# would block it on the non-local UDP ingress face.
#
#   Test A — remote TCP face (FaceScope::NonLocal):
#     ndnpeek from interop via TCP:6364 → ndn-fwd decode stage drops at
#     ingress because /localhop on non-local face is a scope violation.
#
#   Test B — local unix face (FaceScope::Local):
#     ndn-put on ndn-fwd serves /localhop/d02-probe as a local producer.
#     ndn-peek from testclient via unix socket → ndn-fwd decode stage
#     passes (local face) → FIB → ndn-put → Data returned.
COMPOSE="docker compose -f testbed/docker-compose.yml"
if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not available — live interop not run" >&2
    interop_skipped=1
else
    PS_OUT=$($COMPOSE ps testclient 2>/dev/null || true)
    if [[ "$PS_OUT" != *"running"* && "$PS_OUT" != *"Up"* ]]; then
        echo "SKIP: testclient container not running — start testbed first" >&2
        interop_skipped=1
    fi
fi

if [ "$interop_skipped" -eq 0 ]; then
    probe_name="/localhop/d02-probe-$(date +%s)-$$"

    # Prepare probe content file in testclient
    $COMPOSE exec -T testclient bash -c "echo -n LocalhopProbe > /tmp/d02_probe.txt" 2>/dev/null || true

    # Test A: Remote face (TCP from interop, FaceScope::NonLocal) — scope violation, must DROP
    # No producer needed; ndn-fwd drops the Interest before FIB lookup.
    REMOTE=$($COMPOSE exec -T interop bash -c \
        "NDN_CLIENT_TRANSPORT=tcp4://172.30.0.10:6364 \
         ndnpeek -P -w 2000 '$probe_name' 2>&1") || REMOTE="TIMEOUT"
    remote_lc=$(printf '%s' "$REMOTE" | tr '[:upper:]' '[:lower:]')
    if [ -z "$REMOTE" ] || [[ "$remote_lc" == *"timeout"* || "$remote_lc" == *"error"* ]]; then
        echo "ok: INTEROP Test-A — /localhop from remote TCP face dropped (scope enforced)"
    else
        echo "FAIL: INTEROP Test-A — /localhop from remote face was NOT dropped"
        echo "  output: $REMOTE"
        fail=1
    fi

    # Test B: Local face (unix socket from testclient, FaceScope::Local) — must NOT be dropped
    # ndn-put serves as a local producer on ndn-fwd; ndn-peek uses CanBePrefix
    # because ndn-put publishes at /localhop/d02-*/v=N/seg=0. Keep the
    # producer and fetch in one shell so we can wait for the route registration
    # instead of sleeping and racing the local producer startup.
    LOCAL=$($COMPOSE exec -T testclient bash -c "
        set -euo pipefail
        probe='$probe_name'
        ndn-put --no-shm --face-socket /run/ndn-fwd/ndn-fwd.sock \
            --timeout 10000 \"\$probe\" /tmp/d02_probe.txt \
            >/tmp/d02_put.out 2>/tmp/d02_put.err &
        put_pid=\$!
        cleanup() { kill \"\$put_pid\" 2>/dev/null || true; }
        trap cleanup EXIT

        route_seen=0
        for _ in \$(seq 1 30); do
            rib=\$(ndn-ctl --socket /run/ndn-fwd/ndn-fwd.sock route rib-list 2>/tmp/d02_rib.err || true)
            if [[ \"\$rib\" == *\"\$probe\"* ]]; then
                route_seen=1
                break
            fi
            sleep 0.2
        done

        if [ \"\$route_seen\" -ne 1 ]; then
            echo 'producer route not observed before local fetch'
            cat /tmp/d02_put.err 2>/dev/null || true
            cat /tmp/d02_rib.err 2>/dev/null || true
            exit 1
        fi

        ndn-peek --no-shm --can-be-prefix \
            --face-socket /run/ndn-fwd/ndn-fwd.sock \
            --lifetime 5000 \"\$probe\" 2>&1
    ") || LOCAL="TIMEOUT"
    if [[ "$LOCAL" == *"LocalhopProbe"* ]]; then
        echo "ok: INTEROP Test-B — /localhop from local unix-socket face accepted"
    else
        echo "FAIL: INTEROP Test-B — /localhop from local unix-socket face was dropped"
        echo "  output: $LOCAL"
        fail=1
    fi

    printf "Probe: %s\nRemote: %s\nLocal: %s\n" "$probe_name" "$REMOTE" "$LOCAL" >>/tmp/d02_witness.log
fi

if [ "$fail" -ne 0 ]; then
    echo
    echo "=== D.02 / I.11 FAIL ==="
    cat /tmp/d02_witness.log
    exit 1
elif [ "$interop_skipped" -ne 0 ]; then
    echo
    echo "=== D.02 / I.11 PARTIAL — Rust unit passed; live interop skipped ==="
    exit 2
else
    echo
    echo "=== D.02 / I.11 RESOLVED — /localhop scope: remote face drops, local face passes (RUST-UNIT + INTEROP) ==="
    exit 0
fi
