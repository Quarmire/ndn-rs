#!/usr/bin/env bash
# Witness — raw-QUIC forwarder-to-forwarder face carries NDN traffic.
#
# Finding:     QUIC face (crates/ndn-face-quic) operator wiring; design at
#              .claude/notes/face-scope-and-transports/quic-face-sketch-2026-05-23.md
# Severity:    feature witness (functional)
# Witnesses:   Two real ndn-fwd processes — B dials A over a cert-pinned QUIC
#              face; a producer on A serves /quic-witness; a route on B sends
#              that prefix over the QUIC face; a consumer on B fetches it and
#              the Data round-trips over the inter-forwarder QUIC link.
#
# Self-contained: builds the binaries and spawns two forwarders locally over
# Unix mgmt sockets — no Docker. Reverify recipe: INTEGRATION (local processes).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP (cargo/build unavailable)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not available" >&2; exit 2; }

echo "→ building ndn-fwd + ndn-tools (quic feature is default-on)"
if ! cargo build --quiet -p ndn-fwd -p ndn-tools >/tmp/quic01-build.log 2>&1; then
    echo "SKIP: build failed (see /tmp/quic01-build.log)" >&2
    exit 2
fi

FWD="$REPO_ROOT/target/debug/ndn-fwd"
PUT="$REPO_ROOT/target/debug/ndn-put"
PEEK="$REPO_ROOT/target/debug/ndn-peek"
CTL="$REPO_ROOT/target/debug/ndn-ctl"
for b in "$FWD" "$PUT" "$PEEK" "$CTL"; do
    [ -x "$b" ] || { echo "SKIP: missing binary $b" >&2; exit 2; }
done

TMP="$(mktemp -d /tmp/quic01.XXXXXX)"
A_SOCK="$TMP/a.sock"; B_SOCK="$TMP/b.sock"; A_LOG="$TMP/a.log"; B_LOG="$TMP/b.log"
PORT=16367
PREFIX="/quic-witness/obj"

cleanup() { [ -n "${A_PID:-}" ] && kill "$A_PID" 2>/dev/null || true
            [ -n "${B_PID:-}" ] && kill "$B_PID" 2>/dev/null || true
            [ -n "${PUT_PID:-}" ] && kill "$PUT_PID" 2>/dev/null || true
            rm -rf "$TMP"; }
trap cleanup EXIT

cat > "$TMP/a.toml" <<EOF
[security]
profile = "disabled"
[security.mgmt]
require_signed_commands = false
[listeners.quic]
enabled = true
listen = "127.0.0.1:$PORT"
[management]
face_socket = "$A_SOCK"
[logging]
level = "info"
EOF

"$FWD" -c "$TMP/a.toml" >"$A_LOG" 2>&1 & A_PID=$!
for _ in $(seq 1 50); do grep -qE 'cert_sha256=[0-9a-f]{64}' "$A_LOG" && break; sleep 0.2; done
HASH=$(grep -oE 'cert_sha256=[0-9a-f]{64}' "$A_LOG" | head -1 | cut -d= -f2)
[ -n "$HASH" ] || { echo "FAIL: forwarder A logged no QUIC leaf hash" >&2; tail -5 "$A_LOG" >&2; exit 1; }

cat > "$TMP/b.toml" <<EOF
[security]
profile = "disabled"
[security.mgmt]
require_signed_commands = false
[[face]]
kind = "quic"
remote = "quic://127.0.0.1:$PORT"
cert_sha256 = "$HASH"
[management]
face_socket = "$B_SOCK"
[logging]
level = "info"
EOF

"$FWD" -c "$TMP/b.toml" >"$B_LOG" 2>&1 & B_PID=$!
for _ in $(seq 1 50); do grep -q 'QUIC dial face connected' "$B_LOG" && break; sleep 0.2; done
FACE=$(grep -oE 'QUIC dial face connected.*face#[0-9]+' "$B_LOG" | grep -oE '[0-9]+$' | head -1)
[ -n "$FACE" ] || { echo "FAIL: forwarder B did not connect the QUIC dial face" >&2; tail -8 "$B_LOG" >&2; exit 1; }

printf 'QUIC-WITNESS-OK' > "$TMP/content.txt"
"$PUT" --face-socket "$A_SOCK" --no-shm "$PREFIX" "$TMP/content.txt" >"$TMP/put.log" 2>&1 & PUT_PID=$!
for _ in $(seq 1 25); do grep -qiE 'registered|served|waiting' "$TMP/put.log" && break; sleep 0.2; done

"$CTL" --socket "$B_SOCK" route add "$PREFIX" --face "$FACE" >/dev/null 2>&1 || true

OUT=$("$PEEK" --face-socket "$B_SOCK" --no-shm --can-be-prefix --lifetime 5000 "$PREFIX" 2>&1 || true)

if echo "$OUT" | grep -q 'QUIC-WITNESS-OK'; then
    grep -q 'accepted connection' "$A_LOG" \
        && echo "PASS: Data round-tripped over the QUIC inter-forwarder face (A accepted the connection)"
    exit 0
else
    echo "FAIL: content did not round-trip over the QUIC face" >&2
    echo "  peek: $OUT" >&2
    echo "  --- A log tail ---" >&2; tail -6 "$A_LOG" >&2
    echo "  --- B log tail ---" >&2; tail -6 "$B_LOG" >&2
    exit 1
fi
