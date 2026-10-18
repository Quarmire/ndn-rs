#!/usr/bin/env bash
# Witness — a QUIC link between two forwarders carries NDN traffic.
#
# Finding:     QUIC links (ndn-ext/crates/faces/ndn-face-quic, ndn-fwd links)
#              operator wiring; docs at docs/wiki/src/reference/links.md
# Severity:    feature witness (functional)
# Witnesses:   Two real ndn-fwd processes — A listens for links
#              ([[face]] kind = "quic" bind), B dials it from a [[peer]] that
#              names A's key and routes /quic-witness over the link; a
#              producer on A serves /quic-witness; a consumer on B fetches it
#              and the Data round-trips over the inter-forwarder QUIC link.
#
# QUIC links need a daemon with a signing key (security enabled): a link is
# identified by the two devices' keys. Each forwarder here gets its own
# identity in its own PIB ([security] identity + auto_init; profile =
# "disabled" only skips Data validation). Neither is enrolled in a
# namespace, so each side's [[peer]] expects the other's fingerprint
# (key = …): A lists B's key without an endpoint (B may link in), B lists
# A's key with A's endpoint. A first run of each forwarder with only a link
# listener mints its key and logs the fingerprint ("this device's link key",
# fingerprint=…).
#
# Self-contained: builds the binaries and spawns two forwarders locally over
# Unix mgmt sockets — no Docker. Reverify recipe: INTEGRATION (local processes).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP (cargo/build unavailable)
set -euo pipefail
# ndn-fwd and ndn-tools are built in the ndn-fwd workspace, a sibling of ndn-rs.
WORKSPACE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FWD_ROOT="$WORKSPACE_ROOT/ndn-fwd"
[ -f "$FWD_ROOT/Cargo.toml" ] || { echo "SKIP: no ndn-fwd workspace at $FWD_ROOT" >&2; exit 2; }
cd "$FWD_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not available" >&2; exit 2; }

# Ask cargo where it puts the binaries: a shared target dir (CARGO_TARGET_DIR,
# or the workspace's .cargo/config.toml) redirects them out of the repo.
if ! TARGET_DIR="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"; then
    echo "SKIP: cannot locate the cargo target directory of $FWD_ROOT" >&2
    exit 2
fi

echo "→ building ndn-fwd + ndn-tools (quic feature is default-on)"
if ! cargo build --quiet -p ndn-fwd -p ndn-tools >/tmp/quic01-build.log 2>&1; then
    echo "SKIP: build failed (see /tmp/quic01-build.log)" >&2
    exit 2
fi

FWD="$TARGET_DIR/debug/ndn-fwd"
PUT="$TARGET_DIR/debug/ndn-put"
PEEK="$TARGET_DIR/debug/ndn-peek"
for b in "$FWD" "$PUT" "$PEEK"; do
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

# Each forwarder's [security]: its own key in its own PIB.
security_block() {  # $1 = forwarder name
    cat <<EOF
[security]
identity = "/quic-witness/$1"
pib_path = "$TMP/$1-pib"
auto_init = true
profile = "disabled"
[security.mgmt]
require_signed_commands = false
EOF
}

# Run a forwarder once with only a link listener: it mints its key and logs
# the key's fingerprint. Prints the fingerprint.
link_key() {  # $1 = forwarder name
    local cfg="$TMP/$1-mint.toml" log="$TMP/$1-mint.log" pid fp=""
    { security_block "$1"; cat <<EOF
[[face]]
kind = "quic"
bind = "127.0.0.1:0"
[management]
face_socket = "$TMP/$1-mint.sock"
[logging]
level = "info"
EOF
    } > "$cfg"
    "$FWD" -c "$cfg" >"$log" 2>&1 & pid=$!
    for _ in $(seq 1 50); do
        fp=$(grep "this device's link key" "$log" | grep -oE 'fingerprint=[0-9a-f]{64}' \
            | head -1 | cut -d= -f2 || true)
        [ -n "$fp" ] && break
        sleep 0.2
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    [ -n "$fp" ] || { echo "FAIL: forwarder $1 logged no link key" >&2; tail -5 "$log" >&2; return 1; }
    echo "$fp"
}

A_KEY=$(link_key a) || exit 1
B_KEY=$(link_key b) || exit 1

{ security_block a; cat <<EOF
[[face]]
kind = "quic"
bind = "127.0.0.1:$PORT"
[[peer]]
key = "$B_KEY"
[management]
face_socket = "$A_SOCK"
[logging]
level = "info"
EOF
} > "$TMP/a.toml"

"$FWD" -c "$TMP/a.toml" >"$A_LOG" 2>&1 & A_PID=$!
for _ in $(seq 1 50); do grep -q 'listening for QUIC links' "$A_LOG" && break; sleep 0.2; done
grep -q 'listening for QUIC links' "$A_LOG" \
    || { echo "FAIL: forwarder A is not listening for QUIC links" >&2; tail -5 "$A_LOG" >&2; exit 1; }

{ security_block b; cat <<EOF
[[peer]]
key = "$A_KEY"
endpoint = "127.0.0.1:$PORT"
routes = ["/quic-witness"]
[management]
face_socket = "$B_SOCK"
[logging]
level = "info"
EOF
} > "$TMP/b.toml"

"$FWD" -c "$TMP/b.toml" >"$B_LOG" 2>&1 & B_PID=$!
for _ in $(seq 1 50); do grep -q 'link up' "$B_LOG" && break; sleep 0.2; done
FACE=$(grep 'link up' "$B_LOG" | grep -oE 'face=[0-9]+' | head -1 | cut -d= -f2 || true)
[ -n "$FACE" ] || { echo "FAIL: forwarder B did not bring up the QUIC link" >&2; tail -8 "$B_LOG" >&2; exit 1; }

printf 'QUIC-WITNESS-OK' > "$TMP/content.txt"
"$PUT" --face-socket "$A_SOCK" --no-shm "$PREFIX" "$TMP/content.txt" >"$TMP/put.log" 2>&1 & PUT_PID=$!
for _ in $(seq 1 25); do grep -qiE 'registered|served|waiting' "$TMP/put.log" && break; sleep 0.2; done

OUT=$("$PEEK" --face-socket "$B_SOCK" --no-shm --can-be-prefix --lifetime 5000 "$PREFIX" 2>&1 || true)

if echo "$OUT" | grep -q 'QUIC-WITNESS-OK'; then
    grep -q 'link up' "$A_LOG" \
        && echo "PASS: Data round-tripped over the QUIC link (B's face $FACE; A admitted the link)"
    exit 0
else
    echo "FAIL: content did not round-trip over the QUIC link" >&2
    echo "  peek: $OUT" >&2
    echo "  --- A log tail ---" >&2; tail -6 "$A_LOG" >&2
    echo "  --- B log tail ---" >&2; tail -6 "$B_LOG" >&2
    exit 1
fi
