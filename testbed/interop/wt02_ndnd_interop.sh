#!/usr/bin/env bash
# Witness — ndn-rs <-> ndnd WebTransport (HTTP/3) cross-impl interop.
#
# Finding:     ndn-rs's WebTransport face (datagram + NDNLPv2, crates/
#              ndn-face-webtransport) interoperates with ndnd's HTTP/3
#              WebTransport face (fw/face/http3-*.go, NDNLP link service):
#              an Interest/Data round-trips over the cross-impl WT link.
#              This is the only QUIC-family transport ndnd and ndn-rs share
#              (NFD has none; ndnd's is HTTP/3 WebTransport).
#
# Upstream gap (ndnd side, NOT ndn-rs): stock ndnd's
# `fw/face/http3-listener.go` cannot complete a WebTransport handshake with
# any spec-conformant client. Two one-line omissions:
#   (1) its TLS config sets no `NextProtos` -> QUIC has no `h3` ALPN, so the
#       handshake aborts with TLS alert 120 (no_application_protocol);
#   (2) it never calls `webtransport.ConfigureHTTP3Server(s.H3)`, so the
#       server never advertises SETTINGS_ENABLE_WEBTRANSPORT / H3 datagrams /
#       ConnContext, and the session is closed right after the H3 SETTINGS.
# ndn-rs's wtransport client is correct (offers `h3`, ENABLE_WEBTRANSPORT,
# H3_DATAGRAM). To demonstrate interop against the real ndnd codebase without
# editing the checkout, this witness builds ndnd with those two fixes applied
# via `go build -overlay` (the patch is printed below). With them, the
# datagram + NDNLPv2 path interoperates cleanly.
#
# Severity:    interop witness (cross-implementation, functional)
# Reverify recipe: INTEROP-SCRIPT (two implementations, local processes).
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP (toolchain/source unavailable)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

NDND_SRC="${NDND_SRC:-$HOME/Documents/Dev/ndnd}"
# go is often installed but off PATH (e.g. /usr/local/go/bin).
if ! command -v go >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then
    export PATH="$PATH:/usr/local/go/bin"
fi

command -v cargo   >/dev/null 2>&1 || { echo "SKIP: cargo not available"   >&2; exit 2; }
command -v go      >/dev/null 2>&1 || { echo "SKIP: go not available (needed to build ndnd)" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not available" >&2; exit 2; }
[ -f "$NDND_SRC/fw/face/http3-listener.go" ] || { echo "SKIP: ndnd source not at $NDND_SRC (set NDND_SRC)" >&2; exit 2; }

TMP="$(mktemp -d /tmp/wt02.XXXXXX)"
cleanup() { for p in "${PING_PID:-}" "${NDND_PID:-}" "${FWD_PID:-}"; do
              [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
            rm -rf "$TMP"; }
trap cleanup EXIT

# ── Build ndnd with the two ndnd-side WebTransport fixes (overlay; the ndnd
#    checkout is left untouched). ───────────────────────────────────────────
LISTENER_SRC="$NDND_SRC/fw/face/http3-listener.go"
LISTENER_ABS="$(cd "$(dirname "$LISTENER_SRC")" && pwd)/$(basename "$LISTENER_SRC")"
cp "$LISTENER_SRC" "$TMP/http3-listener.go"
perl -0pi -e 's/(MinVersion:\s*tls\.VersionTLS12,\n)/$1\t\t\t\tNextProtos:   []string{"h3"},\n/' "$TMP/http3-listener.go"
perl -0pi -e 's/(\treturn l, nil\n\})/\twebtransport.ConfigureHTTP3Server(l.server.H3)\n$1/' "$TMP/http3-listener.go"
grep -q 'NextProtos' "$TMP/http3-listener.go" && grep -q 'ConfigureHTTP3Server' "$TMP/http3-listener.go" \
    || { echo "SKIP: could not apply ndnd WT fixes (ndnd source layout changed?)" >&2; exit 2; }
printf '{"Replace":{"%s":"%s"}}' "$LISTENER_ABS" "$TMP/http3-listener.go" > "$TMP/overlay.json"

echo "→ building ndnd (go build -overlay; +h3 ALPN +ConfigureHTTP3Server)"
( cd "$NDND_SRC" && go build -overlay "$TMP/overlay.json" -o "$TMP/ndnd" ./cmd/ndnd ) >"$TMP/ndnd-build.log" 2>&1 \
    || { echo "SKIP: ndnd build failed (see $TMP/ndnd-build.log)"; tail -20 "$TMP/ndnd-build.log" >&2; exit 2; }

echo "→ building ndn-fwd + ndn-tools"
cargo build --quiet -p ndn-fwd -p ndn-tools >"$TMP/rs-build.log" 2>&1 \
    || { echo "SKIP: ndn-rs build failed (see $TMP/rs-build.log)"; tail -20 "$TMP/rs-build.log" >&2; exit 2; }

FWD="$REPO_ROOT/target/debug/ndn-fwd"; PEEK="$REPO_ROOT/target/debug/ndn-peek"
CTL="$REPO_ROOT/target/debug/ndn-ctl"; NDND="$TMP/ndnd"
for b in "$FWD" "$PEEK" "$CTL" "$NDND"; do [ -x "$b" ] || { echo "SKIP: missing binary $b" >&2; exit 2; }; done

# ── Self-signed EC P-256 cert for the ndnd HTTP/3 listener ───────────────────
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/key.pem" 2>/dev/null
openssl req -new -x509 -key "$TMP/key.pem" -out "$TMP/cert.pem" -days 13 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null
HASH=$(openssl x509 -in "$TMP/cert.pem" -outform DER | openssl dgst -sha256 -r | awk '{print $1}')
[ ${#HASH} -eq 64 ] || { echo "FAIL: could not compute cert SHA-256 (got '$HASH')" >&2; exit 1; }

WT_PORT=14443
NDND_SOCK="$TMP/ndnd.sock"
PREFIX="/wt-interop"

cat > "$TMP/ndnd.yml" <<EOF
core:
  log_level: INFO
faces:
  udp: { enabled_unicast: false, enabled_multicast: false }
  tcp: { enabled: false }
  unix: { enabled: true, socket_path: "$NDND_SOCK" }
  websocket: { enabled: false }
  http3: { enabled: true, bind: "127.0.0.1", port: $WT_PORT, tls_cert: "$TMP/cert.pem", tls_key: "$TMP/key.pem" }
fw: { threads: 2 }
mgmt: { allow_localhop: true }
EOF

"$NDND" fw run "$TMP/ndnd.yml" >"$TMP/ndnd.log" 2>&1 & NDND_PID=$!
for _ in $(seq 1 60); do [ -S "$NDND_SOCK" ] && break; sleep 0.2; done
[ -S "$NDND_SOCK" ] || { echo "FAIL: ndnd forwarder did not open its unix socket" >&2; tail -15 "$TMP/ndnd.log" >&2; exit 1; }

# ndnd pingserver under /wt-interop (attaches over the unix face).
NDN_CLIENT_TRANSPORT="unix://$NDND_SOCK" "$NDND" pingserver "$PREFIX" >"$TMP/ping.log" 2>&1 & PING_PID=$!
sleep 1
kill -0 "$PING_PID" 2>/dev/null || { echo "FAIL: ndnd pingserver exited early" >&2; tail -15 "$TMP/ping.log" >&2; exit 1; }

# ── ndn-rs forwarder: dial ndnd's WebTransport listener, cert-pinned ─────────
# Dial the IPv4 literal (ndnd binds 127.0.0.1; `localhost` would try ::1 first).
RS_SOCK="$TMP/rs.sock"
cat > "$TMP/rs.toml" <<EOF
[security]
profile = "disabled"
[security.mgmt]
require_signed_commands = false
[[face]]
kind = "web-transport"
remote = "wts://127.0.0.1:$WT_PORT/ndn"
cert_sha256 = "$HASH"
[management]
face_socket = "$RS_SOCK"
[logging]
level = "info"
EOF

"$FWD" -c "$TMP/rs.toml" >"$TMP/rs.log" 2>&1 & FWD_PID=$!
for _ in $(seq 1 80); do grep -q 'WebTransport dial face connected' "$TMP/rs.log" && break; sleep 0.2; done
FACE=$(grep -oE 'WebTransport dial face connected.*face#[0-9]+' "$TMP/rs.log" | grep -oE '[0-9]+$' | head -1)
[ -n "$FACE" ] || { echo "FAIL: ndn-rs did not connect the WebTransport dial face to ndnd" >&2
                    echo "  --- ndn-rs log ---" >&2; tail -12 "$TMP/rs.log" >&2
                    echo "  --- ndnd log ---"   >&2; tail -8  "$TMP/ndnd.log" >&2; exit 1; }

grep -q 'Accepting new HTTP/3 WebTransport face' "$TMP/ndnd.log" \
    || { echo "FAIL: ndnd did not accept the inbound WebTransport session" >&2; tail -10 "$TMP/ndnd.log" >&2; exit 1; }

# Route /wt-interop over the cross-impl WebTransport face.
"$CTL" --socket "$RS_SOCK" route add "$PREFIX" --face "$FACE" >/dev/null 2>&1 || true

# ── Consumer: fetch through ndn-rs -> WT -> ndnd -> pingserver ───────────────
if "$PEEK" --face-socket "$RS_SOCK" --no-shm --lifetime 6000 "$PREFIX/ping/0" >"$TMP/peek.out" 2>&1; then
    echo "PASS: Interest/Data round-tripped over the ndn-rs <-> ndnd WebTransport link (face#$FACE -> ndnd pingserver)"
    exit 0
else
    echo "FAIL: /wt-interop/ping/0 did not round-trip over the cross-impl WebTransport link" >&2
    echo "  peek: $(cat "$TMP/peek.out")" >&2
    echo "  --- ndn-rs log ---" >&2; tail -10 "$TMP/rs.log"  >&2
    echo "  --- ndnd log ---"   >&2; tail -10 "$TMP/ndnd.log" >&2
    exit 1
fi
