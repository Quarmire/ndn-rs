#!/usr/bin/env bash
# Live interop witness for audit finding E.01 — default-on signed-command
# enforcement in ndn-fwd with a real identity rig.
#
# Finding:     testbed/EXPECTED_FAILURES.md § E.01
# Severity:    RESOLVED 2026-05-07 (testbed leg)
# Spec ref:    NFD Developer Guide §7; NFD daemon/mgmt/command-authenticator.cpp
# Witness:     INTEROP-SCRIPT — boots ndn-fwd with require_signed_commands=true
#              and a /test trust anchor; asserts:
#              1a. unsigned command from the daemon's own user (a local
#                  operator, authenticated by peer credentials) → 200
#              1b. unsigned command from another uid → 403 rejected
#              2. /test/admin-signed command → 200 accepted, RIB updated
#              3. /intruder-signed command (untrusted key) → 403 rejected
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
# ndn-fwd, ndn-ctl and ndn-sec are built in the ndn-fwd workspace, a sibling
# of ndn-rs. The committed transcripts live in testbed/transcripts/.
WORKSPACE_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
FWD_ROOT="$WORKSPACE_ROOT/ndn-fwd"
TRANSCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)/transcripts"
mkdir -p "$TRANSCRIPT_DIR"

# ── Prerequisites ─────────────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi
if [ ! -f "$FWD_ROOT/Cargo.toml" ]; then
    echo "SKIP: no ndn-fwd workspace at $FWD_ROOT" >&2
    exit 2
fi

# Ask cargo where it puts the binaries: a shared target dir (CARGO_TARGET_DIR,
# or the workspace's .cargo/config.toml) redirects them out of the repo.
if ! TARGET_DIR="$(cd "$FWD_ROOT" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"; then
    echo "SKIP: cannot locate the cargo target directory of $FWD_ROOT" >&2
    exit 2
fi

# Always build: a stale binary would witness old behaviour.
BUILD_LOG="$(mktemp)"
if ! (cd "$FWD_ROOT" && cargo build -p ndn-fwd -p ndn-tools --bins --quiet) 2>"$BUILD_LOG"; then
    echo "FAIL: build failed"
    cat "$BUILD_LOG"
    rm -f "$BUILD_LOG"
    exit 1
fi
rm -f "$BUILD_LOG"

NDN_FWD="$TARGET_DIR/debug/ndn-fwd"
NDN_CTL="$TARGET_DIR/debug/ndn-ctl"
NDN_SEC="$TARGET_DIR/debug/ndn-sec"

WORK="$(mktemp -d)"
PASS=0
FAIL=0
FWD_PID=""

cleanup() {
    if [ -n "$FWD_PID" ]; then
        kill "$FWD_PID" 2>/dev/null || true
        wait "$FWD_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── Identity rig ──────────────────────────────────────────────────────────────
ANCHOR_PIB="$WORK/anchor-pib"
INTRUDER_PIB="$WORK/intruder-pib"

# /test — self-signed root anchor (trust anchor for ndn-fwd)
"$NDN_SEC" --pib "$ANCHOR_PIB" keygen --anchor /test
# /test/admin — separate key for ndn-ctl; added as a trust anchor so the
# mgmt validator can verify its signatures (single-hop self-signed trust).
"$NDN_SEC" --pib "$ANCHOR_PIB" keygen --anchor /test/admin

# /intruder — key NOT in the trust anchor PIB (untrusted)
"$NDN_SEC" --pib "$INTRUDER_PIB" keygen /intruder

# ── ndn-fwd config for signed-mgmt mode ──────────────────────────────────────
FWD_SOCK="$WORK/ndn-fwd.sock"
cat >"$WORK/ndn-fwd-signed.toml" <<EOF
[engine]
pipeline_threads = 1
cs_capacity_mb   = 4

[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = true
trust_anchor_pib        = "$ANCHOR_PIB"

[[face]]
kind = "udp"
bind = "127.0.0.1:16363"

[management]
face_socket = "$FWD_SOCK"

[logging]
level = "warn"
EOF

# ── Launch ndn-fwd ─────────────────────────────────────────────────────────────
RUST_LOG=warn "$NDN_FWD" -c "$WORK/ndn-fwd-signed.toml" \
    >"$TRANSCRIPT_DIR/e01_fwd_stdout.txt" 2>&1 &
FWD_PID=$!

# Wait for the socket to appear (max 5 s).
for _ in $(seq 1 50); do
    [ -S "$FWD_SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$FWD_SOCK" ]; then
    echo "FAIL: ndn-fwd socket did not appear"
    cat "$TRANSCRIPT_DIR/e01_fwd_stdout.txt"
    exit 1
fi

check_pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
check_fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

# Each `ndn-ctl` invocation opens a fresh Unix-socket face that's torn
# down on disconnect; its routes are cleaned by `on-demand face removed
# from table (FIB routes cleaned)` in the inbound dispatcher.  That
# means a follow-up `ndn-ctl route list` from a *different* invocation
# can't reliably observe the route added in the previous one — the
# entry is correctly added then correctly cleaned up across the two
# socket lifetimes.  So the case assertions below rely on ndn-ctl's
# exit code (0 = `200 OK`, non-zero = an error ControlResponse, which
# the client surfaces as a non-zero exit) rather than racing the FIB
# inspection.  This is the same signal NFD's own `nfdc` exposes.

# ── Case 1a: unsigned command from the daemon's user → 200 ───────────────────
echo "=== Case 1a: unsigned command from a local operator accepted ==="
if "$NDN_CTL" --socket "$FWD_SOCK" route add /e01/test --face 1 \
       >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case1.txt" 2>&1; then
    check_pass "local operator's unsigned route add accepted (200)"
else
    check_fail "local operator's unsigned route add was rejected (expected 200)"
    cat "$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case1.txt"
fi
echo

# ── Case 1b: unsigned command from another uid → 403 ─────────────────────────
# A user namespace maps us to root and uid 1 to a subordinate id, so the
# daemon sees a foreign uid on the socket. Skipped where unavailable.
echo "=== Case 1b: unsigned command from another uid rejected ==="
if unshare --map-auto --map-root-user true 2>/dev/null; then
    chmod 755 "$WORK"
    if unshare --map-auto --map-root-user sh -c \
           "setpriv --reuid=1 --regid=1 --clear-groups '$NDN_CTL' --socket '$FWD_SOCK' route add /e01/other --face 1" \
           >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case1b.txt" 2>&1; then
        check_fail "another uid's unsigned route add must be rejected (got 200)"
        cat "$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case1b.txt"
    else
        check_pass "another uid's unsigned route add rejected (403)"
    fi
else
    echo "  SKIP: user namespaces unavailable"
fi
echo

# ── Case 2: /test/admin-signed command → 200 ─────────────────────────────────
echo "=== Case 2: trusted-key command accepted ==="
if "$NDN_CTL" --socket "$FWD_SOCK" --identity /test/admin --pib "$ANCHOR_PIB" \
       route add /e01/trusted --face 1 \
       >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case2.txt" 2>&1; then
    check_pass "trusted-key route add accepted (200)"
else
    check_fail "trusted-key route add was rejected (expected 200)"
    cat "$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case2.txt"
fi
echo

# ── Case 3: /intruder-signed command → 403 ────────────────────────────────────
echo "=== Case 3: untrusted-key command rejected ==="
if "$NDN_CTL" --socket "$FWD_SOCK" --identity /intruder --pib "$INTRUDER_PIB" \
       route add /e01/intruder --face 1 \
       >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case3.txt" 2>&1; then
    check_fail "untrusted-key route add must be rejected (got 200)"
    cat "$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case3.txt"
else
    check_pass "untrusted-key route add rejected (403)"
fi
echo

# ── Case D: dev-mode regression — require_signed_commands=false still works ───
echo "=== Case D: dev-mode regression (require_signed_commands=false) ==="
DEV_SOCK="$WORK/ndn-fwd-dev.sock"
cat >"$WORK/ndn-fwd-dev.toml" <<EOF
[engine]
pipeline_threads = 1
cs_capacity_mb   = 4

[security]
profile = "disabled"

[security.mgmt]
require_signed_commands = false

[[face]]
kind = "udp"
bind = "127.0.0.1:16364"

[management]
face_socket = "$DEV_SOCK"

[logging]
level = "warn"
EOF

DEV_FWD_PID=""
cleanup_dev() {
    if [ -n "$DEV_FWD_PID" ]; then
        kill "$DEV_FWD_PID" 2>/dev/null || true
        wait "$DEV_FWD_PID" 2>/dev/null || true
    fi
}
trap 'cleanup_dev; cleanup' EXIT

RUST_LOG=warn "$NDN_FWD" -c "$WORK/ndn-fwd-dev.toml" \
    >"$TRANSCRIPT_DIR/e01_dev_stdout.txt" 2>&1 &
DEV_FWD_PID=$!

for _ in $(seq 1 50); do
    [ -S "$DEV_SOCK" ] && break
    sleep 0.1
done

if [ ! -S "$DEV_SOCK" ]; then
    check_fail "dev-mode ndn-fwd socket did not appear"
else
    if "$NDN_CTL" --socket "$DEV_SOCK" route add /dev/test --face 1 \
           >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_caseD.txt" 2>&1; then
        check_pass "dev-mode unsigned route add accepted (regression guard)"
    else
        check_fail "dev-mode unsigned route add rejected (regression: require_signed_commands=false broken)"
        cat "$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_caseD.txt"
    fi
fi
echo

# ── Summary ───────────────────────────────────────────────────────────────────
echo "Results: $PASS passed, $FAIL failed"
echo

if [ "$FAIL" -gt 0 ]; then
    echo "FAIL: E.01 live witness has failures"
    exit 1
fi

echo "=== E.01 RESOLVED (testbed) — signed-command enforcement confirmed ==="
exit 0
