#!/usr/bin/env bash
# Live interop witness for audit finding E.01 — default-on signed-command
# enforcement in ndn-fwd with a real identity rig.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § E.01
# Severity:    RESOLVED 2026-05-07 (testbed leg)
# Spec ref:    NFD Developer Guide §7; NFD daemon/mgmt/command-authenticator.cpp
# Witness:     INTEROP-SCRIPT — boots ndn-fwd with require_signed_commands=true
#              and a /test trust anchor; asserts three cases:
#              1. unsigned (DigestSha256) command → 403 rejected
#              2. /test/admin-signed command → 200 accepted, RIB updated
#              3. /intruder-signed command (untrusted key) → 403 rejected
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TRANSCRIPT_DIR="$(dirname "$0")/transcripts"
mkdir -p "$TRANSCRIPT_DIR"

# ── Prerequisites ─────────────────────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi
if ! command -v ndn-ctl >/dev/null 2>&1 && \
   [ ! -f "$REPO_ROOT/target/debug/ndn-ctl" ]; then
    echo "SKIP: ndn-ctl not built — run 'cargo build -p ndn-tools --bin ndn-ctl'" >&2
    exit 2
fi

# Build required binaries if not already present.
if ! cargo build -p ndn-fwd -p ndn-tools --bins --quiet 2>/tmp/e01_build.log; then
    echo "FAIL: build failed"
    cat /tmp/e01_build.log
    exit 1
fi

NDN_FWD="$REPO_ROOT/target/debug/ndn-fwd"
NDN_CTL="$REPO_ROOT/target/debug/ndn-ctl"
NDN_SEC="$REPO_ROOT/target/debug/ndn-sec"

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

# ── Case 1: unsigned (DigestSha256) command → 403 ─────────────────────────────
echo "=== Case 1: unsigned command rejected ==="
if "$NDN_CTL" --socket "$FWD_SOCK" route add /e01/test --face 1 \
       >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case1.txt" 2>&1; then
    check_fail "unsigned route add must be rejected (got 200)"
    cat "$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case1.txt"
else
    # Verify the RIB does NOT have the entry.
    RIB=$("$NDN_CTL" --socket "$FWD_SOCK" route list 2>/dev/null || true)
    if echo "$RIB" | grep -q "/e01/test"; then
        check_fail "unsigned route add was rejected but RIB shows entry (inconsistency)"
    else
        check_pass "unsigned route add rejected (403); RIB unchanged"
    fi
fi
echo

# ── Case 2: /test/admin-signed command → 200, RIB updated ────────────────────
echo "=== Case 2: trusted-key command accepted ==="
if "$NDN_CTL" --socket "$FWD_SOCK" --identity /test/admin --pib "$ANCHOR_PIB" \
       route add /e01/trusted --face 1 \
       >"$TRANSCRIPT_DIR/e01_signed_mgmt_ndn_fwd_case2.txt" 2>&1; then
    # Verify the RIB shows the entry.
    RIB=$("$NDN_CTL" --socket "$FWD_SOCK" route list 2>/dev/null || true)
    if echo "$RIB" | grep -q "/e01/trusted"; then
        check_pass "trusted-key route add accepted (200); RIB shows /e01/trusted"
    else
        check_fail "route add returned 200 but /e01/trusted not in RIB"
        echo "RIB output: $RIB"
    fi
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
    RIB=$("$NDN_CTL" --socket "$FWD_SOCK" route list 2>/dev/null || true)
    if echo "$RIB" | grep -q "/e01/intruder"; then
        check_fail "untrusted route add was rejected but RIB shows entry (inconsistency)"
    else
        check_pass "untrusted-key route add rejected (403); RIB unchanged"
    fi
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
