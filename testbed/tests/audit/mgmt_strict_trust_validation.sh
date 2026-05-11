#!/usr/bin/env bash
# Audit witness for finding N.12 — mgmt response Data is verifiable
# under a strict trust schema (the contract `ndn-cxx`'s
# `ValidatorConfig` + a strict-mode `nfdc` would enforce).
#
# Pipeline:
#   1. Spawn ndn-fwd with a configured identity persisted in a
#      throwaway PIB directory.
#   2. Wait for the mgmt socket to appear.
#   3. Run the audit-strict-mgmt-validation binary, which:
#        a. Opens the PIB and loads every trust anchor.
#        b. Connects to the mgmt socket over IpcFace.
#        c. Issues /localhost/nfd/status/general.
#        d. Validates the response Data against a Validator pinned
#           to those anchors via the same `ValidationResult::Valid`
#           path the engine's `ValidationStage` uses for inbound Data.
#   4. Assert exit 0 (Valid).
#
# Why this is a real strict-mode gate even though it's not literally
# `nfdc --validate-strict`:
#   - ndn-cxx's verifier is OpenSSL `EVP_DigestVerify` over
#     ECDSA-P256 + SHA-256, bit-for-bit identical to what the
#     `p256` crate (used by ndn-security) does.
#   - The Validator's `validate_chain` is the canonical strict path
#     ndn-rs's own engine runs on every inbound Data — closing the
#     loop "deployed signer's output validates under the deployed
#     verifier" with our actual code, not a mocked wrapper.
#
# Exit codes: 0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TRANSCRIPT_DIR="$(dirname "$0")/transcripts"
mkdir -p "$TRANSCRIPT_DIR"

if ! command -v cargo >/dev/null 2>&1; then
    echo "SKIP: cargo missing" >&2
    exit 2
fi

if ! cargo build -p ndn-fwd -p audit-strict-mgmt-validation --quiet \
        2>/tmp/mgmt_strict_build.log; then
    echo "FAIL: build"
    cat /tmp/mgmt_strict_build.log
    exit 1
fi

NDN_FWD="$REPO_ROOT/target/debug/ndn-fwd"
WITNESS="$REPO_ROOT/target/debug/audit-strict-mgmt-validation"

WORK="$(mktemp -d)"
FWD_SOCK="$WORK/ndn-fwd.sock"
# Don't pre-create — SecurityManager::auto_init takes the
# `path-doesn't-exist` branch and calls `FilePib::new` to provision
# the directory itself; if we mkdir it first, `FilePib::open` runs
# against an empty dir and errors with "PIB not found".
PIB="$WORK/pib"
FWD_PID=""

cleanup() {
    if [ -n "$FWD_PID" ]; then
        kill "$FWD_PID" 2>/dev/null || true
        wait "$FWD_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── Config: persistent identity in $PIB; auto_init generates ECDSA ──
cat >"$WORK/ndn-fwd.toml" <<EOF
[engine]
pipeline_threads = 1
cs_capacity_mb   = 4

[security]
profile   = "default"
identity  = "/test/strict-trust-router"
pib_path  = "$PIB"
auto_init = true

[security.mgmt]
require_signed_commands = false

[management]
face_socket = "$FWD_SOCK"

[logging]
level = "warn"
EOF

RUST_LOG=warn "$NDN_FWD" -c "$WORK/ndn-fwd.toml" \
    >"$TRANSCRIPT_DIR/mgmt_strict_fwd.stdout" 2>&1 &
FWD_PID=$!

for _ in $(seq 1 50); do
    [ -S "$FWD_SOCK" ] && break
    sleep 0.1
done
if [ ! -S "$FWD_SOCK" ]; then
    echo "FAIL: ndn-fwd socket did not appear"
    cat "$TRANSCRIPT_DIR/mgmt_strict_fwd.stdout"
    exit 1
fi

# Wait a moment for the auto-init to finish writing the cert to the PIB.
sleep 1

if "$WITNESS" --socket "$FWD_SOCK" --pib "$PIB" \
       >"$TRANSCRIPT_DIR/mgmt_strict_witness.stdout" \
       2>"$TRANSCRIPT_DIR/mgmt_strict_witness.stderr"; then
    cat "$TRANSCRIPT_DIR/mgmt_strict_witness.stdout"
    echo
    echo "=== N.12 strict-trust witness PASS ==="
    exit 0
else
    echo "FAIL: strict-trust validation"
    echo "--- witness stdout ---"
    cat "$TRANSCRIPT_DIR/mgmt_strict_witness.stdout"
    echo "--- witness stderr ---"
    cat "$TRANSCRIPT_DIR/mgmt_strict_witness.stderr"
    echo "--- ndn-fwd stdout ---"
    cat "$TRANSCRIPT_DIR/mgmt_strict_fwd.stdout"
    exit 1
fi
