#!/usr/bin/env bash
# Witness test for audit finding N.10 — captured signed command
# Interests can be replayed indefinitely because no `SignatureTime`
# window is enforced.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.10
# Severity:    MAJOR (depends on E.01)
# Spec ref:    ndn-cxx `ValidationPolicyCommandInterest` keeps a per-signer
#              `lastTimestamp` and rejects either out-of-window or
#              non-strictly-increasing values; ndn-cxx `interest.cpp`
#              attaches a `SignatureTime` header at signing time.
# Witnesses:   RUST-UNIT in `ndn-mgmt::auth::tests`:
#                - n10_check_sig_time_rejects_missing
#                - n10_check_sig_time_rejects_out_of_window
#                - n10_check_sig_time_accepts_fresh_in_window
#                - n10_check_sig_time_rejects_replay
#                - n10_check_sig_time_accepts_strictly_greater
#                - n10_replay_rejected_when_cache_enabled (end-to-end)
#              RUST-UNIT in `ndn-fwd`:
#                - n10_forwarder_default_replay_cache_is_wired
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-mgmt --lib --quiet n10_ \
        >/tmp/n10_witness.log 2>&1; then
    echo "ok: SignatureTime window enforced; replay rejected"
else
    echo "FAIL: SignatureTime window not enforced"
    fail=1
fi

if cargo test -p ndn-fwd --bin ndn-fwd --quiet n10_forwarder_default_replay_cache_is_wired \
        >/tmp/n10_fwd_witness.log 2>&1; then
    echo "ok: ndn-fwd mounts management with a command replay cache"
else
    echo "FAIL: ndn-fwd command replay cache is not wired"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.10 RESOLVED — replay protection on signed commands ==="
    exit 0
else
    echo
    echo "=== N.10 EXPECTED-FAIL — captured signed commands replayable ==="
    [ -f /tmp/n10_witness.log ] && cat /tmp/n10_witness.log
    [ -f /tmp/n10_fwd_witness.log ] && cat /tmp/n10_fwd_witness.log
    exit 1
fi
