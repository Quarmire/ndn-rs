#!/usr/bin/env bash
# Witness test for audit finding N.06 — Dead Nonce List loop detection
# across PIT erasure.
#
# Finding:     docs/notes/spec-compliance-cross-reference-2026-05-01.md § N.06
# Severity:    MAJOR (loop-detection coverage)
# Spec ref:    NFD `daemon/fw/forwarder.cpp:341,374` consults a separate
#              `DeadNonceList` (`daemon/table/dead-nonce-list.cpp`) with a
#              configurable per-entry lifetime (default 6 s) that
#              survives PIT erasure.
# Witnesses:   RUST-UNIT in `ndn-store::dead_nonce_list::tests`:
#                - n06_insert_and_lookup_within_lifetime
#                - n06_lookup_absent_entry
#                - n06_reinsert_bumps_expiry
#                - n06_purge_expired_drops_stale_only
#                - n06_distinct_nonces_under_same_name_hash
#                - n06_default_lifetime_matches_nfd
#              RUST-UNIT in `ndn-engine::stages::pit`:
#                - n06_dnl_rejects_nonce_after_satisfied_pit_entry_is_erased
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"
if ! command -v cargo >/dev/null 2>&1; then echo "SKIP: cargo missing" >&2; exit 2; fi

fail=0
if cargo test -p ndn-store --lib --quiet n06_ \
        >/tmp/n06_witness.log 2>&1; then
    echo "ok: DeadNonceList tracks nonces with NFD-equivalent semantics"
else
    echo "FAIL: DeadNonceList shape diverges"
    fail=1
fi

if cargo test -p ndn-engine --lib --quiet n06_ \
        >/tmp/n06_engine_witness.log 2>&1; then
    echo "ok: engine PIT pipeline consults DNL after PIT erasure"
else
    echo "FAIL: engine PIT pipeline does not consult DNL"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== N.06 RESOLVED — Dead Nonce List wired into PIT loop detection ==="
    exit 0
else
    echo
    echo "=== N.06 EXPECTED-FAIL — Dead Nonce List missing ==="
    [ -f /tmp/n06_witness.log ] && cat /tmp/n06_witness.log
    [ -f /tmp/n06_engine_witness.log ] && cat /tmp/n06_engine_witness.log
    exit 1
fi
