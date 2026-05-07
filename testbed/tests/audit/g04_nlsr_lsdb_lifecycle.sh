#!/usr/bin/env bash
# Witness recipe for G.04 partial — NLSR LSDB lifecycle.
#
# Finding:     docs/notes/spec-compliance-audit-2026-04-20.md § G.04
# Severity:    MAJOR (partial fix — LSDB storage, install, expiry, refresh)
# Spec ref:    NLSR/src/lsdb.hpp, NLSR/src/lsdb.cpp
# Witnesses:   RUST-UNIT — install/replace/stale/duplicate/expire/refresh
#              covering install semantics, clock-driven expiry (tokio::time::pause
#              + advance), and the 80%-elapsed refresh threshold.
#
# Expected today: FAIL (exit 1) — tests not yet present.
# After phase 2 lands: exit 0.
#
# Exit codes:  0 PASS / 1 FAIL / 2 SKIP
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

# 1. Verify the lsdb module and test module exist.
if grep -q 'mod lsdb' crates/protocols/ndn-routing/src/protocols/nlsr/mod.rs 2>/dev/null; then
    echo "ok: lsdb module declared in nlsr/mod.rs"
else
    echo "FAIL: lsdb module not found in nlsr/mod.rs"
    fail=1
fi

if grep -q 'mod lsdb' crates/protocols/ndn-routing/src/protocols/nlsr/lsdb.rs 2>/dev/null; then
    echo "ok: lsdb test module present in lsdb.rs"
else
    echo "FAIL: lsdb test module not found in lsdb.rs"
    fail=1
fi

# 2. Run the LSDB unit tests.
log="$REPO_ROOT/target/g04_lsdb_lifecycle.log"
cargo test -p ndn-routing "nlsr::lsdb" >"$log" 2>&1 || true
cat "$log"

if grep -qE '^test result: ok' "$log"; then
    echo "ok: nlsr::lsdb tests pass"
elif grep -qE 'FAILED|^error' "$log"; then
    echo "FAIL: one or more nlsr::lsdb tests failed or build failed"
    fail=1
else
    echo "FAIL: test filter produced no output (tests absent or build failed)"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo
    echo "=== G.04 partial PASS — LSDB lifecycle witnessed ==="
    exit 0
else
    echo
    echo "=== G.04 partial FAIL — LSDB lifecycle not yet implemented ==="
    exit 1
fi
