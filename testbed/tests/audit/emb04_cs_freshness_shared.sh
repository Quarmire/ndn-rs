#!/usr/bin/env bash
# Witness for EMB-04 — Content Store freshness/staleness rule lives once.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 2 (step 2)
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core exposes the freshness/staleness decision
#       (e.g. `is_fresh` / `is_stale` over (freshness_period, age)).
#   (b) GREP-PROOF — ndn-embedded/src/cs.rs delegates to it rather than
#       re-implementing the staleness comparison.
#   Freshness is a pure function of (freshness_period, now, stored_at) on both
#   sides — second-cheapest de-duplication after FIB LPM.
#
# Reverify recipe: GREP-PROOF. Runs in any checkout; no Docker.
#
# Expected today: FAIL (exit 1) — cs.rs re-implements staleness; core absent.
#
# Exit codes: 0 PASS · 1 FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0
CRATE_DIR=$(find crates -type d -name ndn-fwd-core 2>/dev/null | head -1)
EMB_CS=crates/ndn-embedded/src/cs.rs

if [ -z "$CRATE_DIR" ]; then
    echo "FAIL: ndn-fwd-core not found (EMB-01 must pass first)" >&2
    fail=1
elif ! grep -rqiE 'fresh_until|fresh_for|is_fresh|is_stale|fn[[:space:]]+freshness' "$CRATE_DIR/src" 2>/dev/null; then
    echo "FAIL: ndn-fwd-core exposes no freshness/staleness decision" >&2
    fail=1
fi

if [ -f "$EMB_CS" ]; then
    if ! grep -qE 'ndn_fwd_core' "$EMB_CS"; then
        echo "FAIL: $EMB_CS does not reference ndn_fwd_core (re-implements staleness)" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-04 — CS freshness rule shared via ndn-fwd-core."
exit "$fail"
