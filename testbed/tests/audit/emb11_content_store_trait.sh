#!/usr/bin/env bash
# Witness for EMB-11 — CsStore trait; CS admission + serve-from-cache.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 5e
# Severity:    embedded anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — ndn-fwd-core defines CsStore (lookup + admit) and a NoCs
#       no-op default, both keyed by component slices.
#   (b) GREP-PROOF — decide_data admits solicited Data to the CS, and the
#       embedded forwarder serves cache hits (cs.lookup) and admits via the
#       Content Store it now holds.
#   (c) GREP-PROOF — the constrained ContentStore implements CsStore.
#   (d) RUST-UNIT  — ndn-fwd-core tests pass, and ndn-embedded tests pass with
#       the `cs` feature (admission + serve-from-cache).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout; no Docker.
#
# Exit codes: 0 PASS · 1 FAIL · 2 SKIP (cargo missing)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

command -v cargo >/dev/null 2>&1 || { echo "SKIP: cargo not in PATH" >&2; exit 2; }

fail=0
CRATE_DIR=$(find crates -type d -name ndn-fwd-core 2>/dev/null | head -1)
STORE="$CRATE_DIR/src/store.rs"
PIPE="$CRATE_DIR/src/pipeline.rs"
FWD=crates/ndn-embedded/src/forwarder.rs
CS=crates/ndn-embedded/src/cs.rs

# (a) CsStore + NoCs.
grep -qE 'trait[[:space:]]+CsStore' "$STORE" || { echo "FAIL: no CsStore trait" >&2; fail=1; }
grep -qE 'fn[[:space:]]+admit' "$STORE" || { echo "FAIL: CsStore lacks admit" >&2; fail=1; }
grep -qE 'fn[[:space:]]+lookup' "$STORE" || { echo "FAIL: CsStore lacks lookup" >&2; fail=1; }
grep -qE 'struct[[:space:]]+NoCs' "$STORE" || { echo "FAIL: no NoCs no-op" >&2; fail=1; }

# (b) decide_data admits; forwarder serves cache + admits.
grep -qE 'cs\.admit\(' "$PIPE" || { echo "FAIL: decide_data does not admit to the CS" >&2; fail=1; }
grep -qE 'self\.cs\.lookup\(' "$FWD" || { echo "FAIL: forwarder does not serve from cache" >&2; fail=1; }

# (c) ContentStore implements CsStore (the `impl … CsStore` may wrap before `for`).
grep -qE 'impl.*CsStore' "$CS" || { echo "FAIL: ContentStore does not impl CsStore" >&2; fail=1; }

# (d) tests pass, including the cs feature.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core && cargo test -p ndn-embedded --features cs"
    if ! cargo test --quiet -p ndn-fwd-core >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-embedded --features cs >/dev/null 2>&1; then
        echo "FAIL: ndn-fwd-core / ndn-embedded(+cs) tests did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-11 — CsStore trait; decide_data caches solicited Data; serve-from-cache works."
exit "$fail"
