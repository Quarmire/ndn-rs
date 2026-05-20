#!/usr/bin/env bash
# Witness recipe for ARCH-12 / S16 — per-module split of ndn-mgmt.
#
# Finding:     docs/notes/architecture-gap-inventory-2026-05-20.md § ARCH-12
# Severity:    Phase 2 architectural cleanup (pre-v0.1.0)
# Witnesses:
#   (a) GREP-PROOF — lib.rs is under the 800-line cap.
#   (b) GREP-PROOF — one MgmtModule-impl file per NFD module exists
#       under crates/spec/ndn-mgmt/src/modules/.
#   (c) GREP-PROOF — `MgmtRouter` is the dispatch surface (no
#       residual `dispatch_command` free function in lib.rs).
#   (d) RUST-UNIT  — the existing ndn-mgmt test suite still passes
#       (wire compatibility is unchanged).
#
# Reverify recipe: GREP-PROOF + RUST-UNIT. Runs in any checkout of
# ndn-rs; no Docker required.
#
# Exit codes:
#   0 — PASS (mgmt monolith split; wire unchanged)
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

fail=0

LIB=crates/spec/ndn-mgmt/src/lib.rs
MODULES_DIR=crates/spec/ndn-mgmt/src/modules

# (1) lib.rs orchestrator size cap.
lib_lines=$(wc -l < "$LIB" | tr -d ' ')
if [ "$lib_lines" -gt 800 ]; then
    echo "FAIL: $LIB is $lib_lines lines (cap: 800)" >&2
    fail=1
fi

# (2) Every NFD-style module has its own file under modules/.
EXPECTED_MODULES=(
    rib faces fib strategy cs status routing discovery neighbors service
    measurements security config log coding rate_limit
)
for m in "${EXPECTED_MODULES[@]}"; do
    f="$MODULES_DIR/${m}.rs"
    if [ ! -f "$f" ]; then
        echo "FAIL: missing per-module file $f" >&2
        fail=1
        continue
    fi
    if ! grep -qE 'impl[[:space:]]+MgmtModule[[:space:]]+for' "$f"; then
        echo "FAIL: $f has no \`impl MgmtModule for …\`" >&2
        fail=1
    fi
done

# (3) MgmtRouter is the dispatch surface; the old dispatch_command
#     free function and the DispatchCtx struct are gone from lib.rs.
if grep -nE '^[[:space:]]*async fn dispatch_command' "$LIB" >/dev/null 2>&1; then
    echo "FAIL: $LIB still defines dispatch_command (use MgmtRouter)" >&2
    grep -nE '^[[:space:]]*async fn dispatch_command' "$LIB" >&2
    fail=1
fi
if grep -nE '^[[:space:]]*struct DispatchCtx' "$LIB" >/dev/null 2>&1; then
    echo "FAIL: $LIB still defines DispatchCtx (replaced by MgmtContext)" >&2
    fail=1
fi
if ! grep -qE 'MgmtRouter::new' "$LIB"; then
    echo "FAIL: $LIB does not instantiate MgmtRouter" >&2
    fail=1
fi

# (4) Wire compat — the ndn-mgmt test suite still passes.
echo "→ cargo test -p ndn-mgmt"
if ! cargo test --quiet -p ndn-mgmt >/dev/null 2>&1; then
    echo "FAIL: cargo test -p ndn-mgmt did not pass" >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "PASS: ARCH-12 — ndn-mgmt split into per-module files; lib.rs=$lib_lines lines; wire unchanged."
fi
exit "$fail"
