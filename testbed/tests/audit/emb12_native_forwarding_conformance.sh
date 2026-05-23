#!/usr/bin/env bash
# Witness for EMB-12 — native engine forwarding decisions match the sans-IO core.
#
# Design:      .claude/notes/embedded-ndn-modular-build-2026-05-22.md § 5f
# Severity:    cross-impl anti-divergence (pre-v0.2.0)
# Witnesses:
#   (a) GREP-PROOF — shared decision vectors (INTEREST_DECISION_CASES) live in
#       ndn-fwd-core, and the sans-IO decide_interest is pinned to them.
#   (b) GREP-PROOF — a native-engine conformance test drives those same vectors
#       through a real ForwarderEngine (EngineBuilder + in-process faces).
#   (c) RUST-UNIT  — both the sans-IO pin (ndn-fwd-core) and the native pin
#       (ndn-engine forwarding_conformance) pass: the lock-free async engine and
#       the sans-IO core agree on forward/drop for every vector.
#
# Architectures differ (multi-stage async + Arc tables vs single-threaded &mut
# sans-IO), so they share decision *semantics* by conformance, not by the
# storage-trait orchestration.
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
NATIVE_TEST=crates/ndn-engine/tests/forwarding_conformance.rs

# (a) shared vectors + sans-IO pin.
grep -rqE 'INTEREST_DECISION_CASES' "$CRATE_DIR/src" 2>/dev/null \
    || { echo "FAIL: ndn-fwd-core lacks INTEREST_DECISION_CASES" >&2; fail=1; }
grep -rqE 'decide_interest_matches_conformance_vectors' "$CRATE_DIR/src" 2>/dev/null \
    || { echo "FAIL: ndn-fwd-core lacks the sans-IO conformance pin" >&2; fail=1; }

# (b) native pin drives the shared vectors through a real engine.
[ -f "$NATIVE_TEST" ] || { echo "FAIL: missing $NATIVE_TEST" >&2; fail=1; }
if [ -f "$NATIVE_TEST" ]; then
    grep -qE 'INTEREST_DECISION_CASES' "$NATIVE_TEST" || { echo "FAIL: native test ignores shared vectors" >&2; fail=1; }
    grep -qE 'EngineBuilder' "$NATIVE_TEST" || { echo "FAIL: native test does not build a real engine" >&2; fail=1; }
    # Data-path pin: satisfy → consumer, unsolicited → drop.
    grep -qE 'native_data_satisfies_pit_to_consumer' "$NATIVE_TEST" || { echo "FAIL: native test lacks Data satisfy pin" >&2; fail=1; }
    grep -qE 'native_unsolicited_data_dropped' "$NATIVE_TEST" || { echo "FAIL: native test lacks unsolicited-Data pin" >&2; fail=1; }
fi

# (c) both pins pass.
if [ "$fail" -eq 0 ]; then
    echo "→ cargo test -p ndn-fwd-core decide_interest_matches_conformance_vectors"
    echo "→ cargo test -p ndn-engine --test forwarding_conformance"
    if ! cargo test --quiet -p ndn-fwd-core decide_interest_matches_conformance_vectors >/dev/null 2>&1 \
        || ! cargo test --quiet -p ndn-engine --test forwarding_conformance >/dev/null 2>&1; then
        echo "FAIL: a conformance pin did not pass" >&2
        fail=1
    fi
fi

[ "$fail" -eq 0 ] && echo "PASS: EMB-12 — native engine forward/drop matches sans-IO decide_interest on all vectors."
exit "$fail"
