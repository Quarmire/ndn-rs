#!/usr/bin/env bash
# Witness scaffold for Face-system Tier 4 §9.9 — TraceContextFeature
# OTel-overhead bench.  Phase-3 OTel (separate prompt) wires the
# sampler that flips the "feature ON" datapoint; until then this
# script lands the harness and exits 2 (SKIP) so the witness shape
# is locked in and Phase-3 cannot skip it.
#
# Finding:     docs/notes/face-system-design-2026-05-20.md §9.9
# Severity:    Phase-2b architectural cleanup (pre-v0.1.0)
# Decision:    p99 delta with TraceContextFeature ON must be within
#              5% of OFF at sample rate 0.01.  The "OFF baseline" can
#              be measured today via `cargo bench --bench face_otel`
#              (the Criterion harness this scaffold expects); the
#              "ON delta" stays blank until Phase-3 wires the
#              sampler.
#
# Reverify recipe:
#   PHASE-3-PENDING: today the script reports SKIP and exits 2.
#   Phase-3 OTel will flip the body to a real assertion.
#
# Exit codes:
#   0 — PASS (ON delta within 5% of OFF — Phase-3)
#   1 — FAIL (ON delta > 5% — Phase-3)
#   2 — SKIP (Phase-3 sampler not wired yet — today's state)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

# Verify the Criterion harness Phase-3 will populate exists in tree
# so this scaffold cannot be deleted in a "tidy unused files" pass.
HARNESS=crates/spec/ndn-transport/benches/face_otel_overhead.rs
if [ ! -f "$HARNESS" ]; then
    echo "FAIL: Criterion harness $HARNESS missing" >&2
    exit 1
fi

echo "SKIP: face_otel_overhead — Phase-3 sampler not wired yet"
echo "  Run \`cargo bench -p ndn-transport --bench face_otel_overhead\` to see the OFF baseline."
echo "  Phase-3 OTel populates the ON-sample-0.01 datapoint and flips this script to a real assertion."
exit 2
