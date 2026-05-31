#!/usr/bin/env bash
# Witness — Phase 4 §4.4 wiki page cap.
#
# Finding:   The wiki is capped to keep it scannable. The original
#            phase-4 cap was 30 (27 + 3 slack). The 2026-05-30 learning-
#            architecture restructure added the "Start here" (3) and
#            "Your path" (4) sections on top of the spec/feature/ops
#            content; the dashboard-next migration docs were moved out to
#            .claude/notes/. The "Choosing" decision layer then added 6
#            pages (intro + 5 decision guides). Deliberate cap: 46
#            (44 current + 2 slack).
# Witness:   GREP-PROOF — count *.md files under docs/wiki/src/. Pass
#            iff count <= 46.
#
# Exit codes:
#   0 — PASS (count <= 46)
#   1 — FAIL (count > 46)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

count=$(find docs/wiki/src -type f -name '*.md' | wc -l | tr -d ' ')
echo "wiki page count: $count"
if [ "$count" -gt 46 ]; then
    echo "FAIL: $count markdown files in docs/wiki/src/ exceeds cap of 46" >&2
    exit 1
fi
echo "PASS"
exit 0
