#!/usr/bin/env bash
# Witness — Phase 4 §4.4 wiki page cap.
#
# Finding:   Phase 4 docs rewrite caps docs/wiki/src/ at 30 markdown
#            pages (27 planned + 3 slack).
# Witness:   GREP-PROOF — count *.md files under docs/wiki/src/. Pass
#            iff count <= 30.
#
# Exit codes:
#   0 — PASS (count <= 30)
#   1 — FAIL (count > 30)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

count=$(find docs/wiki/src -type f -name '*.md' | wc -l | tr -d ' ')
echo "wiki page count: $count"
if [ "$count" -gt 30 ]; then
    echo "FAIL: $count markdown files in docs/wiki/src/ exceeds cap of 30" >&2
    exit 1
fi
echo "PASS"
exit 0
