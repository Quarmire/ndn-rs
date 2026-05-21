#!/usr/bin/env bash
# Witness — Phase 4 §4.5 diagram doctrine: at most one Mermaid
# diagram per page, with the documented exception for the
# Interest/Data lifecycle page (≤ 2).
#
# Witness:   GREP-PROOF — count ```mermaid fences per file. Fail if
#            any page exceeds its cap.
#
# Exit codes:
#   0 — PASS
#   1 — FAIL
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

EXCEPTION="docs/wiki/src/concepts/interest-data-lifecycle.md"
fail=0

while IFS= read -r f; do
    n=$(grep -c '^```mermaid' "$f" || true)
    cap=1
    if [ "$f" = "$EXCEPTION" ]; then
        cap=2
    fi
    if [ "$n" -gt "$cap" ]; then
        echo "FAIL: $f has $n mermaid diagrams (cap $cap)" >&2
        fail=1
    fi
done < <(find docs/wiki/src -type f -name '*.md' | sort)

if [ "$fail" -eq 0 ]; then
    echo "PASS"
fi
exit "$fail"
